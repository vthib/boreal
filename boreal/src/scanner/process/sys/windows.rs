use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    // Safety: this is always safe to call.
    let res = unsafe {
        OpenProcess(
            // PROCESS_QUERY_INFORMATION for VirtualQueryEx
            // PROCESS_VM_READ for ReadProcessMemory
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    };
    let handle = match res {
        Ok(handle) => {
            // Safety:
            // - The handle is valid since the call to OpenProcess succeeded
            // - The handle must be closed with `CloseHandle`.
            unsafe { OwnedHandle::from_raw_handle(handle.0 as _) }
        }
        Err(err) if err.code() == ERROR_INVALID_PARAMETER.into() => {
            return Err(ScanError::UnknownProcess);
        }
        Err(err) => {
            return Err(ScanError::CannotListProcessRegions(err.into()));
        }
    };

    Ok(Box::new(WindowsProcessMemory {
        handle,
        buffer: Vec::new(),
        current_region: None,
    }))
}

#[derive(Debug)]
struct WindowsProcessMemory {
    // Handle to the process being scanned.
    handle: OwnedHandle,

    // Buffer used to hold the duplicated process memory when fetched.
    buffer: Vec<u8>,

    // Current region being listed.
    current_region: Option<RegionDescription>,
}

impl WindowsProcessMemory {
    fn next_region(&self, params: &MemoryParams) -> Option<RegionDescription> {
        let next_addr = match self.current_region {
            Some(desc) => {
                if let Some(chunk_size) = params.memory_chunk_size {
                    if chunk_size < desc.length {
                        // Region has a next chunk, so simply select it.
                        return Some(RegionDescription {
                            start: desc.start.saturating_add(chunk_size),
                            length: desc.length.saturating_sub(chunk_size),
                        });
                    }
                }

                desc.start.checked_add(desc.length)?
            }
            None => 0,
        };

        query_next_region(self.handle.as_handle(), next_addr)
    }
}

fn query_next_region(handle: BorrowedHandle, mut next_addr: usize) -> Option<RegionDescription> {
    loop {
        let mut info = MaybeUninit::uninit();
        // Safety:
        // - the handle is a valid process handle and has the PROCESS_QUERY_INFORMATION
        //   permission.
        let res = unsafe {
            VirtualQueryEx(
                handle_to_windows_handle(handle.as_handle()),
                Some(next_addr as *const c_void),
                info.as_mut_ptr(),
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if res == 0 {
            return None;
        }

        // Safety: returned value is not zero, so the function succeeded, and has filled
        // the info object.
        let info = unsafe { info.assume_init() };

        // If this checked_add fails, a region actually covers up to u64::MAX, so there cannot
        // be any region past it. That's unlikely, but lets just be safe about it.
        next_addr = (info.BaseAddress as usize).checked_add(info.RegionSize)?;
        if info.State == MEM_COMMIT && info.Protect != PAGE_NOACCESS {
            return Some(RegionDescription {
                start: info.BaseAddress as usize,
                length: info.RegionSize,
            });
        }
    }
}

impl FragmentedMemory for WindowsProcessMemory {
    fn reset(&mut self) {
        self.current_region = None;
    }

    fn next(&mut self, params: &MemoryParams) -> Option<RegionDescription> {
        self.current_region = self.next_region(params);
        self.current_region
            .map(|region| get_chunked_region(region, params))
    }

    fn fetch(&mut self, params: &MemoryParams) -> Option<Region> {
        let desc = get_chunked_region(self.current_region?, params);

        self.buffer.resize(
            std::cmp::min(desc.length, params.max_fetched_region_size),
            0,
        );

        let mut nb_bytes_read = 0;
        // Safety:
        // - the handle is a valid process handle and has the PROCESS_VM_READ permissions.
        // - The provided buffer pointer is allocated and has at least `nsize` bytes available.
        let res = unsafe {
            ReadProcessMemory(
                handle_to_windows_handle(self.handle.as_handle()),
                desc.start as _,
                self.buffer.as_mut_ptr().cast(),
                self.buffer.len(),
                Some(&mut nb_bytes_read),
            )
            .ok()
        };

        if res.is_err() {
            return None;
        }

        self.buffer.truncate(nb_bytes_read);
        Some(Region {
            start: desc.start,
            mem: &self.buffer,
        })
    }
}

fn get_chunked_region(desc: RegionDescription, params: &MemoryParams) -> RegionDescription {
    match params.memory_chunk_size {
        Some(chunk_size) => RegionDescription {
            start: desc.start,
            length: std::cmp::min(chunk_size, desc.length),
        },
        None => desc,
    }
}

fn handle_to_windows_handle(handle: BorrowedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle() as _)
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        let memory = process_memory(std::process::id()).unwrap();
        test_type_traits_non_clonable(memory);
    }
}
