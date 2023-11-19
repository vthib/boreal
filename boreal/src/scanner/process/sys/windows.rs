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
        region: None,
    }))
}

#[derive(Debug)]
struct WindowsProcessMemory {
    // Handle to the process being scanned.
    handle: OwnedHandle,

    // Buffer used to hold the duplicated process memory when fetched.
    buffer: Vec<u8>,

    // Description of the current region.
    region: Option<RegionDescription>,
}

impl FragmentedMemory for WindowsProcessMemory {
    fn reset(&mut self) {
        self.region = None;
    }

    fn next(&mut self, _params: &MemoryParams) -> Option<RegionDescription> {
        let mut next_addr = match self.region {
            Some(region) => Some(region.start.checked_add(region.length)?),
            None => None,
        };
        self.region = loop {
            let mut info = MaybeUninit::uninit();
            // Safety:
            // - the handle is a valid process handle and has the PROCESS_QUERY_INFORMATION
            //   permission.
            let res = unsafe {
                VirtualQueryEx(
                    handle_to_windows_handle(self.handle.as_handle()),
                    next_addr.map(|v| v as *const c_void),
                    info.as_mut_ptr(),
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if res == 0 {
                break None;
            }

            // Safety: returned value is not zero, so the function succeeded, and has filled
            // the info object.
            let info = unsafe { info.assume_init() };

            next_addr = match (info.BaseAddress as usize).checked_add(info.RegionSize) {
                Some(v) => Some(v),
                None => {
                    // If this happens, a region actually covers up to u64::MAX, so there cannot
                    // be any region past it. That's unlikely, but lets just be safe about it.
                    break None;
                }
            };
            if info.State == MEM_COMMIT && info.Protect != PAGE_NOACCESS {
                break Some(RegionDescription {
                    start: info.BaseAddress as usize,
                    length: info.RegionSize,
                });
            }
        };
        self.region
    }

    fn fetch(&mut self, _params: &MemoryParams) -> Option<Region> {
        let desc = self.region?;

        // FIXME: make configurable
        self.buffer
            .resize(std::cmp::min(desc.length, 100 * 1024 * 1024), 0);

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
