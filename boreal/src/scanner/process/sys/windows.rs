use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    // Enable the SeDebug privilege on our process, so as to be able to
    // open any process.
    if enable_se_debug_privilege().is_err() {
        // Attempt to open the process regardless, we might not need
        // the SE_DEBUG privilege for this one.
        // TODO: log this once logging is added.
    }

    // Safety: this is always safe to call.
    let res = unsafe {
        OpenProcess(
            // PROCESS_QUERY_INFORMATION for VirtualQueryEx
            // PROCESS_VM_READ for ReadProcessMemory
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            pid,
        )
    };

    if res.is_null() {
        let err = std::io::Error::last_os_error();
        return Err(
            #[allow(clippy::cast_possible_wrap)]
            if err.raw_os_error() == Some(ERROR_INVALID_PARAMETER as _) {
                ScanError::UnknownProcess
            } else {
                ScanError::CannotListProcessRegions(err)
            },
        );
    }

    // Safety:
    // - The handle is valid since the call to OpenProcess succeeded
    // - The handle must be closed with `CloseHandle`.
    let handle = unsafe { OwnedHandle::from_raw_handle(res.cast()) };

    Ok(Box::new(WindowsProcessMemory {
        handle,
        buffer: Vec::new(),
        current_region: None,
    }))
}

fn enable_se_debug_privilege() -> Result<(), std::io::Error> {
    let mut self_token = std::ptr::null_mut();

    // Safety: this is always safe to call.
    let self_handle = unsafe { GetCurrentProcess() };
    // Safety:
    // - handle is valid and has PROCESS_QUERY_LIMITED_INFORMATION
    //   permission since it was retrieve with GetCurrentProcess.
    // - TOKEN_ADJUST_PRIVILEGES is a valid access to ask for.
    let res = unsafe { OpenProcessToken(self_handle, TOKEN_ADJUST_PRIVILEGES, &mut self_token) };
    if res == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut debug_privilege_luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };

    // Safety:
    // - SE_DEBUG_NAME is a wide string ending with a null byte.
    let res = unsafe {
        LookupPrivilegeValueW(
            std::ptr::null_mut(),
            SE_DEBUG_NAME,
            &mut debug_privilege_luid,
        )
    };
    if res == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let cfg = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: debug_privilege_luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // Safety:
    // - token is valid and opened with TOKEN_ADJUST_PRIVILEGES
    // - NewState is well-formed, count is 1 and the Privileges array has one element
    // - Rest of arguments are optional
    let res = unsafe {
        AdjustTokenPrivileges(
            self_token,
            0,
            &cfg,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if res == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
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
                next_addr as *const c_void,
                info.as_mut_ptr(),
                size_of::<MEMORY_BASIC_INFORMATION>(),
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
                &mut nb_bytes_read,
            )
        };

        if res == 0 {
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
    handle.as_raw_handle() as HANDLE
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
