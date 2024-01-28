use std::mem::size_of;

use mach2::kern_return::{KERN_NO_SPACE, KERN_SUCCESS};
use mach2::mach_port::mach_port_deallocate;
use mach2::port::{mach_port_name_t, MACH_PORT_NULL};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region_recurse};
use mach2::vm_prot::VM_PROT_READ;
use mach2::vm_region::vm_region_submap_info_64;

use crate::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    #[allow(clippy::cast_possible_wrap)]
    let pid = pid as i32;

    let mut task_port_name = MACH_PORT_NULL;
    // Safety:
    // - mach_task_self is always safe to call
    // - task_for_pid is provided a valid port name
    let ret = unsafe { task_for_pid(mach_task_self(), pid, &mut task_port_name) };
    if ret != KERN_SUCCESS {
        // There is no errno or detailed error, simply KERN_FAILURE.
        // Try to find out if the pid does not exist, so that the error type can be improved.
        // Safety: always safe to call.
        let kill_res = unsafe { libc::kill(pid, 0) };
        if kill_res == -1 {
            let kill_error = std::io::Error::last_os_error();
            if kill_error.raw_os_error() == Some(libc::ESRCH) {
                return Err(ScanError::UnknownProcess);
            }
        }

        // Otherwise, just return a generic error
        return Err(ScanError::CannotListProcessRegions(std::io::Error::new(
            std::io::ErrorKind::Other,
            "cannot open process",
        )));
    }

    Ok(Box::new(MacosProcessMemory {
        task_port: MachPort {
            name: task_port_name,
        },
        buffer: Vec::new(),
        current_region: None,
    }))
}

#[derive(Debug)]
struct MachPort {
    name: mach_port_name_t,
}

impl Drop for MachPort {
    fn drop(&mut self) {
        // Safety:
        // - mach_task_self is always safe to call
        // - self.name is a valid port name (returned by task_for_pid).
        let _ = unsafe { mach_port_deallocate(mach_task_self(), self.name) };
    }
}

#[derive(Debug)]
struct MacosProcessMemory {
    // Task port on the process
    task_port: MachPort,

    // Buffer used to hold the duplicated process memory when fetched.
    buffer: Vec<u8>,

    // Current region.
    current_region: Option<RegionDescription>,
}

impl MacosProcessMemory {
    fn next_region(&mut self, params: &MemoryParams) -> Option<RegionDescription> {
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

        query_next_region(self.task_port.name, next_addr)
    }
}

// See https://github.com/apple/darwin-xnu/blob/2ff845c2e03/osfmk/mach/vm_region.h#L320
const VM_REGION_SUBMAP_INFO_COUNT_64: usize =
    size_of::<vm_region_submap_info_64>() / size_of::<i32>();

#[allow(clippy::cast_possible_truncation)]
fn query_next_region(
    task_port: mach_port_name_t,
    mut next_addr: usize,
) -> Option<RegionDescription> {
    loop {
        let mut info = vm_region_submap_info_64::default();
        let mut size = 0;
        let mut count = VM_REGION_SUBMAP_INFO_COUNT_64 as u32;
        let mut addr = next_addr as u64;

        // Safety:
        // - the handle is a valid process handle and has the PROCESS_QUERY_INFORMATION
        //   permission.
        let res = unsafe {
            mach_vm_region_recurse(
                task_port,
                &mut addr,
                &mut size,
                &mut 0,
                std::ptr::addr_of_mut!(info).cast(),
                &mut count,
            )
        };

        if res == KERN_NO_SPACE {
            // No more regions
            return None;
        }

        if res != KERN_SUCCESS {
            return None;
        }

        if info.is_submap == 0 && info.protection & VM_PROT_READ != 0 {
            return Some(RegionDescription {
                start: addr as usize,
                length: size as usize,
            });
        }
        next_addr = (addr + size) as usize;
    }
}

impl FragmentedMemory for MacosProcessMemory {
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

        let mut out_size = self.buffer.len() as _;

        // Safety:
        // - the handle is a valid process handle and has the PROCESS_VM_READ permissions.
        // - The provided buffer pointer is allocated and has at least `nsize` bytes available.
        let res = unsafe {
            mach_vm_read_overwrite(
                self.task_port.name,
                desc.start as _,
                self.buffer.len() as u64,
                self.buffer.as_mut_ptr() as usize as u64,
                &mut out_size,
            )
        };

        if res != KERN_SUCCESS {
            return None;
        }

        #[allow(clippy::cast_possible_truncation)]
        self.buffer.truncate(out_size as usize);
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
