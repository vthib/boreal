use crate::memory::FragmentedMemory;
use crate::scanner::ScanError;

mod sys;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    sys::process_memory(pid)
}
