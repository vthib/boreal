use crate::memory::FragmentedMemory;
use crate::scanner::ScanError;

/// Initial capacity for the buffer used when retrieving process memory regions.
///
/// This is useful to avoid reallocating this buffer many times when scanning
/// small regions.
const INITIAL_BUFFER_CAPACITY: usize = 1024 * 1024;

mod sys;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    sys::process_memory(pid)
}
