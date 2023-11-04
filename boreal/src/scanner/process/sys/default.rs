use crate::memory;
use crate::scanner::ScanError;

pub fn process_memory(_pid: u32) -> Result<Box<dyn memory::FragmentedMemory>, ScanError> {
    Err(ScanError::UnsupportedProcessScan)
}
