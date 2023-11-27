use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    let proc_pid_path = Path::new("/proc").join(pid.to_string());

    // TODO: improve errors by at least detecting ENOTFOUND for unknown pid
    let mem_file = File::open(proc_pid_path.join("mem")).map_err(open_error_to_scan_error)?;

    // Use /proc/pid/maps to list the memory regions to scan.
    let maps_file = File::open(proc_pid_path.join("maps")).map_err(open_error_to_scan_error)?;

    Ok(Box::new(LinuxProcessMemory {
        maps_file: BufReader::new(maps_file),
        mem_file,
        buffer: Vec::new(),
        region: None,
    }))
}

// Parse a line from the /proc/pid/maps file.
fn parse_map_line(line: &str) -> Option<RegionDescription> {
    // See man proc(5). Each line is:
    //
    // <start addr>-<end addr> <perms> <offset> <dev-major>:<dev-minor> <inode> <pathname>
    let mut splits = line.split_whitespace();

    let mut addrs = splits.next()?.split('-');
    let start_addr = addrs.next()?;
    let start_addr = usize::from_str_radix(start_addr, 16).ok()?;
    let end_addr = addrs.next()?;
    let end_addr = usize::from_str_radix(end_addr, 16).ok()?;

    let perms = splits.next()?;
    if !perms.starts_with('r') {
        // Region is not readable, so ignore.
        return None;
    }

    Some(RegionDescription {
        start: start_addr,
        length: end_addr.checked_sub(start_addr)?,
    })
}

fn open_error_to_scan_error(open_error: std::io::Error) -> ScanError {
    match open_error.kind() {
        std::io::ErrorKind::NotFound => ScanError::UnknownProcess,
        _ => ScanError::CannotListProcessRegions(open_error),
    }
}

#[derive(Debug)]
struct LinuxProcessMemory {
    // Opened handle on /proc/pid/maps
    maps_file: BufReader<File>,

    // Opened handle on /proc/pid/mem.
    mem_file: File,

    // Buffer used to hold the duplicated process memory when fetched.
    buffer: Vec<u8>,

    // Current region.
    region: Option<RegionDescription>,
}

impl FragmentedMemory for LinuxProcessMemory {
    fn reset(&mut self) {
        let _ = self.maps_file.rewind();
    }

    fn next(&mut self, _params: &MemoryParams) -> Option<RegionDescription> {
        let mut line = String::new();
        self.region = loop {
            line.clear();
            if self.maps_file.read_line(&mut line).is_err() {
                break None;
            }
            if line.is_empty() {
                break None;
            }
            if let Some(desc) = parse_map_line(&line) {
                break Some(desc);
            }
        };
        self.region
    }

    fn fetch(&mut self, params: &MemoryParams) -> Option<Region> {
        let desc = self.region?;
        let _ = self
            .mem_file
            .seek(SeekFrom::Start(desc.start as u64))
            .ok()?;

        let length = std::cmp::min(desc.length, params.max_fetched_region_size);
        self.buffer.resize(length, 0);
        self.mem_file.read_exact(&mut self.buffer).ok()?;

        Some(Region {
            start: desc.start,
            mem: &self.buffer,
        })
    }
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
