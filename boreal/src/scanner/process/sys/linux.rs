use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::memory::{FragmentedMemory, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    let proc_pid_path = Path::new("/proc").join(pid.to_string());

    // TODO: improve errors by at least detecting ENOTFOUND for unknown pid
    let mem_file = File::open(proc_pid_path.join("mem")).map_err(open_error_to_scan_error)?;

    // Use /proc/pid/maps to list the memory regions to scan.
    let file = File::open(proc_pid_path.join("maps")).map_err(open_error_to_scan_error)?;

    let reader = BufReader::new(file);
    let mut regions = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(ScanError::CannotListProcessRegions)?;

        if let Some(region) = parse_map_line(&line) {
            regions.push(region);
        }
    }
    Ok(Box::new(LinuxProcessMemory {
        regions,
        mem_file,
        buffer: Vec::new(),
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
    // List of regions parsed from the /proc/pid/maps file
    regions: Vec<RegionDescription>,

    // Opened handle on /proc/pid/mem.
    mem_file: File,

    // Buffer used to hold the duplicated process memory when fetched.
    buffer: Vec<u8>,
}

impl FragmentedMemory for LinuxProcessMemory {
    fn list_regions(&self) -> Vec<RegionDescription> {
        self.regions.clone()
    }

    fn fetch_region(&mut self, desc: RegionDescription) -> Option<Region> {
        let _ = self
            .mem_file
            .seek(SeekFrom::Start(desc.start as u64))
            .ok()?;

        self.buffer.resize(desc.length, 0);
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
