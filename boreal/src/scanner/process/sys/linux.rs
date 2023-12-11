use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    let proc_pid_path = Path::new("/proc").join(pid.to_string());

    let mem_file = File::open(proc_pid_path.join("mem")).map_err(open_error_to_scan_error)?;

    // Use /proc/pid/maps to list the memory regions to scan.
    let maps_file = File::open(proc_pid_path.join("maps")).map_err(open_error_to_scan_error)?;

    Ok(Box::new(LinuxProcessMemory {
        maps_file: BufReader::new(maps_file),
        mem_file,
        buffer: Vec::new(),
        current_position: None,
        region: None,
    }))
}

#[derive(Debug, PartialEq, Eq)]
struct MapLine {
    start: usize,
    length: usize,
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
    offset: u64,
    path: Option<PathBuf>,
}

// Parse a line from the /proc/pid/maps file.
fn parse_map_line(line: &str) -> Option<MapLine> {
    // See man proc(5). Each line is:
    //
    // <start addr>-<end addr> <perms> <offset> <dev-major>:<dev-minor> <inode> <pathname>
    //
    // We cannot use split_whitespace here, since the path can contain spaces and
    // this method do not allow taking the rest of the string.
    // Once https://doc.rust-lang.org/std/str/struct.SplitWhitespace.html#method.remainder is
    // stable, it could be used.
    // Instead, we used "split_once" as many times as possible, trimming the rest to remove extra
    // whitespaces. It is a bit ugly but it works fine.
    let mut rest = line;
    let mut next_elem = || {
        let (elem, next) = rest.split_once(' ')?;
        rest = next.trim_start();
        Some(elem)
    };

    let mut addrs = next_elem()?.split('-');
    let start_addr = addrs.next()?;
    let start_addr = usize::from_str_radix(start_addr, 16).ok()?;
    let end_addr = addrs.next()?;
    let end_addr = usize::from_str_radix(end_addr, 16).ok()?;

    let perms = next_elem()?;
    if !perms.starts_with('r') {
        // Region is not readable, so ignore.
        return None;
    }

    let offset = next_elem()?;
    let offset = u64::from_str_radix(offset, 16).ok()?;

    let mut device = next_elem()?.split(':');
    let dev_major: u32 = device.next()?.parse().ok()?;
    let dev_minor: u32 = device.next()?.parse().ok()?;

    let (inode, path) = match next_elem() {
        Some(inode) => {
            let inode: u64 = inode.parse().ok()?;
            // Rest of the string may be empty, a special name that looks like `[...]`, or a path.
            let path = rest.starts_with('/').then(|| PathBuf::from(rest.trim()));
            (inode, path)
        }
        // Not space left in the string, so the rest is only the inode
        None => {
            let inode: u64 = rest.parse().ok()?;
            (inode, None)
        }
    };

    Some(MapLine {
        start: start_addr,
        length: end_addr.checked_sub(start_addr)?,
        dev_major,
        dev_minor,
        inode,
        offset,
        path,
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

    // Current position: current region and offset in the region of the current chunk.
    current_position: Option<(MapLine, usize)>,

    // Current region returned by the next call, which needs to be fetched.
    region: Option<RegionDescription>,
}

impl LinuxProcessMemory {
    fn next_position(&mut self, params: &MemoryParams) {
        if let Some(chunk_size) = params.memory_chunk_size {
            if let Some((desc, offset)) = &mut self.current_position {
                let new_offset = offset.saturating_add(chunk_size);
                if new_offset < desc.length {
                    // Region has a next chunk, so simply select it.
                    *offset = new_offset;
                    return;
                }
            }
        }

        // Otherwise, read the next line from the maps file
        let mut line = String::new();
        self.current_position = loop {
            line.clear();
            if self.maps_file.read_line(&mut line).is_err() {
                break None;
            }
            if line.is_empty() {
                break None;
            }
            if let Some(desc) = parse_map_line(&line) {
                break Some((desc, 0));
            }
        };
    }
}

impl FragmentedMemory for LinuxProcessMemory {
    fn reset(&mut self) {
        let _ = self.maps_file.rewind();
    }

    fn next(&mut self, params: &MemoryParams) -> Option<RegionDescription> {
        self.next_position(params);

        self.region =
            self.current_position
                .as_ref()
                .map(|(desc, offset)| match params.memory_chunk_size {
                    Some(chunk_size) => RegionDescription {
                        start: desc.start.saturating_add(*offset),
                        length: std::cmp::min(chunk_size, desc.length),
                    },
                    None => RegionDescription {
                        start: desc.start,
                        length: desc.length,
                    },
                });
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
        test_type_traits_non_clonable(MapLine {
            start: 0,
            length: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            offset: 0,
            path: None,
        });
    }

    #[test]
    fn test_parse_maps() {
        assert_eq!(
            parse_map_line(
                "00400000-00452000 r-xp 00051000 08:02 173521      /usr/bin/dbus-daemon"
            ),
            Some(MapLine {
                start: 0x40_00_00,
                length: 0x05_20_00,
                dev_major: 8,
                dev_minor: 2,
                inode: 173_521,
                offset: 0x05_10_00,
                path: Some(PathBuf::from("/usr/bin/dbus-daemon")),
            })
        );
        // Test with a special name that isn't a path
        assert_eq!(
            parse_map_line("00e03000-00e24000 rw-p 00000000 00:00 0           [heap]",),
            Some(MapLine {
                start: 0xe0_30_00,
                length: 0x02_10_00,
                dev_major: 0,
                dev_minor: 0,
                inode: 0,
                offset: 0,
                path: None,
            })
        );
        // Test with a path containing spaces
        assert_eq!(
            parse_map_line(
                "7f122cd4-7f123cd4  r--p  0002c000   08:10    \
                 37209  /usr/lib/x86_64 linux gnu/ld-2.31.so\n"
            ),
            Some(MapLine {
                start: 0x7f_12_2c_d4,
                length: 0x10_00,
                dev_major: 8,
                dev_minor: 10,
                inode: 37_209,
                offset: 0x2c000,
                path: Some(PathBuf::from("/usr/lib/x86_64 linux gnu/ld-2.31.so")),
            })
        );
        // Test with no special name or path
        assert_eq!(
            parse_map_line("7f122cd4-7f123cd4 r--p 0002c000 08:10 37209"),
            Some(MapLine {
                start: 0x7f_12_2c_d4,
                length: 0x10_00,
                dev_major: 8,
                dev_minor: 10,
                inode: 37_209,
                offset: 0x2c000,
                path: None,
            })
        );

        // If the region is not readable, it's not returned.
        assert_eq!(
            parse_map_line("7f122cd4-7f123cd4 ---p 0002c000 08:10 37209"),
            None
        );

        // Error cases
        assert_eq!(parse_map_line(""), None);
        assert_eq!(parse_map_line(" "), None);
        assert_eq!(parse_map_line("00400000 00452000"), None);
        assert_eq!(parse_map_line("0040000g-00452000 r-xp"), None);
        assert_eq!(parse_map_line("00400000-0045200g r-xp"), None);
        assert_eq!(parse_map_line("00400000-00452000 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp g "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 12 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 a:2 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 1:a "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 1:2 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 1:2 g "), None);
        assert_eq!(parse_map_line("2-1 r--p 0002c000 08:10 37209"), None);
    }
}
