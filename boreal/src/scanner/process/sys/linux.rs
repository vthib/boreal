use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use crate::scanner::ScanError;

pub fn process_memory(pid: u32) -> Result<Box<dyn FragmentedMemory>, ScanError> {
    let proc_pid_path = Path::new("/proc").join(pid.to_string());

    let mem_file = File::open(proc_pid_path.join("mem")).map_err(open_error_to_scan_error)?;

    // Use /proc/pid/maps to list the memory regions to scan.
    let maps_file = File::open(proc_pid_path.join("maps")).map_err(open_error_to_scan_error)?;

    // Used to find dirty pages when reading from file-based memory regions.
    let pagemap_file =
        File::open(proc_pid_path.join("pagemap")).map_err(open_error_to_scan_error)?;

    // Safety: We are on Linux, sysconf is always safe to call
    let res = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = match res.try_into() {
        // Default to 4096, which tends to always be the default on linux
        Err(_) | Ok(0) => 4096,
        Ok(v) => v,
    };

    Ok(Box::new(LinuxProcessMemory {
        maps_file: BufReader::new(maps_file),
        mem_file,
        pagemap_file,
        page_size,
        buffer: Vec::new(),
        current_region: None,
    }))
}

// Parse a line from the /proc/pid/maps file.
fn parse_map_line(line: &str) -> Option<MapRegion> {
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
    let dev_major = device.next()?;
    let dev_major = u32::from_str_radix(dev_major, 16).ok()?;
    let dev_minor = device.next()?;
    let dev_minor = u32::from_str_radix(dev_minor, 16).ok()?;

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

    Some(MapRegion {
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

    // Opened handle on /proc/pid/pagemap
    pagemap_file: File,

    // Size of a page on this system.
    page_size: usize,

    // Buffer used to hold the duplicated process memory when fetched.
    buffer: Vec<u8>,

    // Current region.
    current_region: Option<CurrentRegion>,
}

impl LinuxProcessMemory {
    fn next_position(&mut self, params: &MemoryParams) {
        // Update current line to point to next chunk if possible.
        if self
            .current_region
            .as_mut()
            .is_some_and(|line| line.update_to_next_chunk(params))
        {
            return;
        }

        // Otherwise, read the next line from the maps file
        let mut line = String::new();
        self.current_region = loop {
            line.clear();
            if self.maps_file.read_line(&mut line).is_err() {
                break None;
            }
            if line.is_empty() {
                break None;
            }
            if let Some(desc) = parse_map_line(&line) {
                break Some(CurrentRegion::new(desc));
            }
        };
    }
}

impl FragmentedMemory for LinuxProcessMemory {
    fn reset(&mut self) {
        let _r = self.maps_file.rewind();
    }

    fn next(&mut self, params: &MemoryParams) -> Option<RegionDescription> {
        self.next_position(params);

        self.current_region
            .as_ref()
            .map(|line| line.region_description(params, self.page_size))
    }

    fn fetch(&mut self, params: &MemoryParams) -> Option<Region> {
        let current_region = self.current_region.as_mut()?;
        current_region.fetch(
            params,
            self.page_size,
            &mut self.mem_file,
            &mut self.pagemap_file,
            &mut self.buffer,
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
struct MapRegion {
    start: usize,
    length: usize,
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
    offset: u64,
    path: Option<PathBuf>,
}

impl MapRegion {
    fn open_file(&self) -> Option<(File, usize)> {
        let check_metadata = |metadata: std::fs::Metadata| -> bool {
            let dev = metadata.dev();

            metadata.ino() == self.inode
                && libc::major(dev) == self.dev_major
                && libc::minor(dev) == self.dev_minor
                && metadata.mode() & libc::S_IFMT == libc::S_IFREG
                && metadata.len() > self.offset
        };

        // Do not try to map the file if it does not belong to any device
        if self.dev_major == 0 && self.dev_minor == 0 {
            return None;
        }

        let path = self.path.as_ref()?;
        // First, do a sanity check on the metadata of the path, this avoids opening
        // the file if it does not pass those checks.
        if !check_metadata(std::fs::metadata(path).ok()?) {
            return None;
        }

        let file = File::open(path).ok()?;

        // Then, redo the checks but on the metadata of the opened files, to prevent
        // any TOCTOU issues.
        if !check_metadata(file.metadata().ok()?) {
            return None;
        }

        let file_size = file.metadata().ok()?.len().try_into().ok()?;
        Some((file, file_size))
    }
}

/// Description of a region currently being listed or fetched
#[derive(Debug)]
struct CurrentRegion {
    /// Description of the region
    desc: MapRegion,

    /// Opened handle on the file backing the region.
    ///
    /// Only set if:
    /// - the region is file-backed
    /// - the region has been fetched once, and we managed to open the file
    ///
    file: Option<File>,

    /// Size of the file backing the region.
    file_size: usize,

    /// Current offset into the region.
    ///
    /// Used to handle chunking of the region.
    current_offset: usize,
}

impl CurrentRegion {
    fn new(desc: MapRegion) -> Self {
        Self {
            desc,
            file: None,
            file_size: 0,
            current_offset: 0,
        }
    }

    fn region_description(&self, params: &MemoryParams, page_size: usize) -> RegionDescription {
        let mut desc = RegionDescription {
            start: self.desc.start.saturating_add(self.current_offset),
            length: self.desc.length.saturating_sub(self.current_offset),
        };
        if let Some(chunk_size) = params.memory_chunk_size {
            // Ensure chunk_size is a multiple of the page_size, we need the
            // different chunks to be on different pages to properly handle
            // the pagemap optimization.
            let chunk_size = round_to_page_size(chunk_size, page_size);

            desc.length = std::cmp::min(chunk_size, desc.length);
        }
        desc
    }

    /// Open the file backing the region.
    ///
    /// This is not done when the object is created to avoid opening the file if the
    /// region is only listed and not fetched.
    fn open_backing_file(&mut self) {
        if self.file.is_some() {
            return;
        }
        if let Some((file, file_size)) = self.desc.open_file() {
            self.file = Some(file);
            self.file_size = file_size;
        }
    }

    fn fetch<'a>(
        &mut self,
        params: &MemoryParams,
        page_size: usize,
        mem_file: &mut File,
        pagemap_file: &mut File,
        buffer: &'a mut Vec<u8>,
    ) -> Option<Region<'a>> {
        // Ensure max_fetched_region_size is a multiple of the page_size.
        let max_fetched_region_size = round_to_page_size(params.max_fetched_region_size, page_size);

        let desc = self.region_description(params, page_size);
        let length = std::cmp::min(desc.length, max_fetched_region_size);

        buffer.resize(length, 0);

        // If the region is file-backed, prefer reading from the file rather than from
        // the process memory. This avoids making the OS bring those pages into RAM
        // and inflating the memory usage of the process.
        // However, since the process memory may have modified its copy of the region,
        // we use the pagemap file to find which pages still needs to be fetched from
        // the memory.
        self.open_backing_file();
        match self.file.as_mut() {
            Some(file) => {
                // We need to add the offset from the map line, which indicates at which
                // offset the file was mapped.
                let offset = (self.current_offset as u64).checked_add(self.desc.offset)?;
                let _ = file.seek(SeekFrom::Start(offset)).ok()?;

                let max_length: usize = self.file_size.checked_sub(offset.try_into().ok()?)?;
                if max_length < length {
                    // It is possible for the file to be smaller than the region, as the region
                    // should be multiples of the page size. In that case, the rest of the bytes
                    // are null.
                    // Since there might still be data left from a previous read past the
                    // max_file_length byte, it needs to be reset to 0.
                    // This is done by resizing back and forth.
                    buffer.resize(max_length, 0);
                    file.read_exact(buffer).ok()?;
                    buffer.resize(length, 0);
                } else {
                    file.read_exact(buffer).ok()?;
                }

                // Read the page details for this region, by fetching the u64 value for each
                // page.
                let mut page_details: Vec<u64> = vec![0; length / page_size];
                let _ = pagemap_file
                    .seek(SeekFrom::Start((desc.start / page_size * 8) as u64))
                    .ok()?;
                {
                    // According to man proc(5), pagemap contains details about pages
                    // as u64 values, but no indication of the byte ordering of those values
                    // is specified. We assume here that this means the byte ordering is
                    // native, so simply reading bytes and interpreting it as u64 values
                    // will work.
                    //
                    // Safety: it is safe to align a slice of u64 into a slice of u8, since
                    // there is no alignment constraint for the u8 type, and there is prefix or
                    // suffix.
                    let (_, bytes_vec, _) = unsafe { page_details.align_to_mut::<u8>() };
                    pagemap_file.read_exact(bytes_vec).ok()?;
                }

                for (page_index, page_bits) in page_details.into_iter().enumerate() {
                    // Keep only the last 4 bits
                    let page_bits = page_bits >> 60;
                    // If the two higher bits are 0, the page is not in RAM or swap, it has never
                    // been fetched by the process. Since it is file-backed, keeping the data from
                    // the page is fine.
                    if page_bits & 0xC == 0 {
                        continue;
                    }
                    // Otherwise, the page has been fetched, and the 62th bit is set to 1 only if
                    // the page is file-backed. If not, it has been modified, and we need to fetch
                    // it from the process memory.
                    if page_bits & 0x2 != 0 {
                        continue;
                    }

                    // Since the page may have been modified by the process, fetch it
                    // from the mem file directly.
                    let buf_offset = page_index * page_size;
                    let _ = mem_file
                        .seek(SeekFrom::Start(desc.start.checked_add(buf_offset)? as u64))
                        .ok()?;
                    mem_file
                        .read_exact(&mut buffer[buf_offset..(buf_offset + page_size)])
                        .ok()?;
                }
            }
            None => {
                // not file backed, simply read from the mem file
                let _ = mem_file.seek(SeekFrom::Start(desc.start as u64)).ok()?;
                mem_file.read_exact(buffer).ok()?;
            }
        }

        Some(Region {
            start: desc.start,
            mem: buffer,
        })
    }

    fn update_to_next_chunk(&mut self, params: &MemoryParams) -> bool {
        match params.memory_chunk_size {
            Some(chunk_size) => {
                let new_offset = self.current_offset.saturating_add(chunk_size);
                if new_offset < self.desc.length {
                    // Current line has a next chunk, so simply select it.
                    self.current_offset = new_offset;
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }
}

// Ensure value is a multiple of page_size by rounding it down.
//
// This rounds down as it makes it easier to avoid overflows.
// This function ensures the returned value is not 0. If value < page_size,
// page_size is returned.
fn round_to_page_size(value: usize, page_size: usize) -> usize {
    let res = value - (value % page_size);
    if res == 0 {
        page_size
    } else {
        res
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
        test_type_traits_non_clonable(MapRegion {
            start: 0,
            length: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            offset: 0,
            path: None,
        });
        test_type_traits_non_clonable(CurrentRegion {
            desc: MapRegion {
                start: 0,
                length: 0,
                dev_major: 0,
                dev_minor: 0,
                inode: 0,
                offset: 0,
                path: None,
            },
            file: None,
            file_size: 0,
            current_offset: 0,
        });
    }

    #[test]
    fn test_parse_maps() {
        assert_eq!(
            parse_map_line(
                "00400000-00452000 r-xp 00051000 08:02 173521      /usr/bin/dbus-daemon"
            ),
            Some(MapRegion {
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
            Some(MapRegion {
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
            Some(MapRegion {
                start: 0x7f_12_2c_d4,
                length: 0x10_00,
                dev_major: 8,
                dev_minor: 16,
                inode: 37_209,
                offset: 0x2c000,
                path: Some(PathBuf::from("/usr/lib/x86_64 linux gnu/ld-2.31.so")),
            })
        );
        // Test with no special name or path
        assert_eq!(
            parse_map_line("7f122cd4-7f123cd4 r--p 0002c000 08:10 37209"),
            Some(MapRegion {
                start: 0x7f_12_2c_d4,
                length: 0x10_00,
                dev_major: 8,
                dev_minor: 16,
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
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 g:2 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 1:g "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 1:2 "), None);
        assert_eq!(parse_map_line("00400000-00452000 r-xp 0 1:2 g "), None);
        assert_eq!(parse_map_line("2-1 r--p 0002c000 08:10 37209"), None);
    }

    #[test]
    fn test_round_to_page_size() {
        assert_eq!(round_to_page_size(0, 4096), 4096);
        assert_eq!(round_to_page_size(500, 4096), 4096);
        assert_eq!(round_to_page_size(4095, 4096), 4096);
        assert_eq!(round_to_page_size(4096, 4096), 4096);
        assert_eq!(round_to_page_size(4097, 4096), 4096);
        assert_eq!(round_to_page_size(8000, 4096), 4096);
        assert_eq!(round_to_page_size(9000, 4096), 8192);
        assert_eq!(round_to_page_size(usize::MAX, 4096), usize::MAX - 4095);
    }

    #[test]
    fn test_chunking() {
        let mut region = CurrentRegion::new(MapRegion {
            start: 0x5000,
            length: 0x1200,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            offset: 0,
            path: None,
        });

        let mut params = MemoryParams {
            max_fetched_region_size: 500,
            memory_chunk_size: None,
            can_refetch_regions: false,
        };
        assert_eq!(
            region.region_description(&params, 0x1000),
            RegionDescription {
                start: 0x5000,
                length: 0x1200,
            }
        );
        params.memory_chunk_size = Some(0x800);
        assert_eq!(
            region.region_description(&params, 0x1000),
            RegionDescription {
                start: 0x5000,
                length: 0x1000,
            }
        );
        assert_eq!(
            region.region_description(&params, 0x300),
            RegionDescription {
                start: 0x5000,
                length: 0x600,
            }
        );
        assert_eq!(
            region.region_description(&params, 0x800),
            RegionDescription {
                start: 0x5000,
                length: 0x800,
            }
        );

        assert!(region.update_to_next_chunk(&params));
        assert_eq!(
            region.region_description(&params, 0x800),
            RegionDescription {
                start: 0x5800,
                length: 0x800,
            }
        );

        assert!(region.update_to_next_chunk(&params));
        assert_eq!(
            region.region_description(&params, 0x800),
            RegionDescription {
                start: 0x6000,
                length: 0x200,
            }
        );

        assert!(!region.update_to_next_chunk(&params));
    }
}
