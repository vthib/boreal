//! Describe the different types of objects that can be scanned.

/// Memory to scan
#[derive(Debug)]
pub enum Memory<'a> {
    /// Direct access to all of the bytes to scan.
    ///
    /// For example, scanning a file using mmap.
    Direct(&'a [u8]),

    /// Fragmented access to the bytes to scan.
    ///
    /// This is as if the bytes to scan had holes, which is useful when scanning
    /// the memory of a process, which consists of non contiguous regions of
    /// bytes.
    Fragmented {
        /// Non overlapping regions mapping the fragmented memory.
        regions: &'a [MemoryRegion<'a>],
    },
}

impl Memory<'_> {
    pub(crate) fn filesize(&self) -> Option<usize> {
        match self {
            Self::Direct(mem) => Some(mem.len()),
            Self::Fragmented { .. } => None,
        }
    }

    /// TODO
    #[must_use]
    pub fn get(&self, start: usize, length: usize) -> Option<&[u8]> {
        match self {
            Self::Direct(mem) => {
                let end = start.checked_add(length)?;
                mem.get(start..end)
            }
            Self::Fragmented { regions } => {
                for region in *regions {
                    let Some(relative_start) = start.checked_sub(region.start) else {
                        break;
                    };
                    if relative_start > region.mem.len() {
                        continue;
                    }
                    let end = relative_start.checked_add(length)?;
                    return region.mem.get(relative_start..end);
                }

                None
            }
        }
    }
}

/// A region of memory to scan.
#[derive(Debug)]
pub struct MemoryRegion<'a> {
    /// Index of the start of the region.
    pub start: usize,

    /// Bytes of the whole region.
    pub mem: &'a [u8],
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(Memory::Direct(b""));
        test_type_traits_non_clonable(MemoryRegion { start: 0, mem: b"" });
    }
}