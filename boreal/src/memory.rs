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
        regions: &'a [Region<'a>],
    },
}

impl<'a> Memory<'a> {
    pub(crate) fn filesize(&self) -> Option<usize> {
        match self {
            Self::Direct(mem) => Some(mem.len()),
            Self::Fragmented { .. } => None,
        }
    }

    /// True if all the memory is readily available.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        match self {
            Self::Direct(_) => true,
            Self::Fragmented { .. } => false,
        }
    }

    /// Returns the byte slice of the whole scanned memory if available.
    #[must_use]
    pub fn get_direct(&self) -> Option<&[u8]> {
        match self {
            Self::Direct(v) => Some(*v),
            Self::Fragmented { .. } => None,
        }
    }

    /// Retrieve the data that matches the given range, potentially truncated.
    ///
    /// This will fetch the memory region containing this range and return the data slice
    /// matching the exact range, possibly truncated.
    ///
    /// If the start does not belong to any memory region, None is returned.
    ///
    /// If the end is after the end of the region, the slice is truncated.
    // TODO: return an iterator if the range overlaps multiple regions that are contiguous?
    #[must_use]
    pub fn get(&self, start: usize, end: usize) -> Option<&'a [u8]> {
        match self {
            Self::Direct(mem) => {
                if start >= mem.len() {
                    None
                } else {
                    let end = std::cmp::min(mem.len(), end);
                    mem.get(start..end)
                }
            }
            Self::Fragmented { regions } => {
                for region in *regions {
                    let Some(relative_start) = start.checked_sub(region.start) else {
                        break;
                    };
                    if relative_start >= region.mem.len() {
                        continue;
                    }
                    let end = end.checked_sub(region.start)?;
                    let end = std::cmp::min(region.mem.len(), end);
                    return region.mem.get(relative_start..end);
                }

                None
            }
        }
    }
}

/// A region of memory to scan.
#[derive(Debug)]
pub struct Region<'a> {
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
        test_type_traits_non_clonable(Region { start: 0, mem: b"" });
    }
}
