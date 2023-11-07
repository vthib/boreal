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
    Fragmented(Fragmented<'a>),
}

/// Fragmented memory
#[derive(Debug)]
pub struct Fragmented<'a> {
    pub(crate) obj: Box<dyn FragmentedMemory + 'a>,
    pub(crate) regions: Vec<RegionDescription>,
}

impl<'a> Memory<'a> {
    pub(crate) fn new_fragmented(obj: Box<dyn FragmentedMemory + 'a>) -> Memory {
        // Cache the regions in the object. This avoids reallocating a Vec everytime
        // we list the regions.
        let regions = obj.list_regions();

        Memory::Fragmented(Fragmented { obj, regions })
    }
}

impl Memory<'_> {
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
    pub fn get(&mut self, start: usize, end: usize) -> Option<&[u8]> {
        match self {
            Self::Direct(mem) => {
                if start >= mem.len() {
                    None
                } else {
                    let end = std::cmp::min(mem.len(), end);
                    mem.get(start..end)
                }
            }
            Self::Fragmented(fragmented) => {
                for region in &fragmented.regions {
                    let Some(relative_start) = start.checked_sub(region.start) else {
                        break;
                    };
                    if relative_start >= region.length {
                        continue;
                    }
                    let end = end.checked_sub(region.start)?;
                    let end = std::cmp::min(region.length, end);

                    let region = fragmented.obj.fetch_region(*region)?;
                    return region.mem.get(relative_start..end);
                }

                None
            }
        }
    }
}

/// Memory to scan, fragmented into different regions.
///
/// This trait can be implemented to scan bytes which are not arranged as a
/// single slice. The main use case is for example scanning the memory of a
/// process, which is arranged in non contiguous regions of mapped bytes.
pub trait FragmentedMemory: Send + Sync + std::fmt::Debug {
    /// List non overlapping regions mapping the fragmented memory.
    ///
    /// This listing should be cheap. Actually retrieving the memory behind a region
    /// should only be done in the [`FragmentedMemory::fetch_region`] method.
    /// This is also the reason why this function cannot fail, the regions should have been
    /// precomputed already.
    fn list_regions(&self) -> Vec<RegionDescription>;

    /// Fetch the data of a region.
    ///
    /// If unable to fetch, None must be returned. The region will be ignored,
    /// but scanning will go on:
    /// - This region will not be scanned for strings occurrences, nor will it be
    ///   handled in modules (for example, it will not be parsed by the pe module
    ///   if used).
    /// - If the fetch was done during evaluation, the expression will evaluate
    ///   as `undefined`.
    fn fetch_region(&mut self, region_desc: RegionDescription) -> Option<Region>;
}

/// A description of a region of memory to scan.
#[derive(Copy, Clone, Debug)]
pub struct RegionDescription {
    /// Index of the start of the region.
    pub start: usize,

    /// Length of the region.
    pub length: usize,
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
        test_type_traits_non_clonable(RegionDescription {
            start: 0,
            length: 0,
        });
    }
}
