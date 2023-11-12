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
    pub(crate) params: MemoryParams,
}

/// Parameters related to listing and fetching memory to scan.
#[derive(Debug)]
pub struct MemoryParams {
    /// Maximum size of a fetched region.
    ///
    /// See [`crate::scanner::ScanParams::max_fetched_region_size`]
    /// for more details.
    pub max_fetched_region_size: usize,

    /// Size of memory chunks to scan.
    ///
    /// See [`crate::scanner::ScanParams::memory_chunk_size`]
    /// for more details.
    pub memory_chunk_size: Option<usize>,

    /// Regions can be fetched multiple times.
    ///
    /// See [`crate::scanner::FragmentedScanMode`]
    /// for more details.
    pub can_refetch_regions: bool,
}

impl<'a> Memory<'a> {
    pub(crate) fn new_fragmented(
        obj: Box<dyn FragmentedMemory + 'a>,
        params: MemoryParams,
    ) -> Memory {
        Memory::Fragmented(Fragmented { obj, params })
    }
}

impl Memory<'_> {
    pub(crate) fn filesize(&self) -> Option<usize> {
        match self {
            Self::Direct(mem) => Some(mem.len()),
            Self::Fragmented { .. } => None,
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
                if !fragmented.params.can_refetch_regions {
                    return None;
                }

                fragmented.obj.reset();
                while let Some(region) = fragmented.obj.next(&fragmented.params) {
                    let Some(relative_start) = start.checked_sub(region.start) else {
                        break;
                    };
                    if relative_start >= region.length {
                        continue;
                    }
                    let end = end.checked_sub(region.start)?;
                    let end = std::cmp::min(region.length, end);

                    let region = fragmented.obj.fetch(&fragmented.params)?;
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
    /// List the next region that can be scanned.
    ///
    /// If None is returned, the listing is considered complete.
    fn next(&mut self, params: &MemoryParams) -> Option<RegionDescription>;

    /// Fetch the current region.
    ///
    /// Fetch the region that was last returned by a call to [`FragmentedMemory::next`].
    ///
    /// If unable to fetch, None must be returned. The region will be ignored,
    /// but scanning will go on:
    /// - This region will not be scanned for strings occurrences, nor will it be
    ///   handled in modules (for example, it will not be parsed by the pe module
    ///   if used).
    /// - If the fetch was done during evaluation, the expression will evaluate
    ///   as `undefined`.
    fn fetch(&mut self, params: &MemoryParams) -> Option<Region>;

    /// Reset the object.
    ///
    /// This can be called to reset the object to its initial state. After this
    /// function is called, a call to [`FragmentedMemory::next`] should list
    /// the first region available.
    ///
    /// This is used when multiple iterations over the memory regions are needed.
    /// For example, a first iteration is done for string scanning, but this method can be
    /// called to iterate on regions again when evaluating some conditions
    /// that require access to specific regions.
    fn reset(&mut self);
}

/// A description of a region of memory to scan.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    use super::*;

    #[derive(Debug)]
    struct DummyFragmented;

    impl FragmentedMemory for DummyFragmented {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn reset(&mut self) {}

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn next(&mut self, _params: &MemoryParams) -> Option<RegionDescription> {
            None
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn fetch(&mut self, _params: &MemoryParams) -> Option<Region> {
            None
        }
    }

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(Memory::Direct(b""));
        test_type_traits_non_clonable(Region { start: 0, mem: b"" });
        test_type_traits(RegionDescription {
            start: 0,
            length: 0,
        });
        test_type_traits_non_clonable(MemoryParams {
            max_fetched_region_size: 0,
            memory_chunk_size: None,
            can_refetch_regions: false,
        });
        test_type_traits_non_clonable(DummyFragmented);
        test_type_traits_non_clonable(Fragmented {
            obj: Box::new(DummyFragmented),
            params: MemoryParams {
                max_fetched_region_size: 0,
                memory_chunk_size: None,
                can_refetch_regions: false,
            },
        });
    }
}
