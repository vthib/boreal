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
    ) -> Self {
        Self::Fragmented(Fragmented { obj, params })
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
    /// matching the exact range.
    ///
    /// If the start does not belong to any memory region, None is returned.
    ///
    /// This will only return data from the first memory chunk that intersects the provided
    /// range, and only if this chunk contains the full range. For this reason, in almost
    /// all use cases, it is recommended to use the [`Memory::on_range`] instead, which
    /// will iterate properly on all chunks covering the provided range.
    /// This function exists mostly for retrieval of very small byte slices, such as for
    /// the `uintXX(offset)` expressions.
    #[must_use]
    pub(crate) fn get_contiguous(&mut self, start: usize, end: usize) -> Option<&[u8]> {
        if end < start {
            return None;
        }

        match self {
            Self::Direct(mem) => {
                if start >= mem.len() {
                    None
                } else {
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

                    let region = fragmented.obj.fetch(&fragmented.params)?;
                    return region.mem.get(relative_start..(end - region.start));
                }

                None
            }
        }
    }

    /// Call a callback on each data slice covering a given range.
    ///
    /// This will fetch the memory regions that contain data in this range, and call the
    /// callback on each contiguous data slice.
    ///
    /// As soon as the range is entirely covered or contains indexes that are not covered by any
    /// region, the iteration will end.
    ///
    /// In other words:
    ///
    /// - The first data slice starts on the starting index of the range.
    /// - If the callback is called multiple times, each data slice is guaranteed to be exactly
    ///   following the previous one (no undefined bytes in between).
    /// - The range may not be covered entirely, e.g. asking for `[0; 2*filesize[` will lead
    ///   to the callback being called once, on `[0; filesize[`.
    ///
    /// `None` is returned if either:
    /// - the callback has not been called at least once (so no memory region contains the
    ///   starting bytes of the range).
    /// - there are undefined bytes in between two regions covering the range.
    /// - a region cannot be fetched.
    ///
    /// For example, when providing the range `[50; 100[`, and with regions:
    ///
    /// - `[0;70[`
    /// - `[70; 80[`
    /// - `[80; 150[`
    ///
    /// The callback will be called with `[50; 70[`, `[70; 80[` and `[80; 100[` then
    /// `Some(())` will be returned.
    ///
    /// with regions:
    ///
    /// - `[0;70[`
    /// - `[70; 80[`
    /// - `[90; 150[`
    ///
    /// The callback will be called with `[50; 70[` and `[70; 80[`, then `None` will
    /// be returned.
    ///
    /// with regions:
    ///
    /// - `[0;70[`
    ///
    /// The callback will be called with `[50; 70[` only, then `Some(())` will be
    /// returned.
    ///
    /// And with regions:
    ///
    /// - `[60;70[`
    ///
    /// The callback will not be called at all, and `None` will be returned.
    #[must_use]
    pub fn on_range<F>(&mut self, mut start: usize, end: usize, mut cb: F) -> Option<()>
    where
        F: FnMut(&[u8]),
    {
        if end < start {
            return None;
        }

        match self {
            Self::Direct(mem) => {
                if start >= mem.len() {
                    None
                } else {
                    let end = std::cmp::min(mem.len(), end);
                    cb(&mem[start..end]);
                    Some(())
                }
            }
            Self::Fragmented(fragmented) => {
                if !fragmented.params.can_refetch_regions {
                    return None;
                }

                let mut has_called_cb = false;

                fragmented.obj.reset();
                while let Some(region) = fragmented.obj.next(&fragmented.params) {
                    // If we already called the callback once, the next regions should
                    // be contiguous.
                    if has_called_cb && start != region.start {
                        return None;
                    }
                    // Adjust starting offset relative to the region base
                    let Some(relative_start) = start.checked_sub(region.start) else {
                        break;
                    };
                    if relative_start >= region.length {
                        continue;
                    }

                    // Adjust ending offset relative to the region base and length
                    let relative_end = std::cmp::min(region.length, end - region.start);

                    let fetched_region = fragmented.obj.fetch(&fragmented.params)?;
                    cb(&fetched_region.mem[relative_start..relative_end]);
                    has_called_cb = true;

                    // Update the starting offset for the next region.
                    start = region.start.checked_add(region.length)?;
                    if start >= end {
                        // Range has been entirely covered.
                        break;
                    }
                }

                if has_called_cb {
                    Some(())
                } else {
                    None
                }
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_proper_range() {
        let mut mem = Memory::Direct(b"abc");
        assert_eq!(mem.get_contiguous(2, 1), None);
        assert_eq!(mem.on_range(2, 1, |_| {}), None);
    }
}
