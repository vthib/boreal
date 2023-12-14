//! Parameters applicable to a scan.

use std::time::Duration;

use crate::memory::MemoryParams;

/// Parameters used to configure a scan.
#[derive(Clone, Debug)]
pub struct ScanParams {
    /// Compute full matches on matching rules.
    pub(crate) compute_full_matches: bool,

    /// Max length of the matches returned in matching rules.
    pub(crate) match_max_length: usize,

    /// Max number of matches for a given string.
    pub(crate) string_max_nb_matches: u32,

    /// Max duration for a scan before it is aborted.
    pub(crate) timeout_duration: Option<Duration>,

    /// Compute statistics on scanning.
    ///
    /// This requires the `profiling` feature.
    pub(crate) compute_statistics: bool,

    /// Scanned bytes are part of a process memory.
    pub(crate) process_memory: bool,

    /// Maximum size of a fetched region.
    pub(crate) max_fetched_region_size: usize,

    /// Size of memory chunks to scan.
    pub(crate) memory_chunk_size: Option<usize>,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            compute_full_matches: false,
            match_max_length: 512,
            string_max_nb_matches: 1_000,
            timeout_duration: None,
            compute_statistics: false,
            process_memory: false,
            max_fetched_region_size: 1024 * 1024 * 1024,
            memory_chunk_size: None,
        }
    }
}

impl ScanParams {
    /// Compute full matches on matching rules.
    ///
    /// By default, matching rules may not report all of the string matches:
    /// - a rule may match when a variable is found, without needing to find all its matches
    /// - finding out if a regex matches is cheaper than computing the offset and length of its
    ///   matches
    /// - etc
    /// Therefore, the [`crate::scanner::ScanResult`] object may not contain what a user would
    /// expect.
    ///
    /// Setting this parameter to true ensures that for every matching rules, all of the
    /// variable matches are computed and reported.
    #[must_use]
    pub fn compute_full_matches(mut self, compute_full_matches: bool) -> Self {
        self.compute_full_matches = compute_full_matches;
        self
    }

    /// Max length of the matches returned in matching rules.
    ///
    /// This is the max length of [`crate::scanner::StringMatch::data`].
    ///
    /// The default value is `512`.
    #[must_use]
    pub fn match_max_length(mut self, match_max_length: usize) -> Self {
        self.match_max_length = match_max_length;
        self
    }

    /// Max number of matches for a given string.
    ///
    /// Matches that would occur after this value are not reported. This means that `#a` can never
    /// be greater than this value, and `!a[i]` or `@a[i]` where `i` is greater than this value is
    /// always undefined.
    ///
    /// The default value is `1_000`.
    #[must_use]
    pub fn string_max_nb_matches(mut self, string_max_nb_matches: u32) -> Self {
        self.string_max_nb_matches = string_max_nb_matches;
        self
    }

    /// Maximum duration of a scan before it is stopped.
    ///
    /// If a scan lasts longer that the timeout, the scan will be stopped, and only results
    /// computed before the timeout will be returned.
    ///
    /// By default, no timeout is set.
    #[must_use]
    pub fn timeout_duration(mut self, timeout_duration: Option<Duration>) -> Self {
        self.timeout_duration = timeout_duration;
        self
    }

    /// Compute statistics during scanning.
    ///
    /// This option allows retrieve statistics related to the scanning of bytes.
    /// See `AddRuleStatus::statistics`.
    ///
    /// Default value is false.
    #[must_use]
    pub fn compute_statistics(mut self, compute_statistics: bool) -> Self {
        self.compute_statistics = compute_statistics;
        self
    }

    /// Scanned bytes are part of the memory of a process.
    ///
    /// This has an impact of the behavior of some modules. For example, some file analysis
    /// modules such as `pe` or `elf` will depend on this flag to decide whether to use the
    /// virtual address values (if this flag is true), or the file offset values (if it is
    /// false).
    ///
    /// This is always true when using the APIs to scan a process, regardless of this
    /// parameter. It is false in other APIs, unless this parameter is set.
    ///
    /// One reason to use this parameter is for example to modify how a process regions
    /// are fetched or filtered, but still rely on the same scanning behavior. The
    /// [`crate::Scanner::scan_mem`] or [`crate::Scanner::scan_fragmented`] can then be used,
    /// and the scan will evaluate as if [`crate::Scanner::scan_process`] was called.
    #[must_use]
    pub fn process_memory(mut self, process_memory: bool) -> Self {
        self.process_memory = process_memory;
        self
    }

    /// Maximum size of a fetched region.
    ///
    /// This parameter applies to fragmented memory scanning, using either the
    /// [`crate::Scanner::scan_fragmented`] or [`crate::Scanner::scan_process`]
    /// function.
    ///
    /// If a region is larger than this value, only this size will be
    /// fetched. For example, if this value is 50MB and a region has a size
    /// of 80MB, then only the first 50MB will be scanned, and the trailing
    /// 30MB left will not be scanned.
    ///
    /// This parameter exists as a safeguard, to ensure that memory
    /// consumption will never go above this limit. You may however prefer
    /// tweaking the [`ScanParams::memory_chunk_size`] parameter, to bound
    /// memory consumption while still ensuring every byte is scanned.
    ///
    /// Please note that this value may be adjusted to ensure it is a
    /// multiple of the page size.
    ///
    /// By default, this parameter is set to 1GB.
    #[must_use]
    pub fn max_fetched_region_size(mut self, max_fetched_region_size: usize) -> Self {
        self.max_fetched_region_size = max_fetched_region_size;
        self
    }

    /// Size of memory chunks to scan.
    ///
    /// This parameter bounds the size of the chunks of memory that are
    /// scanned. This only applies to fragmented memory (using either
    /// [`crate::Scanner::scan_fragmented`] or
    /// [`crate::Scanner::scan_process`]) and does not apply when
    /// scanning a contiguous slice of bytes (scanning a file or a
    /// byteslice).
    ///
    /// When this parameter is set, every region that is scanned is
    /// split into chunks of this size maximum, and each chunk is
    /// scanned independently. For example, if a process has a region
    /// of size 80MB, and this parameter is set to 30MB, then:
    ///
    /// - the first 30MB are first fetched and scanned
    /// - the next 30MB are then fetched and scanned
    /// - the last 20MB are then fetched and scanned
    ///
    /// This parameter thus allows setting a bound on the memory
    /// consumption of fragmented memory scanning, while still
    /// scanning all of the bytes available.
    ///
    /// Note however than setting this parameter can cause false
    /// negatives, as string scanning does not handle strings that
    /// are split between different chunks. For example, when
    /// scanning for the string `boreal`, if one chunk ends with
    /// `bor`, and the next one starts with `eal`, the string will
    /// **not** match.
    ///
    /// Please note that, if set, this value may be adjusted to ensure it
    /// is a multiple of the page size.
    ///
    /// By default, this parameter is unset.
    #[must_use]
    pub fn memory_chunk_size(mut self, memory_chunk_size: Option<usize>) -> Self {
        self.memory_chunk_size = memory_chunk_size;
        self
    }

    /// Returns whether full matches are computed on matching rules.
    #[must_use]
    pub fn get_compute_full_matches(&self) -> bool {
        self.compute_full_matches
    }

    /// Returns the maxiumum length of the matches returned in matching rules.
    #[must_use]
    pub fn get_match_max_length(&self) -> usize {
        self.match_max_length
    }

    /// Returns the maximum number of matches for a given string.
    #[must_use]
    pub fn get_string_max_nb_matches(&self) -> u32 {
        self.string_max_nb_matches
    }

    /// Returns the maximum duration of a scan before it is stopped.
    #[must_use]
    pub fn get_timeout_duration(&self) -> Option<&Duration> {
        self.timeout_duration.as_ref()
    }

    /// Returns whether statistics are computed during scanning.
    #[must_use]
    pub fn get_compute_statistics(&self) -> bool {
        self.compute_statistics
    }

    /// Returns whether scanned bytes are considered part of the memory of a process.
    #[must_use]
    pub fn get_process_memory(&self) -> bool {
        self.process_memory
    }

    /// Returns the maximum size of a fetched region.
    #[must_use]
    pub fn get_max_fetched_region_size(&self) -> usize {
        self.max_fetched_region_size
    }

    /// Returns the size of memory chunks to scan.
    #[must_use]
    pub fn get_memory_chunk_size(&self) -> Option<usize> {
        self.memory_chunk_size
    }

    pub(crate) fn to_memory_params(&self) -> MemoryParams {
        MemoryParams {
            max_fetched_region_size: self.max_fetched_region_size,
            memory_chunk_size: self.memory_chunk_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits;

    #[test]
    fn test_types_traits() {
        test_type_traits(ScanParams::default());
    }

    #[test]
    fn test_getters() {
        let params = ScanParams::default();

        let params = params.compute_full_matches(true);
        assert!(params.get_compute_full_matches());

        let params = params.match_max_length(3);
        assert_eq!(params.get_match_max_length(), 3);

        let params = params.string_max_nb_matches(3);
        assert_eq!(params.get_string_max_nb_matches(), 3);

        let params = params.timeout_duration(Some(Duration::from_secs(4)));
        assert_eq!(params.get_timeout_duration(), Some(&Duration::from_secs(4)));

        let params = params.compute_statistics(true);
        assert!(params.get_compute_statistics());

        let params = params.process_memory(true);
        assert!(params.get_process_memory());

        let params = params.max_fetched_region_size(100);
        assert_eq!(params.get_max_fetched_region_size(), 100);

        let params = params.memory_chunk_size(Some(200));
        assert_eq!(params.get_memory_chunk_size(), Some(200));
    }
}
