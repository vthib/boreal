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

    /// Scanning mode of fragmented memory.
    pub(crate) fragmented_scan_mode: FragmentedScanMode,

    /// Scanned bytes are part of a process memory.
    pub(crate) process_memory: bool,

    /// Maximum size of a fetched region.
    pub(crate) max_fetched_region_size: usize,

    /// Size of memory chunks to scan.
    pub(crate) memory_chunk_size: Option<usize>,
}

/// Scan mode to use on fragmented memory, including process scanning.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct FragmentedScanMode {
    /// Modules can parse scanned memory to generate dynamic values.
    ///
    /// If true, some modules (pe, elf, macho, etc) will parse
    /// each region to generate dynamic values. For example, the pe
    /// module will parse each region to detect which region
    /// contains a PE header, and generate dynamic values accordingly
    /// once found.
    ///
    /// Generally, these module will stop parsing regions once a
    /// region matching their filetype is found, but their behavior
    /// can differ.
    ///
    /// Enabling this parameter disables the no-scan optimization.
    pub(crate) modules_dynamic_values: bool,

    /// Regions can be fetched multiple times.
    ///
    /// If true, conditions that uses offsets into the scanned memory
    /// can be evaluated, and may thus cause refetches of regions.
    ///
    /// If false, regions are fetched only once: to scan for strings
    /// occurrences, as well as possibly evaluate modules dynamic
    /// values.
    ///
    /// Enabling this parameter disables the no-scan optimization.
    pub(crate) can_refetch_regions: bool,
}

impl FragmentedScanMode {
    /// Legacy mode, i.e. same behavior as YARA.
    ///
    /// This mode ensures that the behavior is identical to a scan
    /// done by libyara, and is set as the default for this reason.
    /// However, the legacy behavior tends to actually be quite
    /// surprising compared to initial expectations.
    ///
    /// In this mode:
    /// - String scanning is done on each region, and results are
    ///   accumulated.
    /// - File scanning modules (PE, ELF, etc) parses each region
    ///   until one region matches, then ignores the subsequent
    ///   regions.
    /// - Conditions that depend on offsets will trigger new
    ///   fetches of data. For example, use of `uint32(offset)`
    ///   or `hash.md5sum(offset, length)` will cause a new
    ///   fetch of this data, separate from the fetch done
    ///   for string scanning. This **can** add up if many
    ///   such conditions are used, causing higher memory usage
    ///   and longer scan durations.
    /// - The filesize condition is undefined.
    ///
    /// In addition, the no-scan optimization is disabled in
    /// this mode.
    #[must_use]
    pub fn legacy() -> Self {
        Self {
            modules_dynamic_values: true,
            can_refetch_regions: true,
        }
    }

    /// Fast mode.
    ///
    /// In this mode, most of the more surprising or ill-defined
    /// semantics of the legacy mode are updated to guarantee
    /// a faster scan. This includes disabling additional fetches
    /// of data as well as disabling file scanning modules.
    ///
    /// In this mode:
    /// - String scanning is done on each region, and results are
    ///   accumulated.
    /// - File scanning modules (PE, ELF, etc) do not
    ///   scan the regions, so they act as if they did not parse
    ///   a compatible file.
    /// - Conditions that depend on offsets evaluate to undefined.
    ///   For example, use of `uint32(offset)`
    ///   or `hash.md5sum(offset, length)` will evaluate to
    ///   the undefined value.
    /// - The filesize condition is undefined.
    ///
    /// The no-scan optimization is enabled in this mode.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            modules_dynamic_values: false,
            can_refetch_regions: false,
        }
    }

    /// Single-pass mode.
    ///
    /// In this mode, a single pass on the regions is guaranteed,
    /// ensuring that each region is fetched only once. This
    /// means scanning time should scale according to both the
    /// number of strings and the sizes of the scanned data,
    /// without risking pathological scanning times due to some
    /// rules triggering refetches of memory regions.
    ///
    /// This mode has the same semantics as the legacy mode, but
    /// conditions depending on offsets in the scanned data will
    /// all evaluate to undefined.
    ///
    /// In this mode:
    /// - String scanning is done on each region, and results are
    ///   accumulated.
    /// - File scanning modules (PE, ELF, etc) parses each region
    ///   until one region matches, then ignores the subsequent
    ///   regions.
    /// - Conditions that depend on offsets evaluate to undefined.
    ///   For example, use of `uint32(offset)`
    ///   or `hash.md5sum(offset, length)` will evaluate to
    ///   the undefined value.
    /// - The filesize condition is undefined.
    ///
    /// The no-scan optimization is disabled in this mode.
    #[must_use]
    pub fn single_pass() -> Self {
        Self {
            modules_dynamic_values: true,
            can_refetch_regions: false,
        }
    }

    // Independent mode.
    //
    // In this mode, each region is scanned independently, as
    // if [`crate::Scanner::scan_mem`] was called on each region.
    // The semantics are thus identical to a direct memory scan.
    // However, the match results are accumulated, so that if a
    // rule matches on multiple regions, it will be returned
    // multiple times.
    //
    // In this mode, the no-scan optimization is enabled.
    //
    // This mode can be faster than the legacy one, thanks to the
    // fact that the no-scan optimization is enabled, and that
    // there is no additional fetch of the data done during the
    // evaluation of conditions.
    // In legacy mode:
    // - String scanning is done on each region, and results are
    //   accumulated.
    // - File scanning modules (PE, ELF, etc) parses each region
    //   until one region matches, then ignores the subsequent
    //   regions.
    // - Conditions that depend on offsets will trigger new
    //   fetches of data. For example, use of `uint32(offset)`
    //   or `hash.md5sum(offset, length)` will cause a new
    //   fetch of this data, separate from the fetch done
    //   for string scanning. This **can** add up if many
    //   such conditions are used, causing higher memory usage
    //   and longer scan durations.
    // - The filesize condition is undefined.
    // TODO
    // fn independent() -> Self {
    //     Self {
    //         independent: true,
    //         modules_dynamic_values: true,
    //         conditions_can_refetch_regions: true,
    //     }
    // }
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
            fragmented_scan_mode: FragmentedScanMode::legacy(),
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

    /// Scan mode on fragmented memory, including process memory.
    ///
    /// This parameter configures how fragmented memory is scanned.
    /// See [`FragmentedScanMode`] for more details.
    ///
    /// By default, this parameter uses the legacy scan mode.
    #[must_use]
    pub fn fragmented_scan_mode(mut self, mode: FragmentedScanMode) -> Self {
        self.fragmented_scan_mode = mode;
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

    /// Returns the scan mode for fragmented memory.
    #[must_use]
    pub fn get_fragmented_scan_mode(&self) -> FragmentedScanMode {
        self.fragmented_scan_mode
    }

    pub(crate) fn to_memory_params(&self) -> MemoryParams {
        MemoryParams {
            max_fetched_region_size: self.max_fetched_region_size,
            memory_chunk_size: self.memory_chunk_size,
            can_refetch_regions: self.fragmented_scan_mode.can_refetch_regions,
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

        let params = params.fragmented_scan_mode(FragmentedScanMode::fast());
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::fast()
        );
    }
}
