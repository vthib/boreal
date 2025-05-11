//! Parameters applicable to a scan.

use std::time::Duration;

use crate::memory::MemoryParams;

/// Parameters used to configure a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// Bitflag of which events are enabled in the scan callback.
    pub(crate) callback_events: CallbackEvents,

    /// Include not matched rules into results.
    pub(crate) include_not_matched_rules: bool,
}

/// Scan mode to use on fragmented memory, including process scanning.
///
/// There are several different ways to handle how multiple
/// disjointed memory regions are scanned. Use this parameter to
/// change how this scanning is done.
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
            callback_events: CallbackEvents::RULE_MATCH,
            include_not_matched_rules: false,
        }
    }
}

impl ScanParams {
    /// Compute full matches on matching rules.
    ///
    /// By default, matching rules may not report all of the string matches:
    ///
    /// - a rule may match when a variable is found, without needing to find all its matches
    /// - finding out if a regex matches is cheaper than computing the offset and length of its
    ///   matches
    /// - etc
    ///
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
    ///
    /// This requires the `profiling` feature.
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
    /// This parameter is used for both the [`crate::Scanner::scan_process`]
    /// and the [`crate::Scanner::scan_fragmented`] APIs.
    ///
    /// By default, this parameter uses the legacy scan mode.
    #[must_use]
    pub fn fragmented_scan_mode(mut self, mode: FragmentedScanMode) -> Self {
        self.fragmented_scan_mode = mode;
        self
    }

    /// Bitflag of which events are enabled in the scan callback.
    ///
    /// By default, only [`crate::scanner::ScanEvent::RuleMatch`] is enabled.
    /// Use [`ScanParams::callback_events`] with a bitflag of valuesof this
    /// enum to enable additional events.
    ///
    /// ```
    /// use boreal::scanner::{CallbackEvents, ScanParams};
    /// # let mut scanner = boreal::Compiler::new().finalize();
    ///
    /// scanner.set_scan_params(
    ///     ScanParams::default()
    ///         .callback_events(CallbackEvents::RULE_MATCH | CallbackEvents::MODULE_IMPORT),
    /// );
    /// ```
    #[must_use]
    pub fn callback_events(mut self, callback_events: CallbackEvents) -> Self {
        self.callback_events = callback_events;
        self
    }

    /// Include rules that do not match in results.
    ///
    /// If set, scan results will include both rules that matched and rules that did not
    /// match. The field [`crate::scanner::EvaluatedRule::matched`] can be used to
    /// distinguish the two.
    ///
    /// If using the callback API, the [`CallbackEvents::RULE_NO_MATCH`] flag must
    /// also be set.
    ///
    /// It is *not* recommended to set this field, as it may slow down the overall scan.
    /// Notably, setting this parameter disables the no scan optimization.
    #[must_use]
    pub fn include_not_matched_rules(mut self, include_not_matched_rules: bool) -> Self {
        self.include_not_matched_rules = include_not_matched_rules;
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

    /// Returns the bitflag of which events are enabled in the scan callback.
    #[must_use]
    pub fn get_callback_events(&self) -> CallbackEvents {
        self.callback_events
    }

    /// Returns whether rules that do not match are included in results.
    #[must_use]
    pub fn get_include_not_matched_rules(&self) -> bool {
        self.include_not_matched_rules
    }

    pub(crate) fn to_memory_params(&self) -> MemoryParams {
        MemoryParams {
            max_fetched_region_size: self.max_fetched_region_size,
            memory_chunk_size: self.memory_chunk_size,
            can_refetch_regions: self.fragmented_scan_mode.can_refetch_regions,
        }
    }
}

/// Bitflag values of callback events.
///
/// See [`ScanParams::callback_events`] for more details.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CallbackEvents(pub(crate) u32);

impl CallbackEvents {
    /// Enables the [`crate::scanner::ScanEvent::RuleMatch`] events.
    pub const RULE_MATCH: CallbackEvents = CallbackEvents(0b0000_0001);

    /// Enables the [`crate::scanner::ScanEvent::RuleNoMatch`] events.
    ///
    /// The [`ScanParams::include_not_matched_rules`] parameter must also be set to true
    /// to received those events.
    pub const RULE_NO_MATCH: CallbackEvents = CallbackEvents(0b0000_0010);

    /// Enables the [`crate::scanner::ScanEvent::ModuleImport`] events.
    pub const MODULE_IMPORT: CallbackEvents = CallbackEvents(0b0000_0100);

    /// Enables the [`crate::scanner::ScanEvent::ScanStatistics`] events.
    ///
    /// The [`ScanParams::compute_statistics`] parameter must be set to true, and
    /// the `profiling` feature must have been enabled during compilation.
    pub const SCAN_STATISTICS: CallbackEvents = CallbackEvents(0b0000_1000);

    /// Enables the [`crate::scanner::ScanEvent::StringReachedMatchLimit`] events.
    pub const STRING_REACHED_MATCH_LIMIT: CallbackEvents = CallbackEvents(0b0001_0000);

    /// Return an empty bitflag
    #[must_use]
    pub fn empty() -> Self {
        Self(0)
    }
}

impl std::ops::BitOr for CallbackEvents {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitAnd for CallbackEvents {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl std::ops::BitOrAssign for CallbackEvents {
    fn bitor_assign(&mut self, other: Self) {
        self.0.bitor_assign(other.0);
    }
}

impl std::ops::BitAndAssign for CallbackEvents {
    fn bitand_assign(&mut self, other: Self) {
        self.0.bitand_assign(other.0);
    }
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;
    use std::time::Duration;

    use crate::wire::{Deserialize, Serialize};

    use super::{CallbackEvents, FragmentedScanMode, ScanParams};

    impl Serialize for ScanParams {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.compute_full_matches.serialize(writer)?;
            self.match_max_length.serialize(writer)?;
            self.string_max_nb_matches.serialize(writer)?;
            self.timeout_duration
                .map(|v| (v.as_secs(), v.subsec_nanos()))
                .serialize(writer)?;
            self.compute_statistics.serialize(writer)?;
            self.fragmented_scan_mode.serialize(writer)?;
            self.process_memory.serialize(writer)?;
            self.max_fetched_region_size.serialize(writer)?;
            self.memory_chunk_size.serialize(writer)?;
            self.callback_events.0.serialize(writer)?;
            self.include_not_matched_rules.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for ScanParams {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let compute_full_matches = bool::deserialize_reader(reader)?;
            let match_max_length = usize::deserialize_reader(reader)?;
            let string_max_nb_matches = u32::deserialize_reader(reader)?;
            let timeout_duration = <Option<(u64, u32)>>::deserialize_reader(reader)?;
            let compute_statistics = bool::deserialize_reader(reader)?;
            let fragmented_scan_mode = FragmentedScanMode::deserialize_reader(reader)?;
            let process_memory = bool::deserialize_reader(reader)?;
            let max_fetched_region_size = usize::deserialize_reader(reader)?;
            let memory_chunk_size = <Option<usize>>::deserialize_reader(reader)?;
            let callback_events = u32::deserialize_reader(reader)?;
            let include_not_matched_rules = bool::deserialize_reader(reader)?;
            Ok(Self {
                compute_full_matches,
                match_max_length,
                string_max_nb_matches,
                timeout_duration: timeout_duration.map(|(secs, nanos)| Duration::new(secs, nanos)),
                compute_statistics,
                fragmented_scan_mode,
                process_memory,
                max_fetched_region_size,
                memory_chunk_size,
                callback_events: CallbackEvents(callback_events),
                include_not_matched_rules,
            })
        }
    }

    impl Serialize for FragmentedScanMode {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.modules_dynamic_values.serialize(writer)?;
            self.can_refetch_regions.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for FragmentedScanMode {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let modules_dynamic_values = bool::deserialize_reader(reader)?;
            let can_refetch_regions = bool::deserialize_reader(reader)?;
            Ok(Self {
                modules_dynamic_values,
                can_refetch_regions,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::wire::tests::test_round_trip;

        #[test]
        fn test_wire_scan_params() {
            test_round_trip(
                &ScanParams {
                    compute_full_matches: true,
                    match_max_length: 23,
                    string_max_nb_matches: 12,
                    timeout_duration: Some(Duration::from_millis(1_290_874)),
                    compute_statistics: false,
                    fragmented_scan_mode: FragmentedScanMode {
                        modules_dynamic_values: false,
                        can_refetch_regions: true,
                    },
                    process_memory: true,
                    max_fetched_region_size: 29_392,
                    memory_chunk_size: Some(128),
                    callback_events: CallbackEvents::RULE_MATCH | CallbackEvents::MODULE_IMPORT,
                    include_not_matched_rules: true,
                },
                &[0, 1, 9, 13, 26, 27, 29, 30, 38, 47, 51],
            );

            test_round_trip(
                &FragmentedScanMode {
                    modules_dynamic_values: true,
                    can_refetch_regions: false,
                },
                &[0, 1],
            );
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

        let params =
            params.callback_events(CallbackEvents::RULE_MATCH | CallbackEvents::MODULE_IMPORT);
        assert_eq!(
            params.get_callback_events(),
            CallbackEvents::RULE_MATCH | CallbackEvents::MODULE_IMPORT
        );

        let params = params.include_not_matched_rules(true);
        assert!(params.get_include_not_matched_rules());
    }

    #[test]
    fn test_callback_events_ops() {
        let a = CallbackEvents::RULE_MATCH;
        let b = CallbackEvents::MODULE_IMPORT;

        assert_eq!(a | b, CallbackEvents(0b101));
        assert_eq!(a & b, CallbackEvents(0b000));

        let mut c = a;
        c |= b;
        assert_eq!(c, CallbackEvents(0b101));
        assert_eq!(c & a, CallbackEvents(0b01));
        c &= b;
        assert_eq!(c, CallbackEvents(0b100));
    }
}
