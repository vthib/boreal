//! Parameters applicable to a scan.

use std::time::Duration;

/// Parameters used to configure a scan.
#[derive(Clone, Debug)]
pub struct ScanParams {
    /// Compute full matches on matching rules.
    pub(crate) compute_full_matches: bool,

    /// Max length of the matches returned in matching rules.
    pub(crate) match_max_length: usize,

    /// Max number of matches for a given string.
    pub(crate) string_max_nb_matches: usize,

    /// Max duration for a scan before it is aborted.
    pub(crate) timeout_duration: Option<Duration>,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            compute_full_matches: false,
            match_max_length: 512,
            string_max_nb_matches: 1_000,
            timeout_duration: None,
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
    pub fn string_max_nb_matches(mut self, string_max_nb_matches: usize) -> Self {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits;

    #[test]
    fn test_types_traits() {
        test_type_traits(ScanParams::default());
    }
}
