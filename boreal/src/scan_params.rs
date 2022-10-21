/// Parameters used to configure a scan.
#[derive(Clone, Debug, Default)]
pub struct ScanParams {
    /// Compute full matches on matching rules.
    pub(crate) compute_full_matches: bool,
}

impl ScanParams {
    /// Compute full matches on matching rules.
    ///
    /// By default, matching rules may not report all of the string matches:
    /// - a rule may match when a variable is found, without needing to find all its matches
    /// - finding out if a regex matches is cheaper than computing the offset and length of its
    ///   matches
    /// - etc
    /// Therefore, the [`crate::ScanResult`] object may not contain what a user would expect.
    ///
    /// Setting this parameter to true ensures that for every matching rules, all of the
    /// variable matches are computed and reported.
    #[must_use]
    pub fn compute_full_matches(mut self, compute_full_matches: bool) -> Self {
        self.compute_full_matches = compute_full_matches;
        self
    }
}
