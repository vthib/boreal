/// Parameters used to configure a scan.
#[derive(Clone, Debug)]
pub struct ScanParams {
    /// Compute full matches on matching rules.
    pub(crate) compute_full_matches: bool,
}

/// Builder for the [`ScanParams`] object
#[derive(Clone, Debug)]
pub struct ScanParamsBuilder {
    compute_full_matches: bool,
}

impl Default for ScanParamsBuilder {
    fn default() -> Self {
        Self {
            compute_full_matches: false,
        }
    }
}

impl ScanParamsBuilder {
    /// Consume the builder and generate a [`ScanParams`] object usable for scans.
    #[must_use]
    pub fn build(self) -> ScanParams {
        let Self {
            compute_full_matches,
        } = self;

        ScanParams {
            compute_full_matches,
        }
    }

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
