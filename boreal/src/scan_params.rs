/// Parameters used to configure a scan.
#[derive(Clone, Debug)]
pub struct ScanParams<'a> {
    /// Bytes on which to run a scan
    pub(crate) mem: &'a [u8],

    /// Configuration for the early scan optimization.
    pub(crate) early_scan: EarlyScanConfiguration,

    /// Compute full matches on matching rules.
    pub(crate) compute_full_matches: bool,
}

/// Builder for the [`ScanParams`] object
#[derive(Clone, Debug)]
pub struct ScanParamsBuilder {
    early_scan: EarlyScanConfiguration,
    compute_full_matches: bool,
}

/// Parameters for the use of the early scanning optimization.
///
/// This optimization attempts to look for the presence of strings in as few scans as possible.
///
/// Modifying this parameter is mostly present for testing purposes.
#[derive(Clone, Debug)]
pub enum EarlyScanConfiguration {
    /// Let the engine decide the configuration.
    ///
    /// This will depend on the size of the bytes to scan, the total number of strings, etc.
    /// This is the recommended value.
    AutoConfigure,

    /// Disable the early scan optimization.
    ///
    /// This will disable any initial scan for string matches, and only do
    /// those scans on-demand, so when each rule is evaluated.
    Disable,

    /// Enable the early scan optimization.
    ///
    /// Always enable the optimizaial scan for string matches, and only do
    /// those scans on-demand, so when each rule is evaluated.
    Enable,
}

impl Default for ScanParamsBuilder {
    fn default() -> Self {
        Self {
            early_scan: EarlyScanConfiguration::AutoConfigure,
            compute_full_matches: false,
        }
    }
}

impl ScanParamsBuilder {
    /// Consume the builder and generate a [`ScanParams`] object usable for scans.
    #[must_use]
    pub fn build(self, mem: &[u8]) -> ScanParams {
        let Self {
            early_scan,
            compute_full_matches,
        } = self;

        ScanParams {
            mem,
            early_scan,
            compute_full_matches,
        }
    }

    /// Configuration for the early scan optimization.
    #[must_use]
    pub fn early_scan(mut self, early_scan: EarlyScanConfiguration) -> Self {
        self.early_scan = early_scan;
        self
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
