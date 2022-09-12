/// Parameters used to configure a scan.
#[derive(Clone, Debug)]
pub struct ScanParams<'a> {
    /// Bytes on which to run a scan
    pub(crate) mem: &'a [u8],

    /// Configuration for the early scan optimization.
    pub(crate) early_scan: EarlyScanConfiguration,
}

/// Builder for the [`ScanParams`] object
pub struct ScanParamsBuilder {
    early_scan: EarlyScanConfiguration,
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
        }
    }
}

impl ScanParamsBuilder {
    #[must_use]
    pub fn build(self, mem: &[u8]) -> ScanParams {
        let Self { early_scan } = self;

        ScanParams { mem, early_scan }
    }

    #[must_use]
    pub fn early_scan(mut self, early_scan: EarlyScanConfiguration) -> Self {
        self.early_scan = early_scan;
        self
    }
}
