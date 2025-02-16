/// Scanning error
#[derive(Debug)]
pub enum ScanError {
    /// Scanning took too long and timed out.
    ///
    /// See [`crate::scanner::ScanParams::timeout_duration`] for more details.
    Timeout,

    /// Error when reading the file to scan.
    CannotReadFile(std::io::Error),

    /// Process scanning is not implemented on this operating system.
    UnsupportedProcessScan,

    /// Unknown process.
    UnknownProcess,

    /// Error when listing regions of a process before a scan.
    CannotListProcessRegions(std::io::Error),

    /// The scan callback asked for the scan to be aborted.
    ///
    /// See [`crate::scanner::ScanCallbackResult::Abort`].
    CallbackAbort,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "timeout"),
            Self::CannotReadFile(err) => write!(f, "cannot read file to scan: {err}"),
            Self::UnsupportedProcessScan => {
                write!(f, "process scanning is not implemented on this OS")
            }
            Self::UnknownProcess => {
                write!(f, "unknown process")
            }
            Self::CannotListProcessRegions(error) => {
                write!(f, "error listing memory regions of process: {error}")
            }
            Self::CallbackAbort => {
                write!(f, "scan aborted in callback")
            }
        }
    }
}

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(ScanError::Timeout);
    }
}
