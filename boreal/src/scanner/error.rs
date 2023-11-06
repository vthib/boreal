/// Scanning error
#[derive(Debug)]
pub enum ScanError {
    /// Scanning took too long and timed out.
    ///
    /// See [`crate::scanner::ScanParams::timeout_duration`] for more details.
    Timeout,

    /// Error when reading a file to scan.
    ScannedFileRead(std::io::Error),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "timeout"),
            Self::ScannedFileRead(err) => write!(f, "error reading the file to scan: {err}"),
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
