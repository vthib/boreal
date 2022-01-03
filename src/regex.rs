//! Regular expressions handling.

/// A regular expression.
#[derive(Clone, Debug, PartialEq)]
pub struct Regex {
    /// The regular expression parsed inside the `/` delimiters.
    pub expr: String,
    /// case insensitive (`i` flag).
    pub case_insensitive: bool,
    /// `.` matches `\n` (`s` flag).
    pub dot_all: bool,
}
