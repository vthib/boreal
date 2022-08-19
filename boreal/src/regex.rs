use regex::bytes::RegexBuilder;

/// Regex following the YARA format.
///
/// This represents a regex expression as can be used in a YARA rule, either as a
/// string or has a raw value.
#[derive(Clone, Debug)]
pub struct Regex(regex::bytes::Regex);

impl Regex {
    /// Build the regex from a string.
    ///
    /// # Errors
    ///
    /// Will return `err` if the regex is malformed.
    pub fn new<T: AsRef<str>>(
        expr: T,
        case_insensitive: bool,
        dot_all: bool,
    ) -> Result<Self, Error> {
        Self::new_inner(expr.as_ref(), case_insensitive, dot_all)
    }

    fn new_inner(expr: &str, case_insensitive: bool, dot_all: bool) -> Result<Self, Error> {
        RegexBuilder::new(expr)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .dot_matches_new_line(dot_all)
            .build()
            .map(Regex)
            .map_err(Error)
    }

    /// Return the regex as a [`regex::bytes::Regex`].
    #[must_use]
    pub fn as_regex(&self) -> &regex::bytes::Regex {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Error(regex::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
