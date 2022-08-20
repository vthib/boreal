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
        let expr = normalize_regex(expr);

        RegexBuilder::new(&expr)
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

/// Convert a yara regex into a rust one.
///
/// Here is a list of the differences to handle:
///
/// - While the regex might be a string, it gets matched as a byte string by Yara. This leads
///   to some confusing behavior, for example `/é+/` will match `\xC3\xA9` (é in unicode) but will
///   match `\xC3\xA9\xA9` and not match `\xC3\xA9\xC3\xA9`.
pub(crate) fn normalize_regex(expr: &str) -> String {
    use std::fmt::Write;

    let mut res = String::with_capacity(expr.len());

    // Decompose non ascii chars into their utf-8 encoding, as the yara regex
    // engine would consider them.
    for b in expr.as_bytes() {
        if b.is_ascii() {
            res.push(char::from(*b));
        } else {
            let _ = write!(res, r"\x{:2x}", b);
        }
    }

    res
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
