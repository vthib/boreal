use std::fmt::Write;

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
/// - Yara regexes allow any backslash: if the character is not special, it will act as if the
///   backslash was not present.
pub(crate) fn normalize_regex(expr: &str) -> String {
    let expr = decompose_unicode_bytes(expr);
    // Order is important here. Yara handles those escapes during lexing, and thus before
    // interpreting the string. This is the different between `{\,2}` being valid or not.
    let expr = remove_unneeded_escapes(&expr);
    fix_at_most_repetitions(&expr)
}

/// Find uses of the `{,N}` syntax, and replace with `{0,N}`
fn fix_at_most_repetitions(expr: &str) -> String {
    let mut res = String::with_capacity(expr.len());
    let mut prev_is_escape = false;
    let mut starting_repetition = false;

    for c in expr.chars() {
        if c == ',' && starting_repetition {
            res.push('0');
        }

        res.push(c);
        starting_repetition = c == '{' && !starting_repetition && !prev_is_escape;
        prev_is_escape = c == '\\' && !prev_is_escape;
    }

    res
}

fn remove_unneeded_escapes(expr: &str) -> String {
    let mut res = String::with_capacity(expr.len());
    let mut prev_is_escape = false;

    for b in expr.as_bytes() {
        match (prev_is_escape, *b) {
            (false, b'\\') => prev_is_escape = true,
            (false, b) => res.push(char::from(b)),
            (true, b'\\') => {
                res.push_str(r"\\");
                prev_is_escape = false;
            }
            (true, c) => {
                // unicode values have already been decomposed. It is thus safe to iterate on
                // bytes, and cast as chars.
                let c = char::from(c);

                // If the byte is escapable, keep the escape and the byte.
                // Otherwise, this means the escape char is useless
                if byte_is_escapable(c) {
                    res.push('\\');
                }
                res.push(c);
                prev_is_escape = false;
            }
        }
    }
    if prev_is_escape {
        res.push('\\');
    }

    res
}

fn byte_is_escapable(c: char) -> bool {
    // These are the escapable bytes for a YARA regex. These are not all the accepted escapable
    // bytes for a rust regex, meaning those are not available in yara rules.
    match c {
        // TODO: Technically, 'b' and 'B' are not accepted in a char range. So this code is invalid
        // for this, and writing [\b] in a yara rule will not work...
        'x' | 'n' | 't' | 'r' | 'f' | 'a' => true,
        'w' | 'W' | 's' | 'S' | 'd' | 'D' | 'b' | 'B' => true,
        c if regex_syntax::is_meta_character(c) => true,
        _ => false,
    }
}

fn decompose_unicode_bytes(expr: &str) -> String {
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
