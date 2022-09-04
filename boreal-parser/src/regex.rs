//! Parsing related to strings, regexes and identifiers.
use std::ops::Range;

use nom::{
    bytes::complete::is_not,
    character::complete::char,
    combinator::{cut, opt},
    error::{ErrorKind as NomErrorKind, ParseError},
    sequence::{terminated, tuple},
};

use super::error::Error;
use super::nom_recipes::rtrim;
use super::types::{Input, ParseResult};

/// A regular expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Regex {
    /// The regular expression parsed inside the `/` delimiters.
    pub expr: String,
    /// case insensitive (`i` flag).
    pub case_insensitive: bool,
    /// `.` matches `\n` (`s` flag).
    pub dot_all: bool,

    /// The span of the regex expression
    pub span: Range<usize>,
}

/// Parse a regular expression.
///
/// Equivalent to the _REGEX_ lexical pattern in libyara.
/// This is roughly equivalent to the pattern `/\/"[^/\n]+\//i?s?`, with:
/// - `\/` replaced by `/`.
/// - `\<anything>` unmodified.
///
/// XXX: There is change of behavior from libyara. `\<nul_byte>` was forbidden,
/// but we do not have an issue about this (we do not save the regular expression
/// as a C string). See [Issue #576 in Yara](https://github.com/VirusTotal/yara/issues/576).
pub fn regex(input: Input) -> ParseResult<Regex> {
    let start = input;
    let (input, _) = char('/')(input)?;

    // We cannot use escaped_transform, as it is not an error to use
    // the control character with any char other than `/`.
    let (input, expr) = cut(terminated(regex_contents, char('/')))(input)?;
    let (input, (no_case, dot_all)) = rtrim(tuple((opt(char('i')), opt(char('s')))))(input)?;

    Ok((
        input,
        Regex {
            expr,
            case_insensitive: no_case.is_some(),
            dot_all: dot_all.is_some(),
            span: input.get_span_from(start),
        },
    ))
}

/// Parsed the contents between the '/' chars delimiting a regex.
/// See [`regex`] for details.
fn regex_contents(mut input: Input) -> ParseResult<String> {
    // This is mostly inspired by the impl of
    // [`nom::bytes::complete::escaped_transform`].

    let mut res = String::new();
    let normal = is_not("/\\\n");

    while !input.cursor().is_empty() {
        match normal(input) {
            Ok((new_input, o)) => {
                res.push_str(o.cursor());
                if new_input.cursor().is_empty() {
                    return Ok((new_input, res));
                } else if new_input.cursor().len() == input.cursor().len() {
                    return Ok((input, res));
                }
                input = new_input;
            }
            Err(nom::Err::Error(_)) => {
                // access [0] is safe since input.len() > 0.
                if input.cursor().as_bytes()[0] == b'\\' {
                    if input.cursor().len() <= 1 {
                        input.advance(1);
                        return Err(nom::Err::Error(Error::from_error_kind(
                            input,
                            NomErrorKind::EscapedTransform,
                        )));
                    }
                    match input.cursor().as_bytes()[1] {
                        b'/' => {
                            res.push('/');
                        }
                        c => {
                            res.push('\\');
                            res.push(c as char);
                        }
                    }
                    input.advance(2);
                } else {
                    return Ok((input, res));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok((input, res))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{parse, parse_err};

    #[test]
    fn test_parse_regex() {
        use super::{regex, Regex};

        parse(
            regex,
            "/a/i",
            "",
            Regex {
                expr: "a".to_owned(),
                case_insensitive: true,
                dot_all: false,
                span: 0..4,
            },
        );
        parse(
            regex,
            "/[^0-9]+/a",
            "a",
            Regex {
                expr: "[^0-9]+".to_owned(),
                case_insensitive: false,
                dot_all: false,
                span: 0..9,
            },
        );
        parse(
            regex,
            r#"/a\/b\cd/isb"#,
            "b",
            Regex {
                expr: "a/b\\cd".to_owned(),
                case_insensitive: true,
                dot_all: true,
                span: 0..11,
            },
        );
        parse(
            regex,
            r#"/.{2}/si c"#,
            "i c",
            Regex {
                expr: ".{2}".to_owned(),
                case_insensitive: false,
                dot_all: true,
                span: 0..7,
            },
        );
        parse(
            regex,
            "/\0\\\0/ c",
            "c",
            Regex {
                expr: "\0\\\0".to_owned(),
                case_insensitive: false,
                dot_all: false,
                span: 0..5,
            },
        );

        parse_err(regex, "");
        parse_err(regex, "/");
        parse_err(regex, "/\n/");
        parse_err(regex, "/a{2}");
    }
}
