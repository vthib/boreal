//! Parsing related to strings, regexes and identifiers.
use std::borrow::ToOwned;
use std::ops::Range;

use nom::{
    bytes::complete::{is_not, take_while},
    character::complete::char,
    combinator::{cut, map, opt, recognize},
    error::{ErrorKind as NomErrorKind, ParseError},
    sequence::{pair, preceded, terminated, tuple},
};

use super::error::Error;
use super::nom_recipes::{rtrim, take_one};
use super::types::{Input, ParseResult};

/// A regular expression.
#[derive(Clone, Debug, PartialEq)]
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

/// Returns true if the char is an identifier digit, ie a-z, a-Z, 0-9, _
fn is_identifier_digit(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
}

/// Parse the contents of an identifier string.
///
/// This is always the rest of an identifier type, where the first
/// character determines which type of identifier is being parsed.
///
/// This function *does not* right-trim, as it can be followed
/// by a '*' character that is meaningful in some contexts.
fn identifier_contents(input: Input) -> ParseResult<String> {
    map(take_while(is_identifier_digit), |input: Input| {
        input.cursor().to_owned()
    })(input)
}

/// Helper for [`string_identifier`] and [`string_identifier_with_wildcard`].
fn string_identifier_no_rtrim(input: Input) -> ParseResult<String> {
    preceded(char('$'), cut(identifier_contents))(input)
}

/// Parse a string identifier.
///
/// This is equivalent to the `_STRING_IDENTIFIER_` lexical patterns in
/// libyara.
/// Roughly equivalent to `$[a-ZA-Z0-9_]*`.
pub fn string_identifier(input: Input) -> ParseResult<String> {
    rtrim(string_identifier_no_rtrim)(input)
}

/// Parse a string identifier with an optional trailing wildcard.
///
/// This is equivalent to
/// `_STRING_IDENTIFIER_ | _STRING_IDENTIFIER_WITH_WILDCARD_` in libyara.
pub fn string_identifier_with_wildcard(input: Input) -> ParseResult<(String, bool)> {
    rtrim(pair(
        string_identifier_no_rtrim,
        map(opt(char('*')), |v| v.is_some()),
    ))(input)
}

/// Parse a string count, roughly equivalent to `#[a-zA-Z0-9_]*`.
pub fn count(input: Input) -> ParseResult<String> {
    rtrim(preceded(char('#'), cut(identifier_contents)))(input)
}

/// Parse a string offset, roughly equivalent to `@[a-zA-Z0-9_]*`.
pub fn offset(input: Input) -> ParseResult<String> {
    rtrim(preceded(char('@'), cut(identifier_contents)))(input)
}

/// Parse a string length, roughly equivalent to `![a-zA-Z0-9_]*`.
pub fn length(input: Input) -> ParseResult<String> {
    rtrim(preceded(char('!'), cut(identifier_contents)))(input)
}

/// Parse an identifier.
///
/// This is roughly equivalent to `[a-ZA-Z_][a-zA-Z0-9_]*`.
pub fn identifier(input: Input) -> ParseResult<String> {
    rtrim(map(
        recognize(tuple((
            take_one(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '_')),
            cut(take_while(is_identifier_digit)),
        ))),
        |input| input.cursor().to_owned(),
    ))(input)
}

/// Parse a quoted string with escapable characters.
///
/// Equivalent to the `_TEXT_STRING_` lexical pattern in libyara.
/// This is roughly equivalent to the pattern `/"[^\n\"]*"/`, with control
/// patterns `\t`, `\r`, `\n`, `\"`, `\\`, and `\x[0-9a-fA-F]{2}`.
///
/// This parser allows non ascii bytes, hence returning a byte string.
pub fn quoted(input: Input) -> ParseResult<Vec<u8>> {
    rtrim(quoted_no_rtrim)(input)
}

fn quoted_no_rtrim(input: Input) -> ParseResult<Vec<u8>> {
    let (mut input, _) = char('"')(input)?;

    let mut index = 0;
    let mut res = Vec::new();

    let mut chars = input.cursor().chars().enumerate();

    while let Some((i, c)) = chars.next() {
        index = i;
        match c {
            '\\' => match chars.next() {
                Some((_, 't')) => res.push(b'\t'),
                Some((_, 'r')) => res.push(b'\r'),
                Some((_, 'n')) => res.push(b'\n'),
                Some((_, '"')) => res.push(b'"'),
                Some((_, '\\')) => res.push(b'\\'),
                Some((_, 'x')) => match (chars.next(), chars.next()) {
                    (Some((i1, a)), Some((i2, b))) => {
                        let a = match a.to_digit(16) {
                            Some(a) => a,
                            None => {
                                index = i1;
                                break;
                            }
                        };
                        let b = match b.to_digit(16) {
                            Some(b) => b,
                            None => {
                                index = i2;
                                break;
                            }
                        };
                        #[allow(clippy::cast_possible_truncation)]
                        res.push(((a as u8) << 4) + (b as u8));
                    }
                    _ => break,
                },
                Some((j, _)) => {
                    index = j;
                    break;
                }
                None => break,
            },
            '"' => {
                input.advance(i + 1);
                return Ok((input, res));
            }
            c => {
                let mut buf = [0; 4];
                let _r = c.encode_utf8(&mut buf);
                res.extend(&buf[..c.len_utf8()]);
            }
        }
    }

    input.advance(index);
    Err(nom::Err::Error(Error::from_error_kind(
        input,
        NomErrorKind::EscapedTransform,
    )))
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
    // TODO: test this more extensively, but with libyara compliance tests
    fn test_parse_quoted() {
        use super::quoted;

        parse(quoted, "\"\" b", "b", "");
        parse(quoted, "\"1\"b", "b", "1");
        parse(quoted, "\"abc +$\" b", "b", "abc +$");

        parse(
            quoted,
            r#"" \r \n \t \"\\a \\r""#,
            "",
            " \r \n \t \"\\a \\r",
        );
        parse(quoted, r#""\x10 \x32""#, "", "\u{10} 2");
        parse(quoted, r#""\x00 \xFF""#, "", [0, b' ', 255]);

        parse(quoted, r#""\xc3\x0f]\x00""#, "", [0xc3, 0x0f, b']', 0x00]);

        parse_err(quoted, "a");
        parse_err(quoted, r#"""#);
        parse_err(quoted, r#""ab"#);
        parse_err(quoted, r#""a\"#);
        parse_err(quoted, r#""a\xAG""#);
        parse_err(quoted, r#""a\xGA""#);
        parse_err(quoted, r#""\a""#);
    }

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

    #[test]
    fn test_string_identifier() {
        use super::string_identifier;

        parse(string_identifier, "$-", "-", "");
        parse(string_identifier, "$*", "*", "");
        parse(string_identifier, "$a c", "c", "a");
        parse(string_identifier, "$9b*c", "*c", "9b");
        parse(string_identifier, "$_1Bd_F+", "+", "_1Bd_F");

        parse_err(string_identifier, "");
        parse_err(string_identifier, "*");
    }

    #[test]
    fn test_string_identifier_with_wildcard() {
        use super::string_identifier_with_wildcard as siww;

        parse(siww, "$_*", "", ("_".to_owned(), true));
        parse(siww, "$", "", ("".to_owned(), false));
        parse(siww, "$a* c", "c", ("a".to_owned(), true));
        parse(siww, "$9b*c", "c", ("9b".to_owned(), true));
        parse(siww, "$_1Bd_F+", "+", ("_1Bd_F".to_owned(), false));

        parse_err(siww, "");
        parse_err(siww, "*");
    }

    #[test]
    fn test_count() {
        use super::count;

        parse(count, "#-", "-", "");
        parse(count, "#*", "*", "");
        parse(count, "#a c", "c", "a");
        parse(count, "#9b*c", "*c", "9b");
        parse(count, "#_1Bd_F+", "+", "_1Bd_F");

        parse_err(count, "");
        parse_err(count, "$");
        parse_err(count, "@");
        parse_err(count, "!");
        parse_err(count, "*");
    }

    #[test]
    fn test_offset() {
        use super::offset;

        parse(offset, "@-", "-", "");
        parse(offset, "@*", "*", "");
        parse(offset, "@a c", "c", "a");
        parse(offset, "@9b*c", "*c", "9b");
        parse(offset, "@_1Bd_F+", "+", "_1Bd_F");

        parse_err(offset, "");
        parse_err(offset, "$");
        parse_err(offset, "#");
        parse_err(offset, "!");
        parse_err(offset, "*");
    }

    #[test]
    fn test_length() {
        use super::length;

        parse(length, "!-", "-", "");
        parse(length, "!*", "*", "");
        parse(length, "!a c", "c", "a");
        parse(length, "!9b*c", "*c", "9b");
        parse(length, "!_1Bd_F+", "+", "_1Bd_F");

        parse_err(length, "");
        parse_err(length, "$");
        parse_err(length, "#");
        parse_err(length, "@");
        parse_err(length, "*");
    }

    #[test]
    fn test_identifier() {
        use super::identifier;

        parse(identifier, "a+", "+", "a");
        parse(identifier, "_*", "*", "_");
        parse(identifier, "A5 c", "c", "A5");
        parse(identifier, "g9b*c", "*c", "g9b");
        parse(identifier, "__1Bd_F+", "+", "__1Bd_F");

        parse_err(identifier, "");
        parse_err(identifier, "*");
        parse_err(identifier, "$");
        parse_err(identifier, "9");
        parse_err(identifier, "9b");
    }
}
