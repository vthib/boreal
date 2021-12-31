//! Parsing related to strings.
//!
//! This implements the _TEXT_STRING_ and _REGEX_ lexical patterns from
//! libyara.
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, is_not, take_while},
    character::complete::{char, one_of},
    combinator::{cut, map, opt, recognize, value},
    error::{Error, ErrorKind, FromExternalError, ParseError},
    multi::fold_many_m_n,
    sequence::{preceded, terminated, tuple},
    IResult,
};

/// Returns true if the char is an identifier digit, ie a-z, a-Z, 0-9, _
fn is_identifier_digit(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
}

/// Parse the contents of an identifier string.
///
/// This is always the rest of an identifier type, where the first
/// character determines which type of identifier is being parsed.
fn identifier_contents(input: &str) -> IResult<&str, String> {
    map(take_while(is_identifier_digit), |s: &str| s.to_owned())(input)
}

/// Parse a string identifier
///
/// Returns the identifier name, and a boolean indicating whether
/// the end of the identifier has a wildcard.
///
/// This is equivalent to the _STRING_IDENTIFIER(_WITH_WILDCARD)_
/// lexical patterns in libyara.
/// Roughly equivalent to `$[a-ZA-Z0-9_]*\*?`.
fn string_identifier(input: &str) -> IResult<&str, (String, bool)> {
    preceded(
        char('$'),
        cut(tuple((
            identifier_contents,
            map(opt(char('*')), |v| v.is_some()),
        ))),
    )(input)
}

/// Parse a string count, roughly equivalent to `#[a-zA-Z0-9_]*`.
fn string_count(input: &str) -> IResult<&str, String> {
    preceded(char('#'), cut(identifier_contents))(input)
}

/// Parse a string offset, roughly equivalent to `@[a-zA-Z0-9_]*`.
fn string_offset(input: &str) -> IResult<&str, String> {
    preceded(char('@'), cut(identifier_contents))(input)
}

/// Parse a string length, roughly equivalent to `![a-zA-Z0-9_]*`.
fn string_length(input: &str) -> IResult<&str, String> {
    preceded(char('!'), cut(identifier_contents))(input)
}

/// Accepts a single character if the passed function returns true on it.
fn take_one<F>(f: F) -> impl Fn(&str) -> IResult<&str, char>
where
    F: Fn(char) -> bool,
{
    move |input| match input.chars().next().map(|c| (c, f(c))) {
        Some((c, true)) => Ok((&input[c.len_utf8()..], c)),
        _ => Err(nom::Err::Error(Error::from_char(input, '0'))),
    }
}

/// Parse an identifier.
///
/// Returns the identifier name, and a boolean indicating whether
/// the end of the identifier has a wildcard.
///
/// This is roughly equivalent to `[a-ZA-Z_][a-zA-Z0-9_]*`.
fn identifier(input: &str) -> IResult<&str, (String, bool)> {
    tuple((
        map(
            recognize(tuple((
                take_one(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '_')),
                cut(take_while(is_identifier_digit)),
            ))),
            |s| s.to_owned(),
        ),
        map(opt(char('*')), |v| v.is_some()),
    ))(input)
}

/// Parse a quoted string with escapable characters.
///
/// Equivalent to the _TEXT_STRING_ lexical pattern in libyara.
/// This is roughly equivalent to the pattern `/"[^\n\"]*"/`, with control
/// patterns `\t`, `\r`, `\n`, `\"`, `\\`, and `\x[0-9a-fA-F]{2}`.
pub fn quoted_string(input: &str) -> IResult<&str, String> {
    let (input, _) = char('"')(input)?;

    // escaped transform does not handle having no content, so
    // handle empty string explicitly.
    // TODO: ticket for nom?
    if let Ok((next_input, '"')) = char::<&str, nom::error::Error<&str>>('"')(input) {
        return Ok((next_input, "".to_owned()));
    }

    cut(terminated(
        escaped_transform(
            is_not("\\\n\""),
            '\\',
            alt((
                value('\t', char('t')),
                value('\r', char('r')),
                value('\n', char('n')),
                value('\"', char('\"')),
                value('\\', char('\\')),
                preceded(
                    char('x'),
                    cut(map(
                        fold_many_m_n(
                            2,
                            2,
                            one_of("0123456789abcdefABCDEF"),
                            || 0,
                            |acc, v| (acc << 4) + (v.to_digit(16).unwrap_or(0) as u8),
                        ),
                        |v| v as char,
                    )),
                ),
            )),
        ),
        char('"'),
    ))(input)
}

/// A regular expression.
#[derive(Debug, PartialEq)]
pub struct Regex {
    /// The regular expression parsed inside the `/` delimiters.
    expr: String,
    /// case insensitive (`i` flag).
    case_insensitive: bool,
    /// `.` matches `\n` (`s` flag).
    dot_all: bool,
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
/// as a C string). See https://github.com/VirusTotal/yara/issues/576.
pub fn regex(input: &str) -> IResult<&str, Regex> {
    let (input, _) = char('/')(input)?;

    // We cannot use escaped_transform, as it is not an error to use
    // the control character with any char other than `/`.
    let (input, expr) = cut(terminated(regex_contents, char('/')))(input)?;
    if expr.is_empty() {
        return Err(nom::Err::Error(Error::from_external_error(
            input,
            ErrorKind::Verify,
            "regex expression cannot be empty",
        )));
    }

    let (input, no_case) = opt(char('i'))(input)?;
    let (input, dot_all) = opt(char('s'))(input)?;

    Ok((
        input,
        Regex {
            expr,
            case_insensitive: no_case.is_some(),
            dot_all: dot_all.is_some(),
        },
    ))
}

/// Parsed the contents between the '/' chars delimiting a regex.
/// See [`regex`] for details.
fn regex_contents(mut input: &str) -> IResult<&str, String> {
    // This is mostly inspired by the impl of
    // [`nom::bytes::complete::escaped_transform`].

    let mut res = String::new();
    let normal = is_not("/\\\n");

    while !input.is_empty() {
        match normal(input) {
            Ok((new_input, o)) => {
                res.push_str(o);
                if new_input.is_empty() {
                    return Ok((new_input, res));
                } else if new_input.len() == input.len() {
                    return Ok((input, res));
                } else {
                    input = new_input;
                }
            }
            Err(nom::Err::Error(_)) => {
                // access [0] is safe since input.len() > 0.
                if input.as_bytes()[0] == b'\\' {
                    if input.len() <= 1 {
                        return Err(nom::Err::Error(Error::from_error_kind(
                            &input[1..],
                            ErrorKind::EscapedTransform,
                        )));
                    }
                    match input.as_bytes()[1] {
                        b'/' => {
                            res.push('/');
                        }
                        c => {
                            res.push('\\');
                            res.push(c as char);
                        }
                    }
                    input = &input[2..];
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
    use super::super::test_utils::{parse, parse_err};

    #[test]
    fn test_parse_quoted_string() {
        use super::quoted_string;

        parse(quoted_string, "\"\"", "", "".to_owned());
        parse(quoted_string, "\"1\"b", "b", "1".to_owned());
        parse(quoted_string, "\"abc +$\"", "", "abc +$".to_owned());

        parse(
            quoted_string,
            r#"" \r \n \t \"\\a \\r""#,
            "",
            " \r \n \t \"\\a \\r".to_owned(),
        );
        parse(quoted_string, r#""\x10 \x32""#, "", "\u{10} 2".to_owned());
        parse(
            quoted_string,
            r#""\x00 \xFF""#,
            "",
            "\u{00} \u{FF}".to_owned(),
        );

        parse_err(quoted_string, "a");
        parse_err(quoted_string, "\"");
        parse_err(quoted_string, "\"\n\"");
        parse_err(quoted_string, "\"\n\"");
        parse_err(quoted_string, r#""\a""#);
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
            },
        );
        parse(
            regex,
            r#"/.{2}/si"#,
            "i",
            Regex {
                expr: ".{2}".to_owned(),
                case_insensitive: false,
                dot_all: true,
            },
        );
        parse(
            regex,
            "/\0\\\0/",
            "",
            Regex {
                expr: "\0\\\0".to_owned(),
                case_insensitive: false,
                dot_all: false,
            },
        );

        parse_err(regex, "");
        parse_err(regex, "/");
        parse_err(regex, "//");
        parse_err(regex, "/\n/");
        parse_err(regex, "/a{2}");
    }

    #[test]
    fn test_string_identifier() {
        use super::string_identifier;

        parse(string_identifier, "$-", "-", ("".to_owned(), false));
        parse(string_identifier, "$*", "", ("".to_owned(), true));
        parse(string_identifier, "$a", "", ("a".to_owned(), false));
        parse(string_identifier, "$9b*c", "c", ("9b".to_owned(), true));
        parse(
            string_identifier,
            "$_1Bd_F+",
            "+",
            ("_1Bd_F".to_owned(), false),
        );

        parse_err(string_identifier, "");
        parse_err(string_identifier, "*");
    }

    #[test]
    fn test_string_count() {
        use super::string_count;

        parse(string_count, "#-", "-", "".to_owned());
        parse(string_count, "#*", "*", "".to_owned());
        parse(string_count, "#a", "", "a".to_owned());
        parse(string_count, "#9b*c", "*c", "9b".to_owned());
        parse(string_count, "#_1Bd_F+", "+", "_1Bd_F".to_owned());

        parse_err(string_count, "");
        parse_err(string_count, "$");
        parse_err(string_count, "@");
        parse_err(string_count, "!");
        parse_err(string_count, "*");
    }

    #[test]
    fn test_string_offset() {
        use super::string_offset;

        parse(string_offset, "@-", "-", "".to_owned());
        parse(string_offset, "@*", "*", "".to_owned());
        parse(string_offset, "@a", "", "a".to_owned());
        parse(string_offset, "@9b*c", "*c", "9b".to_owned());
        parse(string_offset, "@_1Bd_F+", "+", "_1Bd_F".to_owned());

        parse_err(string_offset, "");
        parse_err(string_offset, "$");
        parse_err(string_offset, "#");
        parse_err(string_offset, "!");
        parse_err(string_offset, "*");
    }

    #[test]
    fn test_string_length() {
        use super::string_length;

        parse(string_length, "!-", "-", "".to_owned());
        parse(string_length, "!*", "*", "".to_owned());
        parse(string_length, "!a", "", "a".to_owned());
        parse(string_length, "!9b*c", "*c", "9b".to_owned());
        parse(string_length, "!_1Bd_F+", "+", "_1Bd_F".to_owned());

        parse_err(string_length, "");
        parse_err(string_length, "$");
        parse_err(string_length, "#");
        parse_err(string_length, "@");
        parse_err(string_length, "*");
    }

    #[test]
    fn test_identifier() {
        use super::identifier;

        parse(identifier, "a+", "+", ("a".to_owned(), false));
        parse(identifier, "_*", "", ("_".to_owned(), true));
        parse(identifier, "A5", "", ("A5".to_owned(), false));
        parse(identifier, "g9b*c", "c", ("g9b".to_owned(), true));
        parse(identifier, "__1Bd_F+", "+", ("__1Bd_F".to_owned(), false));

        parse_err(identifier, "");
        parse_err(identifier, "*");
        parse_err(identifier, "$");
        parse_err(identifier, "9");
        parse_err(identifier, "9b");
    }
}
