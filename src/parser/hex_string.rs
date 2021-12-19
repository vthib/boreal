//! Parsing related to hex strings, eg { AB 0F [0-300] ... }
//!
//! This implements the hex_lexer files from libyara.
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{char, digit1, multispace0 as sp0},
    combinator::{cut, map, map_res, opt, value},
    error::{Error, ErrorKind, ParseError},
    multi::fold_many_m_n,
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};

// Parse an hex-digit, and return its value in [0-15].
fn hex_digit(input: &str) -> IResult<&str, u8> {
    match input
        .chars()
        .next()
        .and_then(|c| c.to_digit(16).map(|v| v as u8))
    {
        Some(v) => Ok((&input[1..], v)),
        _ => Err(nom::Err::Error(Error::from_error_kind(
            input,
            ErrorKind::HexDigit,
        ))),
    }
}

/// Parse a hex byte.
///
/// Equivalent to the _BYTE_ lexical pattern in libyara.
fn byte(input: &str) -> IResult<&str, u8> {
    fold_many_m_n(2, 2, hex_digit, || 0, |acc, v| (acc << 4) | v)(input)
}

/// Mask on a byte.
#[derive(Debug, PartialEq)]
enum Mask {
    /// The left part is masked, ie ?X
    Left,
    /// The right part is masked, ie X?
    Right,
    /// Both parts are masked, ie ??
    All,
}

/// Parse a masked hex byte, ie X?, ?X or ??.
///
/// Equivalent to the _MASKED_BYTE_ lexical pattern in libyara.
fn masked_byte(input: &str) -> IResult<&str, (u8, Mask)> {
    alt((
        map(tag("??"), |_| (0, Mask::All)),
        map(preceded(char('?'), hex_digit), |v| (v, Mask::Left)),
        map(terminated(hex_digit, char('?')), |v| (v, Mask::Right)),
    ))(input)
}

/// Parse a C-style /* ... */ comment.
///
/// Equivalent to the `comment` state in libyara.
fn multiline_comment(input: &str) -> IResult<&str, ()> {
    value((), tuple((tag("/*"), take_until("*/"), tag("*/"))))(input)
}

/// Parse single line // ... comments.
fn singleline_comment(input: &str) -> IResult<&str, ()> {
    value((), tuple((tag("//"), take_until("\n"), char('\n'))))(input)
}

/// A jump range, which can be expressed in multiple ways:
///
/// - `[a-b]` means between `a` and `b`, inclusive.
/// - `[-b]` is equivalent to `[0-b]`.
/// - `[a-]` means `a` or more.
/// - `[-]` is equivalent to `[0-]`.
/// - `[a]` is equivalent to `[a-a]`.
#[derive(Debug, PartialEq)]
struct Range {
    /// Beginning of the range, included.
    from: u32,
    /// Optional end of the range, included.
    to: Option<u32>,
}

/// Parse a range.
///
/// This is equivalent to the range state in libyara.
fn range(input: &str) -> IResult<&str, Range> {
    delimited(
        char('['),
        cut(alt((
            // Parses [a?-b?]
            map(
                separated_pair(
                    preceded(sp0, opt(map_res(digit1, |a: &str| a.parse()))),
                    preceded(sp0, char('-')),
                    preceded(sp0, opt(map_res(digit1, |a: &str| a.parse()))),
                ),
                |(from, to)| Range {
                    from: from.unwrap_or(0),
                    to,
                },
            ),
            // Parses [a]
            map(
                preceded(sp0, map_res(digit1, |a: &str| a.parse())),
                |value| Range {
                    from: value,
                    to: Some(value),
                },
            ),
        ))),
        preceded(sp0, char(']')),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::{parse, parse_err};

    #[test]
    fn test_parse_hex_byte() {
        use super::byte;

        parse(byte, "AF", "", 0xAF);
        parse(byte, "10F", "F", 0x10);
        parse(byte, "9E 1", " 1", 0x9E);

        parse_err(byte, "G1");
        parse_err(byte, "1G");
        parse_err(byte, "1");
        parse_err(byte, " ");
    }

    #[test]
    fn test_parse_masked_byte() {
        use super::{masked_byte, Mask};

        parse(masked_byte, "?1", "", (1, Mask::Left));
        parse(masked_byte, "C??", "?", (0xC, Mask::Right));
        parse(masked_byte, "?? ", " ", (0, Mask::All));

        parse_err(masked_byte, "AB");
        parse_err(masked_byte, " ?");
        parse_err(masked_byte, "G?");
        parse_err(masked_byte, "?G");
    }

    #[test]
    fn test_multiline_comment() {
        use super::multiline_comment;

        parse(multiline_comment, "/**/a", "a", ());
        parse(multiline_comment, "/* a\n */\n", "\n", ());
        parse(multiline_comment, "/*** a\n\n**//* a */c", "/* a */c", ());
        parse(multiline_comment, "/*** a\n//*/\n*/", "\n*/", ());

        parse_err(multiline_comment, "/");
        parse_err(multiline_comment, "/*");
        parse_err(multiline_comment, "/*/");
        parse_err(multiline_comment, "/*\n/*");
        parse_err(multiline_comment, "/ * */");
        parse_err(multiline_comment, "/* * /");
    }

    #[test]
    fn test_singleine_comment() {
        use super::singleline_comment;

        parse(singleline_comment, "//\n", "", ());
        parse(singleline_comment, "// comment\n// 2", "// 2", ());

        parse_err(singleline_comment, "/");
        parse_err(singleline_comment, "//");
        parse_err(singleline_comment, "// comment");
        parse_err(singleline_comment, "// comment //");
    }

    #[test]
    fn test_range() {
        use super::{range, Range};

        parse(range, "[-] a", " a", Range { from: 0, to: None });
        parse(
            range,
            "[ 15 -35]",
            "",
            Range {
                from: 15,
                to: Some(35),
            },
        );
        parse(range, "[1-  ]", "", Range { from: 1, to: None });
        parse(
            range,
            "[1-2]]",
            "]",
            Range {
                from: 1,
                to: Some(2),
            },
        );
        parse(
            range,
            "[  1  -  2  ]",
            "",
            Range {
                from: 1,
                to: Some(2),
            },
        );
        parse(
            range,
            "[-1]",
            "",
            Range {
                from: 0,
                to: Some(1),
            },
        );
        parse(
            range,
            "[12 ]",
            "",
            Range {
                from: 12,
                to: Some(12),
            },
        );

        parse_err(range, "[");
        parse_err(range, "[]");
        parse_err(range, "[--]");
        parse_err(range, "[1-2-3]");
        parse_err(range, "[1-2-]");
        parse_err(range, "[-2-]");
        parse_err(range, "[d-e]");
        parse_err(range, "[999999999999-]");
        parse_err(range, "[-999999999999]");
    }
}
