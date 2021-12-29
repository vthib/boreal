//! Parsing related to hex strings, eg { AB 0F [0-300] ... }
//!
//! This implements the hex_lexer files from libyara.
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{char, digit1, multispace0 as sp0},
    combinator::{cut, map, map_res, opt, value},
    error::{Error, ErrorKind, FromExternalError, ParseError},
    multi::many1,
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
    let (input, digit0) = hex_digit(input)?;

    map(cut(hex_digit), move |digit1| (digit0 << 4) | digit1)(input)
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
    let (input, range) = delimited(
        terminated(char('['), sp0),
        cut(alt((
            // Parses [a?-b?]
            map(
                separated_pair(
                    opt(map_res(terminated(digit1, sp0), |a: &str| a.parse())),
                    terminated(char('-'), sp0),
                    opt(map_res(terminated(digit1, sp0), |a: &str| a.parse())),
                ),
                |(from, to)| Range {
                    from: from.unwrap_or(0),
                    to,
                },
            ),
            // Parses [a]
            map(
                map_res(terminated(digit1, sp0), |a: &str| a.parse()),
                |value| Range {
                    from: value,
                    to: Some(value),
                },
            ),
        ))),
        terminated(char(']'), sp0),
    )(input)?;

    if let Err(desc) = validate_range(&range) {
        return Err(nom::Err::Failure(Error::from_external_error(
            input,
            ErrorKind::Verify,
            desc,
        )));
    }
    Ok((input, range))
}

/// Validate a range is well-formed.
fn validate_range(range: &Range) -> Result<(), String> {
    if let Some(to) = range.to {
        if range.from == 0 && to == 0 {
            return Err("invalid jump length".to_owned());
        }
        if range.from > to {
            return Err("invalid jump range".to_owned());
        }
    }

    Ok(())
}

/// A token in an hex string.
#[derive(Debug, PartialEq)]
enum HexToken {
    /// A fully declared byte, eg `9C`
    Byte(u8),
    /// A masked byte, eg `?5`, `C?`, `??`
    MaskedByte(u8, Mask),
    /// A range, eg `[5-10]`, `[3-]`, ...
    Range(Range),
    /// Two possible list of tokens, eg `( 12 34 | 98 76 )`
    Alternatives(Vec<HexToken>, Vec<HexToken>),
}

/// Parse an alternative between two sets of tokens.
///
/// This looks like `( AB .. | CD .. )`.
///
/// This is equivalent to the `alternatives` from hex_grammar.y in libyara.
fn alternatives(input: &str) -> IResult<&str, HexToken> {
    delimited(
        terminated(char('('), sp0),
        map(
            cut(separated_pair(
                many1(hex_token),
                terminated(char('|'), sp0),
                many1(hex_token),
            )),
            |(left, right)| HexToken::Alternatives(left, right),
        ),
        terminated(char(')'), sp0),
    )(input)
}

/// Parse an hex token.
///
/// This is equivalent to the `tokens` rule in hex_grammar.y in libyara.
fn hex_token(input: &str) -> IResult<&str, HexToken> {
    alt((
        // Always have at least one space after a byte or a masked byte
        map(terminated(byte, sp0), HexToken::Byte),
        map(terminated(masked_byte, sp0), |(v, mask)| {
            HexToken::MaskedByte(v, mask)
        }),
        map(range, |range| {
            // Jump of one is equivalent to ??
            if let Some(to) = &range.to {
                if range.from == *to && range.from == 1 {
                    return HexToken::MaskedByte(0, Mask::All);
                }
            }
            HexToken::Range(range)
        }),
        alternatives,
    ))(input)
}

/// Parse an hex string.
///
/// This looks like `{ AB .. }`.
///
/// This is equivalent to the `hex_string` rule in hex_grammar.y in libyara.
fn hex_string(input: &str) -> IResult<&str, Vec<HexToken>> {
    delimited(
        terminated(char('{'), sp0),
        cut(many1(hex_token)),
        terminated(char('}'), sp0),
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
    fn test_singleline_comment() {
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

        parse(range, "[-] a", "a", Range { from: 0, to: None });
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

        // validation errors
        parse_err(range, "[4-2]");
        parse_err(range, "[4-3]");
        parse(
            range,
            "[4-4]",
            "",
            Range {
                from: 4,
                to: Some(4),
            },
        );
        parse_err(range, "[0]");
        parse_err(range, "[0-0]");
        parse(
            range,
            "[1]",
            "",
            Range {
                from: 1,
                to: Some(1),
            },
        );
    }

    #[test]
    fn test_alternatives() {
        use super::{alternatives, HexToken, Mask, Range};

        parse(
            alternatives,
            "( AB | 56 ?F ) ",
            "",
            HexToken::Alternatives(
                vec![HexToken::Byte(0xAB)],
                vec![HexToken::Byte(0x56), HexToken::MaskedByte(0x0F, Mask::Left)],
            ),
        );
        parse(
            alternatives,
            "(12[1-3]|[3-5])",
            "",
            HexToken::Alternatives(
                vec![
                    HexToken::Byte(0x12),
                    HexToken::Range(Range {
                        from: 1,
                        to: Some(3),
                    }),
                ],
                vec![HexToken::Range(Range {
                    from: 3,
                    to: Some(5),
                })],
            ),
        );
        parse(
            alternatives,
            "( ( 12 | 23)| 15) ",
            "",
            HexToken::Alternatives(
                vec![HexToken::Alternatives(
                    vec![HexToken::Byte(0x12)],
                    vec![HexToken::Byte(0x23)],
                )],
                vec![HexToken::Byte(0x15)],
            ),
        );

        parse_err(alternatives, ")");
        parse_err(alternatives, "()");
        parse_err(alternatives, "(");
        parse_err(alternatives, "(|)");
        parse_err(alternatives, "(|");
        parse_err(alternatives, "(AB|)");
        parse_err(alternatives, "(|12)");
        parse_err(alternatives, "(|123)");
    }

    #[test]
    fn test_hex_string() {
        use super::{hex_string, HexToken, Mask, Range};

        parse(hex_string, "{ AB }", "", vec![HexToken::Byte(0xAB)]);

        parse(
            hex_string,
            "{ DE AD BE EF }",
            "",
            vec![
                HexToken::Byte(0xDE),
                HexToken::Byte(0xAD),
                HexToken::Byte(0xBE),
                HexToken::Byte(0xEF),
            ],
        );
        parse(
            hex_string,
            "{ 01 ?2 ?? [1-] ( AF | DC ) }",
            "",
            vec![
                HexToken::Byte(1),
                HexToken::MaskedByte(2, Mask::Left),
                HexToken::MaskedByte(0, Mask::All),
                HexToken::Range(Range { from: 1, to: None }),
                HexToken::Alternatives(vec![HexToken::Byte(0xAF)], vec![HexToken::Byte(0xDC)]),
            ],
        );

        parse_err(hex_string, "AB");
        parse_err(hex_string, "{");
        parse_err(hex_string, "{}");
        parse_err(hex_string, "{A}");
        parse_err(hex_string, "{ABA}");
        parse_err(hex_string, "{AB");
    }
}
