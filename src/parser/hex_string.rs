//! Parsing related to hex strings, eg { AB 0F [0-300] ... }
//!
//! This implements the `hex_lexer/hex_grammar` files from libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, digit1, multispace0 as sp0},
    combinator::{cut, map, opt},
    error::{ErrorKind as NomErrorKind, ParseError},
    multi::many1,
    sequence::{preceded, separated_pair, terminated},
};

use super::error::{Error, ErrorKind};
use super::nom_recipes::{map_res, rtrim};
use super::types::{Input, ParseResult};

/// A token in an hex string.
#[derive(Debug, PartialEq)]
pub enum HexToken {
    /// A fully declared byte, eg `9C`
    Byte(u8),
    /// A masked byte, eg `?5`, `C?`, `??`
    MaskedByte(u8, Mask),
    /// A jump of unknown bytes, eg `[5-10]`, `[3-]`, ...
    Jump(Jump),
    /// Two possible list of tokens, eg `( 12 34 | 98 76 )`
    Alternatives(Vec<HexToken>, Vec<HexToken>),
}
pub type HexString = Vec<HexToken>;

/// Mask on a byte.
#[derive(Debug, PartialEq)]
pub enum Mask {
    /// The left part is masked, ie ?X
    Left,
    /// The right part is masked, ie X?
    Right,
    /// Both parts are masked, ie ??
    All,
}

/// A jump range, which can be expressed in multiple ways:
///
/// - `[a-b]` means between `a` and `b`, inclusive.
/// - `[-b]` is equivalent to `[0-b]`.
/// - `[a-]` means `a` or more.
/// - `[-]` is equivalent to `[0-]`.
/// - `[a]` is equivalent to `[a-a]`.
#[derive(Debug, PartialEq)]
pub struct Jump {
    /// Beginning of the range, included.
    pub from: u32,
    /// Optional end of the range, included.
    pub to: Option<u32>,
}

// TODO: handle this limit in some way
const JUMP_LIMIT_IN_ALTERNATIVES: u32 = 200;

/// Parse an hex-digit, and return its value in [0-15].
fn hex_digit(mut input: Input) -> ParseResult<u8> {
    match input.cursor().chars().next().and_then(|c| {
        // Cannot truncate, so allow lint
        #[allow(clippy::cast_possible_truncation)]
        c.to_digit(16).map(|v| v as u8)
    }) {
        Some(v) => {
            input.advance(1);
            Ok((input, v))
        }
        _ => Err(nom::Err::Error(Error::from_error_kind(
            input,
            NomErrorKind::HexDigit,
        ))),
    }
}

/// Parse a hex byte.
///
/// Equivalent to the _BYTE_ lexical pattern in libyara.
fn byte(input: Input) -> ParseResult<u8> {
    let (input, digit0) = hex_digit(input)?;

    map(rtrim(hex_digit), move |digit1| (digit0 << 4) | digit1)(input)
}

/// Parse a masked hex byte, ie X?, ?X or ??.
///
/// Equivalent to the `_MASKED_BYTE_` lexical pattern in libyara.
fn masked_byte(input: Input) -> ParseResult<(u8, Mask)> {
    rtrim(alt((
        map(tag("??"), |_| (0, Mask::All)),
        map(preceded(char('?'), hex_digit), |v| (v, Mask::Left)),
        map(terminated(hex_digit, char('?')), |v| (v, Mask::Right)),
    )))(input)
}

/// Parse a jump range, which can be expressed in multiple ways:
///
/// - `[a-b]` means between `a` and `b`, inclusive.
/// - `[-b]` is equivalent to `[0-b]`.
/// - `[a-]` means `a` or more.
/// - `[-]` is equivalent to `[0-]`.
/// - `[a]` is equivalent to `[a-a]`.
///
/// This is equivalent to the range state in libyara.
fn range(input: Input) -> ParseResult<Jump> {
    let start = input;
    let (input, _) = rtrim(char('['))(input)?;

    let (input, jump) = cut(terminated(
        alt((
            // Parses [a?-b?]
            map(
                separated_pair(
                    opt(map_res(rtrim(digit1), |v| {
                        str::parse(v.cursor()).map_err(ErrorKind::StrToIntError)
                    })),
                    rtrim(char('-')),
                    opt(map_res(rtrim(digit1), |v| {
                        str::parse(v.cursor()).map_err(ErrorKind::StrToIntError)
                    })),
                ),
                |(from, to)| Jump {
                    from: from.unwrap_or(0),
                    to,
                },
            ),
            // Parses [a]
            map(
                map_res(rtrim(digit1), |v| {
                    str::parse(v.cursor()).map_err(ErrorKind::StrToIntError)
                }),
                |value| Jump {
                    from: value,
                    to: Some(value),
                },
            ),
        )),
        rtrim(char(']')),
    ))(input)?;

    if let Err(kind) = validate_jump(&jump) {
        return Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            kind,
        )));
    }
    Ok((input, jump))
}

/// Validate that a jump is well-formed.
fn validate_jump(range: &Jump) -> Result<(), ErrorKind> {
    if let Some(to) = range.to {
        if range.from == 0 && to == 0 {
            return Err(ErrorKind::JumpEmpty);
        }
        if range.from > to {
            return Err(ErrorKind::JumpRangeInvalid {
                from: range.from,
                to,
            });
        }
    }

    Ok(())
}

/// Parse an alternative between two sets of tokens.
///
/// This looks like `( AB .. | CD .. )`.
///
/// This is equivalent to the `alternatives` from `hex_grammar.y` in libyara.
fn alternatives(input: Input) -> ParseResult<HexToken> {
    let (input, _) = rtrim(char('('))(input)?;

    cut(terminated(
        map(
            separated_pair(
                many1(|input| hex_token(input, true)),
                terminated(char('|'), sp0),
                many1(|input| hex_token(input, true)),
            ),
            |(left, right)| HexToken::Alternatives(left, right),
        ),
        rtrim(char(')')),
    ))(input)
}

fn validate_jump_in_alternatives(jump: &Jump) -> Result<(), ErrorKind> {
    match jump.to {
        None => Err(ErrorKind::JumpUnboundedInAlternation),
        Some(to) => {
            // No need to test from, as from <= to, if from is over the limit, to will be.
            if to > JUMP_LIMIT_IN_ALTERNATIVES {
                Err(ErrorKind::JumpTooBigInAlternation {
                    limit: JUMP_LIMIT_IN_ALTERNATIVES,
                })
            } else {
                Ok(())
            }
        }
    }
}

/// Parse an hex token.
///
/// Some token are not allowed inside an alternatives, which is why a
/// `in_alternatives` flag is needed.
///
/// This is equivalent to the `tokens` rule in `hex_grammar.y` in libyara.
fn hex_token(input: Input, in_alternatives: bool) -> ParseResult<HexToken> {
    alt((
        map(masked_byte, |(v, mask)| HexToken::MaskedByte(v, mask)),
        // Always have at least one space after a byte or a masked byte
        map(byte, HexToken::Byte),
        map_res(range, |range| {
            // Some jumps are forbidden inside an alternatives
            if in_alternatives {
                validate_jump_in_alternatives(&range)?;
            }

            // Jump of one is equivalent to ??
            if let Some(to) = &range.to {
                if range.from == *to && range.from == 1 {
                    return Ok(HexToken::MaskedByte(0, Mask::All));
                }
            }
            Ok(HexToken::Jump(range))
        }),
        alternatives,
    ))(input)
}

/// Parse an hex string.
///
/// This looks like `{ AB .. }`.
///
/// This is equivalent to the `hex_string` rule in `hex_grammar.y` in libyara.
pub(crate) fn hex_string(input: Input) -> ParseResult<HexString> {
    let (input, _) = rtrim(char('{'))(input)?;

    cut(terminated(
        many1(|input| hex_token(input, false)),
        rtrim(char('}')),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::tests::{parse, parse_err};

    #[test]
    fn test_parse_hex_byte() {
        parse(byte, "AF", "", 0xAF);
        parse(byte, "10F", "F", 0x10);
        parse(byte, "9E 1", "1", 0x9E);

        parse_err(byte, "G1");
        parse_err(byte, "1G");
        parse_err(byte, "1");
        parse_err(byte, " ");
    }

    #[test]
    fn test_parse_masked_byte() {
        parse(masked_byte, "?1", "", (1, Mask::Left));
        parse(masked_byte, "C??", "?", (0xC, Mask::Right));
        parse(masked_byte, "?? ", "", (0, Mask::All));

        parse_err(masked_byte, "AB");
        parse_err(masked_byte, " ?");
        parse_err(masked_byte, "G?");
        parse_err(masked_byte, "?G");
    }

    #[test]
    fn test_range() {
        parse(range, "[-] a", "a", Jump { from: 0, to: None });
        parse(
            range,
            "[ 15 -35]",
            "",
            Jump {
                from: 15,
                to: Some(35),
            },
        );
        parse(range, "[1-  ]", "", Jump { from: 1, to: None });
        parse(
            range,
            "[1-2]]",
            "]",
            Jump {
                from: 1,
                to: Some(2),
            },
        );
        parse(
            range,
            "[  1  -  2  ]",
            "",
            Jump {
                from: 1,
                to: Some(2),
            },
        );
        parse(
            range,
            "[-1]",
            "",
            Jump {
                from: 0,
                to: Some(1),
            },
        );
        parse(
            range,
            "[12 ]",
            "",
            Jump {
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
            Jump {
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
            Jump {
                from: 1,
                to: Some(1),
            },
        );
    }

    #[test]
    fn test_alternatives() {
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
                    HexToken::Jump(Jump {
                        from: 1,
                        to: Some(3),
                    }),
                ],
                vec![HexToken::Jump(Jump {
                    from: 3,
                    to: Some(5),
                })],
            ),
        );
        parse(
            alternatives,
            "( ( [1-5] | 23)| 15) ",
            "",
            HexToken::Alternatives(
                vec![HexToken::Alternatives(
                    vec![HexToken::Jump(Jump {
                        from: 1,
                        to: Some(5),
                    })],
                    vec![HexToken::Byte(0x23)],
                )],
                vec![HexToken::Byte(0x15)],
            ),
        );

        parse_err(alternatives, "( AB | [-] )");
        parse_err(alternatives, "( AB | [1-] )");
        parse_err(alternatives, "( AB | [1-250] )");
        parse_err(alternatives, "( AB | [199-201] )");
        parse_err(alternatives, "( AB | [200-201] )");
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
            "{ 01 ?2 ?? 3? [1-] ( AF | DC ) }",
            "",
            vec![
                HexToken::Byte(1),
                HexToken::MaskedByte(2, Mask::Left),
                HexToken::MaskedByte(0, Mask::All),
                HexToken::MaskedByte(3, Mask::Right),
                HexToken::Jump(Jump { from: 1, to: None }),
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
