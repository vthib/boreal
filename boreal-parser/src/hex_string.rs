//! AST objects related to hex strings.
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::{char, digit1};
use nom::combinator::{cut, map, opt, value};
use nom::error::{ErrorKind as NomErrorKind, ParseError};
use nom::multi::{many1, separated_list1};
use nom::sequence::{delimited, preceded, terminated};
use nom::Parser;

use super::error::{Error, ErrorKind};
use super::nom_recipes::{map_res, rtrim};
use super::types::{Input, ParseResult};

const JUMP_LIMIT_IN_ALTERNATIVES: u32 = 200;
const MAX_HEX_TOKEN_RECURSION: usize = 10;

/// A token in an hex string.
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    /// A fully declared byte, eg `9C`
    Byte(u8),
    /// Negation of a byte, eg `~9C`
    NotByte(u8),
    /// A masked byte, eg `?5`, `C?`, `??`
    MaskedByte(u8, Mask),
    /// Negation of a masked byte, eg `~?C`. The mask cannot be [`Mask::All`].
    NotMaskedByte(u8, Mask),
    /// A jump of unknown bytes, eg `[5-10]`, `[3-]`, ...
    Jump(Jump),
    /// Two possible list of tokens, eg `( 12 34 | 98 76 )`
    Alternatives(Vec<Vec<Token>>),
}

/// Mask on a byte.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jump {
    /// Beginning of the range, included.
    pub from: u32,
    /// Optional end of the range, included.
    pub to: Option<u32>,
}

/// Parse a hex string.
///
/// The input is expected to look like `{ AB .. }`.
///
/// # Errors
///
/// Returns an error if the parsing fails.
pub fn parse_hex_string(input: &str) -> Result<Vec<Token>, Error> {
    use nom::Finish;

    let input = Input::new(input);
    let (_, tokens) = hex_string(input).finish()?;

    Ok(tokens)
}

/// Parse an hex string.
///
/// This looks like `{ AB .. }`.
///
/// This is equivalent to the `hex_string` rule in `hex_grammar.y` in libyara.
pub(crate) fn hex_string(input: Input) -> ParseResult<Vec<Token>> {
    let (input, _) = rtrim(char('{')).parse(input)?;

    cut(terminated(|input| tokens(input, false), rtrim(char('}')))).parse(input)
}

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

    map(rtrim(hex_digit), move |digit1| (digit0 << 4) | digit1).parse(input)
}

/// Parse the not tokens.
fn not_token(input: Input) -> ParseResult<Token> {
    let start = input.pos();

    let (input, _) = char('~').parse(input)?;
    let (input, token) = cut(alt((
        map(byte, Token::NotByte),
        map(masked_byte, |(b, mask)| Token::NotMaskedByte(b, mask)),
    )))
    .parse(input)?;

    if let Token::NotMaskedByte(_, Mask::All) = &token {
        return Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            ErrorKind::CannotNegateMaskAll,
        )));
    }

    Ok((input, token))
}

/// Parse a masked hex byte, ie X?, ?X or ??.
///
/// Equivalent to the `_MASKED_BYTE_` lexical pattern in libyara.
fn masked_byte(input: Input) -> ParseResult<(u8, Mask)> {
    rtrim(alt((
        map(tag("??"), |_| (0, Mask::All)),
        map(preceded(char('?'), hex_digit), |v| (v, Mask::Left)),
        map(terminated(hex_digit, char('?')), |v| (v, Mask::Right)),
    )))
    .parse(input)
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
    let start = input.pos();
    let (input, _) = rtrim(char('[')).parse(input)?;

    // Parse 'a'
    let (input, from) = opt(map_res(rtrim(digit1), |v| {
        str::parse::<u32>(v.cursor()).map_err(ErrorKind::StrToIntError)
    }))
    .parse(input)?;

    let (input, to) = match from {
        Some(from) => {
            alt((
                // Parses -b?]
                delimited(
                    rtrim(char('-')),
                    opt(map_res(rtrim(digit1), |v| {
                        str::parse(v.cursor()).map_err(ErrorKind::StrToIntError)
                    })),
                    rtrim(char(']')),
                ),
                // Otherwise, this means '[a]'
                value(Some(from), rtrim(char(']'))),
            ))
            .parse(input)?
        }
        None => delimited(
            rtrim(char('-')),
            opt(map_res(rtrim(digit1), |v| {
                str::parse(v.cursor()).map_err(ErrorKind::StrToIntError)
            })),
            rtrim(char(']')),
        )
        .parse(input)?,
    };

    let jump = Jump {
        from: from.unwrap_or(0),
        to,
    };

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
/// This looks like `( AB .. | CD .. [ | .. ] )`.
///
/// This is equivalent to the `alternatives` from `hex_grammar.y` in libyara.
fn alternatives(input: Input) -> ParseResult<Token> {
    let (input, _) = rtrim(char('(')).parse(input)?;

    cut(terminated(
        map(
            separated_list1(rtrim(char('|')), |input| tokens(input, true)),
            Token::Alternatives,
        ),
        rtrim(char(')')),
    ))
    .parse(input)
}

fn range_as_hex_token(input: Input, in_alternatives: bool) -> ParseResult<Token> {
    let start = input.pos();
    let (input, range) = range(input)?;

    // Some jumps are forbidden inside an alternatives
    if in_alternatives {
        if let Err(kind) = validate_jump_in_alternatives(&range) {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                kind,
            )));
        }
    }

    // Jump of one is equivalent to ??
    if let Some(to) = &range.to {
        if range.from == *to && range.from == 1 {
            return Ok((input, Token::MaskedByte(0, Mask::All)));
        }
    }
    Ok((input, Token::Jump(range)))
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
/// This is equivalent to the `token_or_range` rule in `hex_grammar.y` in libyara.
fn hex_token(input: Input, in_alternatives: bool) -> ParseResult<Token> {
    alt((
        not_token,
        map(byte, Token::Byte),
        map(masked_byte, |(v, mask)| Token::MaskedByte(v, mask)),
        |input| range_as_hex_token(input, in_alternatives),
        alternatives,
    ))
    .parse(input)
}

/// Parse a list of token
///
/// A jump is not allowed at the beginning or at the end of the list.
///
/// This is equivalent to the `tokens` rule in `hex_grammar.y` in libyara.
fn tokens(mut input: Input, in_alternatives: bool) -> ParseResult<Vec<Token>> {
    let start = input.pos();

    // This combinator is recursive:
    //
    // tokens => hex_token => alternatives => tokens
    //
    // Use the inner recursive counter to make sure this recursion cannot grow too much.
    if input.inner_recursion_counter >= MAX_HEX_TOKEN_RECURSION {
        return Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            ErrorKind::HexStringTooDeep,
        )));
    }

    input.inner_recursion_counter += 1;
    let (mut input, tokens) = many1(|input| hex_token(input, in_alternatives)).parse(input)?;
    input.inner_recursion_counter -= 1;

    if matches!(tokens[0], Token::Jump(_))
        || (tokens.len() > 1 && matches!(tokens[tokens.len() - 1], Token::Jump(_)))
    {
        Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            ErrorKind::JumpAtBound,
        )))
    } else {
        Ok((input, tokens))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{parse, parse_err, parse_err_type, test_public_type};

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
    fn test_parse_not_token() {
        parse(not_token, "~23a", "a", Token::NotByte(0x23));
        parse(
            not_token,
            "~?3b",
            "b",
            Token::NotMaskedByte(0x03, Mask::Left),
        );
        parse(
            not_token,
            "~F?",
            "",
            Token::NotMaskedByte(0x0F, Mask::Right),
        );

        parse_err(not_token, "~");
        parse_err(not_token, "~1");
        parse_err(not_token, "~1 2");
        parse_err(not_token, "~ 12");
        parse_err(not_token, "~??");
        parse_err(not_token, "~g1");
        parse_err(not_token, "~1g");
        parse_err(not_token, "12");
        parse_err(not_token, "?a");
        parse_err(not_token, "a?");
        parse_err(not_token, "??");
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
        parse_err(range, "[1 2]");
        parse_err(range, "[999999999999-]");
        parse_err(range, "[1-999999999999]");
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
            Token::Alternatives(vec![
                vec![Token::Byte(0xAB)],
                vec![Token::Byte(0x56), Token::MaskedByte(0x0F, Mask::Left)],
            ]),
        );
        parse(
            alternatives,
            "(12[1]C?|??[3-5]33)",
            "",
            Token::Alternatives(vec![
                vec![
                    Token::Byte(0x12),
                    Token::MaskedByte(0, Mask::All),
                    Token::MaskedByte(0x0C, Mask::Right),
                ],
                vec![
                    Token::MaskedByte(0x00, Mask::All),
                    Token::Jump(Jump {
                        from: 3,
                        to: Some(5),
                    }),
                    Token::Byte(0x33),
                ],
            ]),
        );
        parse(
            alternatives,
            "( ( ?D | 23)| 15) ",
            "",
            Token::Alternatives(vec![
                vec![Token::Alternatives(vec![
                    vec![Token::MaskedByte(0x0D, Mask::Left)],
                    vec![Token::Byte(0x23)],
                ])],
                vec![Token::Byte(0x15)],
            ]),
        );
        parse(
            alternatives,
            "( AA (BB | CC) | DD | EE FF )",
            "",
            Token::Alternatives(vec![
                vec![
                    Token::Byte(0xAA),
                    Token::Alternatives(vec![vec![Token::Byte(0xBB)], vec![Token::Byte(0xCC)]]),
                ],
                vec![Token::Byte(0xDD)],
                vec![Token::Byte(0xEE), Token::Byte(0xFF)],
            ]),
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

        parse_err(alternatives, "( [-] AB | CD )");
        parse_err(alternatives, "( AB [1-2] | CD )");
        parse_err(alternatives, "( AB | [3-] CD )");
        parse_err(alternatives, "( AB | CD EF [-5] )");
    }

    #[test]
    fn test_hex_string() {
        parse(hex_string, "{ AB }", "", vec![Token::Byte(0xAB)]);

        parse(
            hex_string,
            "{ DE AD BE EF }",
            "",
            vec![
                Token::Byte(0xDE),
                Token::Byte(0xAD),
                Token::Byte(0xBE),
                Token::Byte(0xEF),
            ],
        );
        parse(
            hex_string,
            "{ 01 ?2 ?? 3? [1-] ( AF | DC ) }",
            "",
            vec![
                Token::Byte(1),
                Token::MaskedByte(2, Mask::Left),
                Token::MaskedByte(0, Mask::All),
                Token::MaskedByte(3, Mask::Right),
                Token::Jump(Jump { from: 1, to: None }),
                Token::Alternatives(vec![vec![Token::Byte(0xAF)], vec![Token::Byte(0xDC)]]),
            ],
        );

        parse(
            hex_string,
            "{ 01 [1] 02 [2] 03 }  a",
            "a",
            vec![
                Token::Byte(1),
                Token::MaskedByte(0, Mask::All),
                Token::Byte(2),
                Token::Jump(Jump {
                    from: 2,
                    to: Some(2),
                }),
                Token::Byte(3),
            ],
        );

        parse_err(hex_string, "{ [-] }");
        parse_err(hex_string, "{ [-] AB }");
        parse_err(hex_string, "{ AB CD [-] }");

        parse_err(hex_string, "AB");
        parse_err(hex_string, "{");
        parse_err(hex_string, "{}");
        parse_err(hex_string, "{A}");
        parse_err(hex_string, "{ABA}");
        parse_err(hex_string, "{AB");
    }

    #[test]
    fn test_stack_overflow() {
        // Parsing of a hex string includes recursion, so it must be protected against
        // stack overflowing.
        let mut hex = String::new();
        hex.push_str("{ AB ");
        for _ in 0..10_000 {
            hex.push_str("( CD | ");
        }
        for _ in 0..10_000 {
            hex.push(')');
        }
        hex.push('}');

        parse_err_type(
            hex_string,
            &hex,
            &Error::new(70..70, ErrorKind::HexStringTooDeep),
        );

        // counter should reset, so many imbricated alternations, but all below the limit should be
        // fine.
        let mut hex = String::new();
        hex.push_str("{ AB ");
        let nb = MAX_HEX_TOKEN_RECURSION - 1;
        for _ in 0..nb {
            hex.push_str("( CD | ");
        }
        for _ in 0..nb {
            hex.push_str(" EF )");
        }
        hex.push_str(" EF ");
        for _ in 0..nb {
            hex.push_str("( CD | ");
        }
        for _ in 0..nb {
            hex.push_str("EF )");
        }
        hex.push('}');

        let input = Input::new(&hex);
        let _res = hex_string(input).unwrap();
        assert_eq!(input.inner_recursion_counter, 0);
    }

    #[test]
    fn test_parse_hex_string() {
        assert!(parse_hex_string(r"{ AB }").is_ok());
        assert!(parse_hex_string(r"AB").is_err());
    }

    #[test]
    fn test_public_types() {
        test_public_type(Token::Byte(3));
        test_public_type(Mask::Left);
        test_public_type(Jump { from: 3, to: None });
    }
}
