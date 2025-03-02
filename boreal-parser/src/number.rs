//! Parsing related to numbers.
//!
//! This implements the _NUMBER_ and _DOUBLE_ lexical patterns from libyara.
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::{char, digit1, hex_digit1, oct_digit1};
use nom::combinator::{cut, opt, recognize};
use nom::sequence::{pair, preceded};
use nom::Parser;

use super::error::{Error, ErrorKind};
use super::nom_recipes::{rtrim, textual_tag as ttag};
use super::types::{Input, ParseResult};

/// Parse a decimal number.
///
/// This function matches the pattern `/\d+(MB|KB)?`/.
fn decimal_number(input: Input) -> ParseResult<i64> {
    let start = input.pos();
    let (input, (n, suffix)) =
        rtrim(pair(digit1, opt(alt((ttag("MB"), ttag("KB")))))).parse(input)?;

    let n = match str::parse::<i64>(&n) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::StrToIntError(e),
            )))
        }
    };

    let coef = match suffix {
        Some("MB") => 1024 * 1024,
        Some("KB") => 1024,
        _ => return Ok((input, n)),
    };
    match n.checked_mul(coef) {
        Some(n) => Ok((input, n)),
        None => Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            ErrorKind::MulOverflow {
                left: n,
                right: coef,
            },
        ))),
    }
}

/// Parse an hexadecimal number.
///
/// This function matches the pattern `/0x\d+`/.
fn hexadecimal_number(input: Input) -> ParseResult<i64> {
    let start = input.pos();
    let (input, n) = preceded(tag("0x"), cut(rtrim(hex_digit1))).parse(input)?;

    let n = match i64::from_str_radix(&n, 16) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::StrToHexIntError(e),
            )))
        }
    };

    Ok((input, n))
}

/// Parse an octal number.
///
/// This function matches the pattern `/0o\d+`/.
fn octal_number(input: Input) -> ParseResult<i64> {
    let start = input.pos();
    let (input, n) = preceded(tag("0o"), cut(rtrim(oct_digit1))).parse(input)?;

    let n = match i64::from_str_radix(&n, 8) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::StrToOctIntError(e),
            )))
        }
    };

    Ok((input, n))
}

/// Parse a number (integer).
///
/// Equivalent to the _NUMBER_ lexical pattern in libyara.
/// Can be:
/// - hexadecimal with 0x prefix,
/// - octal with 0o prefix,
/// - decimal with optional KB/MB suffix.
pub(crate) fn number(input: Input) -> ParseResult<i64> {
    // XXX: decimal number must be last, otherwise, it would parse the '0'
    // in the '0x'/'0o' prefix.
    alt((hexadecimal_number, octal_number, decimal_number)).parse(input)
}

/// Parse a double.
///
/// Equivalent to the _DOUBLE_ lexical pattern in libyara.
/// This functions matches the pattern `/\d+\.\d+/`.
pub(crate) fn double(input: Input) -> ParseResult<f64> {
    let (input, payload) = rtrim(recognize((digit1, char('.'), digit1))).parse(input)?;

    // Safety: this cannot fail, we are parsing `[0-9]+ '.' [0-9]+` which is guaranteed to
    // be valid, see <https://doc.rust-lang.org/std/primitive.f64.html#impl-FromStr>
    let v = str::parse::<f64>(&payload).unwrap();
    Ok((input, v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{parse, parse_err};

    #[test]
    fn test_parse_number() {
        parse(number, "0x2", "", 2);
        parse(number, "0x10", "", 16);
        parse(number, "0xfFaAbBcCdDeE5", "", 0xf_faab_bccd_dee5_i64);
        parse(number, "0xfF 3", "3", 0xff);
        parse(number, "0x1cg", "g", 0x1c);

        parse(number, "0x7FFFFFFFFFFFFFFF", "", i64::MAX);
        parse_err(number, "0xFFFFFFFFFFFFFFFF");

        parse(number, "0o10", "", 8);
        parse(number, "0o1234567", "", 0o1_234_567);
        parse(number, "0o2 4", "4", 2);
        parse(number, "0o789", "89", 7);
        parse(number, "0o777777777777777777777", "", i64::MAX);
        parse_err(number, "0o1777777777777777777777");

        parse(number, "010", "", 10);
        parse(number, "123456790", "", 123_456_790);
        parse(number, "52 5", "5", 52);
        parse(number, "52af", "af", 52);
        parse(number, "12MB", "", 12 * 1024 * 1024);
        parse(number, "456KB", "", 456 * 1024);

        parse(number, "9223372036854775807", "", i64::MAX);
        parse_err(number, "9223372036854775808");

        parse(number, "9007199254740991KB", "", i64::MAX - 1024 + 1);
        parse_err(number, "9007199254740992KB");
        parse(number, "8796093022207MB", "", i64::MAX - 1024 * 1024 + 1);
        parse_err(number, "8796093022208MB");

        parse_err(number, "a");
        parse_err(number, " 1");
    }

    #[test]
    fn test_parse_double() {
        parse(double, "3.4", "", 3.4);
        parse(double, "015.340b", "b", 15.34);
        parse_err(double, "a");
    }

    #[test]
    fn test_textual_tags() {
        // Parse two numbers consecutively, to detect
        // invalid acceptance of non textual "tag".
        fn f(input: Input) -> ParseResult<(i64, i64)> {
            pair(number, number).parse(input)
        }

        parse_err(f, "1MB2");
        parse_err(f, "1KB2");
    }
}
