//! Parsing related to numbers.
//!
//! This implements the _NUMBER_ and _DOUBLE_ lexical patterns from libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, digit1, hex_digit1, oct_digit1},
    combinator::{cut, map_res, opt, recognize, success},
    sequence::{pair, tuple},
    IResult,
};

use super::nom_recipes::{rtrim, textual_tag as ttag};

/// Parse a decimal number.
///
/// This function matches the pattern `/\d+(MB|KB)?`/.
fn decimal_number(input: &str) -> IResult<&str, i64> {
    map_res(
        rtrim(pair(
            map_res(digit1, str::parse::<i64>),
            opt(alt((ttag("MB"), ttag("KB")))),
        )),
        |(n, suffix)| match suffix {
            Some("MB") => n.checked_mul(1024 * 1024).ok_or(()),
            Some("KB") => n.checked_mul(1024).ok_or(()),
            _ => Ok(n),
        },
    )(input)
}

/// Parse an hexadecimal number.
///
/// This function matches the pattern `/0x\d+`/.
fn hexadecimal_number(input: &str) -> IResult<&str, i64> {
    let (input, _) = tag("0x")(input)?;

    cut(map_res(rtrim(hex_digit1), |v| i64::from_str_radix(v, 16)))(input)
}

/// Parse an octal number.
///
/// This function matches the pattern `/0o\d+`/.
fn octal_number(input: &str) -> IResult<&str, i64> {
    let (input, _) = tag("0o")(input)?;

    cut(map_res(rtrim(oct_digit1), |v| i64::from_str_radix(v, 8)))(input)
}

/// Parse a number (integer).
///
/// Equivalent to the _NUMBER_ lexical pattern in libyara.
/// Can be:
/// - hexadecimal with 0x prefix,
/// - octal with 0o prefix,
/// - decimal with optional KB/MB suffix.
pub fn number(input: &str) -> IResult<&str, i64> {
    // XXX: decimal number must be last, otherwise, it would parse the '0'
    // in the '0x'/'0o' prefix.
    alt((hexadecimal_number, octal_number, decimal_number))(input)
}

/// Parse a double.
///
/// Equivalent to the _DOUBLE_ lexical pattern in libyara.
/// This functions matches the pattern `/\d+\.\d+/`.
pub fn double(input: &str) -> IResult<&str, f64> {
    let (input, payload) = rtrim(recognize(tuple((digit1, char('.'), digit1))))(input)?;

    cut(map_res(success(payload), str::parse::<f64>))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::tests::{parse, parse_err};

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
        fn f(input: &str) -> IResult<&str, (i64, i64)> {
            pair(number, number)(input)
        }

        parse_err(f, "1MB2");
        parse_err(f, "1KB2");
    }
}
