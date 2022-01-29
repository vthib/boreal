//! Parsing related to the expressions `(u)uintXX(value)`.
//!
//! This implements the `integer_function` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    sequence::{delimited, pair, tuple},
};

use crate::expression::ReadIntegerSize;
use crate::parser::nom_recipes::{rtrim, Input, ParseResult};

use super::{primary_expression::primary_expression, Expression, ParsedExpr};

/// Parse a read of an integer.
///
/// Equivalent to the `_INTEGER_FUNCTION_` lexical pattern in libyara.
/// This is roughly equivalent to `u?int(8|16|32)(be)?`.
///
/// it returns a triple that consists of, in order:
/// - a boolean indicating the sign (true if unsigned).
/// - the size of the integer
/// - a boolean indicating the endianness (true if big-endian).
fn read_integer(input: Input) -> ParseResult<(bool, ReadIntegerSize, bool)> {
    rtrim(tuple((
        map(opt(char('u')), |v| v.is_some()),
        alt((
            map(tag("int8"), |_| ReadIntegerSize::Int8),
            map(tag("int16"), |_| ReadIntegerSize::Int16),
            map(tag("int32"), |_| ReadIntegerSize::Int32),
        )),
        map(opt(tag("be")), |v| v.is_some()),
    )))(input)
}

pub fn read_integer_expression(input: Input) -> ParseResult<ParsedExpr> {
    let (input, ((unsigned, size, big_endian), expr)) = pair(
        read_integer,
        cut(delimited(
            rtrim(char('(')),
            primary_expression,
            rtrim(char(')')),
        )),
    )(input)?;

    Ok((
        input,
        ParsedExpr {
            expr: Expression::ReadInteger {
                unsigned,
                size,
                big_endian,
                addr: Box::new(expr),
            },
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::{parse, parse_err};
    use super::{
        read_integer, read_integer_expression, Expression, ParsedExpr, ReadIntegerSize as RIS,
    };

    #[test]
    fn test_read_integer() {
        parse(read_integer, "int8b", "b", (false, RIS::Int8, false));
        parse(read_integer, "uint8 be", "be", (true, RIS::Int8, false));
        parse(read_integer, "int8bet", "t", (false, RIS::Int8, true));
        parse(read_integer, "uint8be", "", (true, RIS::Int8, true));

        parse(read_integer, "int16b", "b", (false, RIS::Int16, false));
        parse(read_integer, "uint16 be", "be", (true, RIS::Int16, false));
        parse(read_integer, "int16bet", "t", (false, RIS::Int16, true));
        parse(read_integer, "uint16be", "", (true, RIS::Int16, true));

        parse(read_integer, "int32b", "b", (false, RIS::Int32, false));
        parse(read_integer, "uint32 be", "be", (true, RIS::Int32, false));
        parse(read_integer, "int32bet", "t", (false, RIS::Int32, true));
        parse(read_integer, "uint32be", "", (true, RIS::Int32, true));

        parse_err(read_integer, "");
        parse_err(read_integer, "u");
        parse_err(read_integer, "uint");
        parse_err(read_integer, "int");
        parse_err(read_integer, "int9");
        parse_err(read_integer, "uint1");
    }

    #[test]
    fn test_read_integer_expression() {
        parse(
            read_integer_expression,
            "uint8(3)",
            "",
            ParsedExpr {
                expr: Expression::ReadInteger {
                    unsigned: true,
                    size: RIS::Int8,
                    big_endian: false,
                    addr: Box::new(ParsedExpr {
                        expr: Expression::Number(3),
                    }),
                },
            },
        );

        parse_err(read_integer_expression, "()");
        parse_err(read_integer_expression, "int16");
        parse_err(read_integer_expression, "uint32(");
        parse_err(read_integer_expression, "uint32()");
        parse_err(read_integer_expression, "uint32be ( 3");
    }
}
