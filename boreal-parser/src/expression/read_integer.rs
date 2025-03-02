//! Parsing related to the expressions `(u)uintXX(value)`.
//!
//! This implements the `integer_function` element in grammar.y in libyara.
use nom::branch::alt;
use nom::character::complete::char;
use nom::combinator::{cut, map};
use nom::sequence::{delimited, pair};
use nom::Parser;

use crate::expression::primary_expression::primary_expression;
use crate::expression::{Expression, ExpressionKind, ReadIntegerType};
use crate::nom_recipes::{rtrim, textual_tag as ttag};
use crate::types::{Input, ParseResult};

/// Parse a read of an integer.
///
/// Equivalent to the `_INTEGER_FUNCTION_` lexical pattern in libyara.
/// This is roughly equivalent to `u?int(8|16|32)(be)?`.
///
/// it returns a triple that consists of, in order:
/// - a boolean indicating the sign (true if unsigned).
/// - the size of the integer
/// - a boolean indicating the endianness (true if big-endian).
fn read_integer_type(input: Input) -> ParseResult<ReadIntegerType> {
    rtrim(alt((
        map(ttag("uint32be"), |_| ReadIntegerType::Uint32BE),
        map(ttag("uint32"), |_| ReadIntegerType::Uint32),
        map(ttag("int32be"), |_| ReadIntegerType::Int32BE),
        map(ttag("int32"), |_| ReadIntegerType::Int32),
        map(ttag("uint16be"), |_| ReadIntegerType::Uint16BE),
        map(ttag("uint16"), |_| ReadIntegerType::Uint16),
        map(ttag("int16be"), |_| ReadIntegerType::Int16BE),
        map(ttag("int16"), |_| ReadIntegerType::Int16),
        map(ttag("uint8be"), |_| ReadIntegerType::Uint8),
        map(ttag("uint8"), |_| ReadIntegerType::Uint8),
        map(ttag("int8be"), |_| ReadIntegerType::Int8),
        map(ttag("int8"), |_| ReadIntegerType::Int8),
    )))
    .parse(input)
}

pub(super) fn read_integer_expression(input: Input) -> ParseResult<Expression> {
    let start = input.pos();
    let (input, (ty, expr)) = pair(
        read_integer_type,
        cut(delimited(
            rtrim(char('(')),
            primary_expression,
            rtrim(char(')')),
        )),
    )
    .parse(input)?;

    Ok((
        input,
        Expression {
            expr: ExpressionKind::ReadInteger {
                ty,
                addr: Box::new(expr),
            },
            span: input.get_span_from(start),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        read_integer_expression, read_integer_type, Expression, ExpressionKind, ReadIntegerType,
    };
    use crate::test_helpers::{parse, parse_err, test_public_type};

    #[test]
    fn test_read_integer() {
        parse(read_integer_type, "int8", "", ReadIntegerType::Int8);
        parse(read_integer_type, "int8be a", "a", ReadIntegerType::Int8);
        parse(read_integer_type, "uint8 a", "a", ReadIntegerType::Uint8);
        parse(read_integer_type, "uint8be", "", ReadIntegerType::Uint8);
        parse(read_integer_type, "uint8 be", "be", ReadIntegerType::Uint8);
        parse(read_integer_type, "uint8 a", "a", ReadIntegerType::Uint8);

        parse(read_integer_type, "int16 a", "a", ReadIntegerType::Int16);
        parse(
            read_integer_type,
            "uint16 be",
            "be",
            ReadIntegerType::Uint16,
        );
        parse(
            read_integer_type,
            "int16be a",
            "a",
            ReadIntegerType::Int16BE,
        );
        parse(read_integer_type, "uint16be", "", ReadIntegerType::Uint16BE);

        parse(read_integer_type, "int32 b", "b", ReadIntegerType::Int32);
        parse(
            read_integer_type,
            "uint32 be",
            "be",
            ReadIntegerType::Uint32,
        );
        parse(
            read_integer_type,
            "int32be a",
            "a",
            ReadIntegerType::Int32BE,
        );
        parse(read_integer_type, "uint32be", "", ReadIntegerType::Uint32BE);

        parse_err(read_integer_type, "");
        parse_err(read_integer_type, "u");
        parse_err(read_integer_type, "uint");
        parse_err(read_integer_type, "int");
        parse_err(read_integer_type, "int8b");
        parse_err(read_integer_type, "int8bet");
        parse_err(read_integer_type, "int16bet");
        parse_err(read_integer_type, "int9");
        parse_err(read_integer_type, "uint1");
    }

    #[test]
    fn test_read_integer_expression() {
        parse(
            read_integer_expression,
            "uint8(3)",
            "",
            Expression {
                expr: ExpressionKind::ReadInteger {
                    ty: ReadIntegerType::Uint8,
                    addr: Box::new(Expression {
                        expr: ExpressionKind::Integer(3),
                        span: 6..7,
                    }),
                },
                span: 0..8,
            },
        );

        parse_err(read_integer_expression, "()");
        parse_err(read_integer_expression, "int16");
        parse_err(read_integer_expression, "uint32(");
        parse_err(read_integer_expression, "uint32()");
        parse_err(read_integer_expression, "uint32be ( 3");
    }

    #[test]
    fn test_public_types() {
        test_public_type(ReadIntegerType::Int32);
    }
}
