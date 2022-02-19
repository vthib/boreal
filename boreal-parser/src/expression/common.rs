//! Parsing methods common to several expressions.
use nom::{
    bytes::complete::tag,
    character::complete::char,
    combinator::cut,
    sequence::{separated_pair, terminated},
};

use super::{primary_expression::primary_expression, ParsedExpr};
use crate::nom_recipes::rtrim;
use crate::types::{Input, ParseResult};

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
pub(super) fn range(input: Input) -> ParseResult<(Box<ParsedExpr>, Box<ParsedExpr>)> {
    let (input, _) = rtrim(char('('))(input)?;

    let (input, (a, b)) = terminated(
        separated_pair(
            primary_expression,
            rtrim(tag("..")),
            cut(primary_expression),
        ),
        cut(rtrim(char(')'))),
    )(input)?;

    Ok((input, (Box::new(a), Box::new(b))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::{Expression, Type},
        tests::{parse, parse_err},
    };

    #[test]
    fn test_range() {
        parse(
            range,
            "(1..1) b",
            "b",
            (
                Box::new(ParsedExpr {
                    expr: Expression::Number(1),
                    ty: Type::Integer,
                    span: 1..2,
                }),
                Box::new(ParsedExpr {
                    expr: Expression::Number(1),
                    ty: Type::Integer,
                    span: 4..5,
                }),
            ),
        );
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (
                Box::new(ParsedExpr {
                    expr: Expression::Filesize,
                    ty: Type::Integer,
                    span: 2..10,
                }),
                Box::new(ParsedExpr {
                    expr: Expression::Entrypoint,
                    ty: Type::Integer,
                    span: 14..24,
                }),
            ),
        );

        parse_err(range, "");
        parse_err(range, "(");
        parse_err(range, "(1)");
        parse_err(range, "()");
        parse_err(range, "(..)");
        parse_err(range, "(1..)");
        parse_err(range, "(..1)");
    }
}
