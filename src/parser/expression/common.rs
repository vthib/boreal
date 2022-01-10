//! Parsing methods common to several expressions.
use nom::{
    bytes::complete::tag,
    character::complete::char,
    combinator::cut,
    sequence::{separated_pair, terminated},
    IResult,
};

use super::{primary_expression::primary_expression, ParsedExpr};
use crate::parser::nom_recipes::rtrim;

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
pub fn range(input: &str) -> IResult<&str, (ParsedExpr, ParsedExpr)> {
    let (input, _) = rtrim(char('('))(input)?;

    cut(terminated(
        separated_pair(primary_expression, rtrim(tag("..")), primary_expression),
        rtrim(char(')')),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::super::Type;
    use super::*;
    use crate::expression::Expression;
    use crate::parser::test_utils::{parse, parse_err};

    #[test]
    fn test_range() {
        parse(
            range,
            "(1..1) b",
            "b",
            (
                ParsedExpr {
                    expr: Expression::Number(1),
                    ty: Type::Integer,
                },
                ParsedExpr {
                    expr: Expression::Number(1),
                    ty: Type::Integer,
                },
            ),
        );
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (
                ParsedExpr {
                    expr: Expression::Filesize,
                    ty: Type::Integer,
                },
                ParsedExpr {
                    expr: Expression::Entrypoint,
                    ty: Type::Integer,
                },
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
