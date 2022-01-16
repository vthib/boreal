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
pub fn range(input: &str) -> IResult<&str, (Box<ParsedExpr>, Box<ParsedExpr>)> {
    let (input, _) = rtrim(char('('))(input)?;

    let (input, (a, b)) = cut(terminated(
        separated_pair(primary_expression, rtrim(tag("..")), primary_expression),
        rtrim(char(')')),
    ))(input)?;

    Ok((input, (Box::new(a), Box::new(b))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expression::Expression;
    use crate::parser::test_utils::{parse, parse_err};

    #[test]
    fn test_range() {
        parse(
            range,
            "(1..1) b",
            "b",
            (
                Box::new(ParsedExpr {
                    expr: Expression::Number(1),
                }),
                Box::new(ParsedExpr {
                    expr: Expression::Number(1),
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
                }),
                Box::new(ParsedExpr {
                    expr: Expression::Entrypoint,
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
