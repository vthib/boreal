//! Parsing methods common to several expressions.
use nom::bytes::complete::tag;
use nom::character::complete::char;
use nom::combinator::cut;
use nom::sequence::{separated_pair, terminated};
use nom::Parser;

use super::{primary_expression::primary_expression, Expression};
use crate::nom_recipes::rtrim;
use crate::types::{Input, ParseResult};

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
pub(super) fn range(input: Input) -> ParseResult<(Box<Expression>, Box<Expression>)> {
    let (input, _) = rtrim(char('(')).parse(input)?;

    let (input, (a, b)) = terminated(
        separated_pair(
            primary_expression,
            rtrim(tag("..")),
            cut(primary_expression),
        ),
        cut(rtrim(char(')'))),
    )
    .parse(input)?;

    Ok((input, (Box::new(a), Box::new(b))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::ExpressionKind,
        test_helpers::{parse, parse_err},
    };

    #[test]
    fn test_range() {
        parse(
            range,
            "(1..1) b",
            "b",
            (
                Box::new(Expression {
                    expr: ExpressionKind::Integer(1),
                    span: 1..2,
                }),
                Box::new(Expression {
                    expr: ExpressionKind::Integer(1),
                    span: 4..5,
                }),
            ),
        );
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (
                Box::new(Expression {
                    expr: ExpressionKind::Filesize,
                    span: 2..10,
                }),
                Box::new(Expression {
                    expr: ExpressionKind::Entrypoint,
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
