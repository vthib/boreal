//! Parsing methods common to several expressions.
use nom::{
    bytes::complete::tag,
    character::complete::char,
    combinator::cut,
    sequence::{separated_pair, terminated},
    Parser,
};

use super::{primary_expression::primary_expression, Expression, ParsedExpr};
use crate::parser::types::{Input, ParseResult};
use crate::parser::{nom_recipes::rtrim, types::ParseError};

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
pub fn range(input: Input) -> ParseResult<(Box<ParsedExpr>, Box<ParsedExpr>)> {
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

pub(super) fn map_expr<'a, F, C, O>(
    mut f: F,
    constructor: C,
) -> impl FnMut(Input<'a>) -> ParseResult<'a, ParsedExpr>
where
    F: Parser<Input<'a>, O, ParseError>,
    C: Fn(O) -> Expression,
{
    move |input| {
        let start = input;
        let (input, output) = f.parse(input)?;
        Ok((
            input,
            ParsedExpr {
                expr: constructor(output),
                span: input.get_span_from(start),
            },
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{
        expression::Expression,
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
                    span: 1..2,
                }),
                Box::new(ParsedExpr {
                    expr: Expression::Number(1),
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
                    span: 2..10,
                }),
                Box::new(ParsedExpr {
                    expr: Expression::Entrypoint,
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
