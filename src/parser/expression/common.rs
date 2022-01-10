//! Parsing methods common to several expressions.
use nom::{
    bytes::complete::tag,
    character::complete::char,
    combinator::cut,
    sequence::{separated_pair, terminated},
    IResult,
};

use super::{primary_expression::primary_expression, Expression, Type};
use crate::parser::nom_recipes::rtrim;

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
pub fn range(input: &str) -> IResult<&str, (Box<Expression>, Box<Expression>)> {
    let (input, _) = rtrim(char('('))(input)?;

    let (input, (a, b)) = cut(terminated(
        separated_pair(primary_expression, rtrim(tag("..")), primary_expression),
        rtrim(char(')')),
    ))(input)?;

    let a = a.try_unwrap(input, Type::Integer)?;
    let b = b.try_unwrap(input, Type::Integer)?;
    Ok((input, (a, b)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::test_utils::{parse, parse_err};

    #[test]
    fn test_range() {
        parse(
            range,
            "(1..1) b",
            "b",
            (
                Box::new(Expression::Number(1)),
                Box::new(Expression::Number(1)),
            ),
        );
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (
                Box::new(Expression::Filesize),
                Box::new(Expression::Entrypoint),
            ),
        );

        parse_err(range, "");
        parse_err(range, "(");
        parse_err(range, "(1)");
        parse_err(range, "()");
        parse_err(range, "(..)");
        parse_err(range, "(1..)");
        parse_err(range, "(..1)");

        parse_err(range, "(1..\"a\")");
        parse_err(range, "(/a/ .. 1)");
    }
}
