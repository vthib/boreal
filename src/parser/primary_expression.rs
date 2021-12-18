use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, multispace0 as sp0},
    combinator::{map, opt, recognize},
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};

use super::number;

#[derive(Debug, PartialEq)]
pub enum PrimaryExpression {
    FileSize,
    EntryPoint,
    IntegerFunction {
        name: String,
        expr: Box<PrimaryExpression>,
    },
    Number(i64),
}

// u?int(8|16|32)(be)?
fn integer_function(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        opt(char('u')),
        alt((tag("int8"), tag("int16"), tag("int32"))),
        opt(tag("be")),
    )))(input)
}

fn primary_expression(input: &str) -> IResult<&str, PrimaryExpression> {
    alt((
        map(tag("filesize"), |_| PrimaryExpression::FileSize),
        map(tag("entrypoint"), |_| PrimaryExpression::EntryPoint),
        map(number::number, PrimaryExpression::Number),
        map(
            pair(
                integer_function,
                delimited(
                    preceded(sp0, char('(')),
                    primary_expression,
                    preceded(sp0, char(')')),
                ),
            ),
            |(name, expr)| PrimaryExpression::IntegerFunction {
                name: name.to_owned(),
                expr: Box::new(expr),
            },
        ),
    ))(input)
}

#[cfg(test)]
mod tests {}
