//! Parsing related to expressions involving string count/offset/length.
//!
//! This implements the `string_count/offset/length` elements in grammar.y
//! in libyara.
use nom::{
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, opt},
    sequence::{delimited, preceded},
    IResult,
};

use super::{common::range, primary_expression::primary_expression, Expression, ParsedExpr};
use crate::parser::{nom_recipes::rtrim, string};

/// Parse a `string_count ( 'in' range )` expression
pub fn string_count_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, identifier) = string::count(input)?;
    let (input, range) = opt(preceded(rtrim(tag("in")), cut(range)))(input)?;

    let expr = match range {
        // string_count
        None => Expression::Count(identifier),
        // string_count 'in' range
        Some((from, to)) => Expression::CountInRange {
            identifier,
            from,
            to,
        },
    };
    Ok((input, ParsedExpr { expr }))
}

/// Parse a `string_offset ( '[' primary_expression ']' )` expression
pub fn string_offset_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, identifier) = string::offset(input)?;
    let (input, expr) = opt(delimited(
        rtrim(char('[')),
        cut(primary_expression),
        cut(rtrim(char(']'))),
    ))(input)?;

    let expr = Expression::Offset {
        identifier,
        occurence_number: match expr {
            Some(v) => Box::new(v),
            None => Box::new(ParsedExpr {
                expr: Expression::Number(1),
            }),
        },
    };
    Ok((input, ParsedExpr { expr }))
}

/// Parse a `string_length ( '[' primary_expression ']' )` expression
pub fn string_length_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, identifier) = string::length(input)?;
    let (input, expr) = opt(delimited(
        rtrim(char('[')),
        cut(primary_expression),
        cut(rtrim(char(']'))),
    ))(input)?;

    let expr = Expression::Length {
        identifier,
        occurence_number: match expr {
            Some(v) => Box::new(v),
            None => Box::new(ParsedExpr {
                expr: Expression::Number(1),
            }),
        },
    };
    Ok((input, ParsedExpr { expr }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::test_utils::{parse, parse_err};

    #[test]
    fn test_string_count_expression() {
        parse(
            string_count_expression,
            "#foo bar",
            "bar",
            ParsedExpr {
                expr: Expression::Count("foo".to_owned()),
            },
        );
        parse(
            string_count_expression,
            "#foo in (0 ..filesize ) c",
            "c",
            ParsedExpr {
                expr: Expression::CountInRange {
                    identifier: "foo".to_owned(),
                    from: Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Filesize,
                    }),
                },
            },
        );

        parse_err(string_count_expression, "");
        parse_err(string_count_expression, "foo");
    }

    #[test]
    fn test_string_offset_expression() {
        parse(
            string_offset_expression,
            "@a c",
            "c",
            ParsedExpr {
                expr: Expression::Offset {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expression::Number(1),
                    }),
                },
            },
        );
        parse(
            string_offset_expression,
            "@a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expression::Offset {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expression::Number(2),
                    }),
                },
            },
        );
    }

    #[test]
    fn test_string_length_expression() {
        parse(
            string_length_expression,
            "!a c",
            "c",
            ParsedExpr {
                expr: Expression::Length {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expression::Number(1),
                    }),
                },
            },
        );
        parse(
            string_length_expression,
            "!a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expression::Length {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expression::Number(2),
                    }),
                },
            },
        );

        parse_err(string_length_expression, "");
        parse_err(string_length_expression, "foo");
    }
}
