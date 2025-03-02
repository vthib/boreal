//! Parsing related to expressions involving string count/offset/length.
//!
//! This implements the `string_count/offset/length` elements in grammar.y
//! in libyara.
use nom::bytes::complete::tag;
use nom::character::complete::char;
use nom::combinator::{cut, opt};
use nom::sequence::{delimited, preceded};
use nom::Parser;

use crate::expression::common::range;
use crate::expression::primary_expression::primary_expression;
use crate::expression::{Expression, ExpressionKind};
use crate::nom_recipes::rtrim;
use crate::string;
use crate::types::{Input, ParseResult};

/// Parse a `string_count ( 'in' range )` expression
pub(super) fn string_count_expression(input: Input) -> ParseResult<Expression> {
    let start = input.pos();
    let (input_after_count, variable_name) = string::count(input)?;
    let (input, range) = opt(preceded(rtrim(tag("in")), cut(range))).parse(input_after_count)?;

    let expr = match range {
        // string_count
        None => ExpressionKind::Count(variable_name),
        // string_count 'in' range
        Some((from, to)) => ExpressionKind::CountInRange {
            variable_name,
            variable_name_span: input_after_count.get_span_from(start),
            from,
            to,
        },
    };
    Ok((
        input,
        Expression {
            expr,
            span: input.get_span_from(start),
        },
    ))
}

/// Parse a `string_offset ( '[' primary_expression ']' )` expression
pub(super) fn string_offset_expression(input: Input) -> ParseResult<Expression> {
    let start = input.pos();
    let (input, variable_name) = string::offset(input)?;
    let (input, expr) = opt(delimited(
        rtrim(char('[')),
        cut(primary_expression),
        cut(rtrim(char(']'))),
    ))
    .parse(input)?;

    let span = input.get_span_from(start);
    let expr = ExpressionKind::Offset {
        variable_name,
        occurence_number: match expr {
            Some(v) => Box::new(v),
            None => Box::new(Expression {
                expr: ExpressionKind::Integer(1),
                span: span.clone(),
            }),
        },
    };
    Ok((input, Expression { expr, span }))
}

/// Parse a `string_length ( '[' primary_expression ']' )` expression
pub(super) fn string_length_expression(input: Input) -> ParseResult<Expression> {
    let start = input.pos();
    let (input, variable_name) = string::length(input)?;
    let (input, expr) = opt(delimited(
        rtrim(char('[')),
        cut(primary_expression),
        cut(rtrim(char(']'))),
    ))
    .parse(input)?;

    let span = input.get_span_from(start);
    let expr = ExpressionKind::Length {
        variable_name,
        occurence_number: match expr {
            Some(v) => Box::new(v),
            None => Box::new(Expression {
                expr: ExpressionKind::Integer(1),
                span: span.clone(),
            }),
        },
    };
    Ok((input, Expression { expr, span }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{parse, parse_err};

    #[test]
    fn test_string_count_expression() {
        parse(
            string_count_expression,
            "#foo bar",
            "bar",
            Expression {
                expr: ExpressionKind::Count("foo".to_owned()),
                span: 0..4,
            },
        );
        parse(
            string_count_expression,
            "#foo in (0 ..filesize ) c",
            "c",
            Expression {
                expr: ExpressionKind::CountInRange {
                    variable_name: "foo".to_owned(),
                    variable_name_span: 0..4,
                    from: Box::new(Expression {
                        expr: ExpressionKind::Integer(0),
                        span: 9..10,
                    }),
                    to: Box::new(Expression {
                        expr: ExpressionKind::Filesize,
                        span: 13..21,
                    }),
                },
                span: 0..23,
            },
        );

        parse_err(string_count_expression, "");
        parse_err(string_count_expression, "foo");
        parse_err(string_count_expression, "#foo in");
    }

    #[test]
    fn test_string_offset_expression() {
        parse(
            string_offset_expression,
            "@a c",
            "c",
            Expression {
                expr: ExpressionKind::Offset {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: ExpressionKind::Integer(1),
                        span: 0..2,
                    }),
                },
                span: 0..2,
            },
        );
        parse(
            string_offset_expression,
            "@a [ 2] c",
            "c",
            Expression {
                expr: ExpressionKind::Offset {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: ExpressionKind::Integer(2),
                        span: 5..6,
                    }),
                },
                span: 0..7,
            },
        );
    }

    #[test]
    fn test_string_length_expression() {
        parse(
            string_length_expression,
            "!a c",
            "c",
            Expression {
                expr: ExpressionKind::Length {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: ExpressionKind::Integer(1),
                        span: 0..2,
                    }),
                },
                span: 0..2,
            },
        );
        parse(
            string_length_expression,
            "!a [ 2] c",
            "c",
            Expression {
                expr: ExpressionKind::Length {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: ExpressionKind::Integer(2),
                        span: 5..6,
                    }),
                },
                span: 0..7,
            },
        );

        parse_err(string_length_expression, "");
        parse_err(string_length_expression, "foo");
    }
}
