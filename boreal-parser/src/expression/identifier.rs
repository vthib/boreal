//! Parsing methods for identifiers used in expressions.
//!
//! This parses the [`crate::expression::Identifier`] object.
//! See the `identifier` rule in `grammar.y` in libyara.
use nom::branch::alt;
use nom::combinator::{map, opt};
use nom::{
    character::complete::char, combinator::cut, multi::separated_list0, sequence::terminated,
};

use super::{Expression, Identifier, IdentifierOperation};
use crate::nom_recipes::{not_followed, rtrim};
use crate::string::identifier as raw_identifier;
use crate::types::{Input, ParseResult};
use crate::IdentifierOperationType;

use super::boolean_expression::boolean_expression;
use super::primary_expression::primary_expression;

/// Parse a subfield, eg `.foo`.
fn subfield(input: Input) -> ParseResult<String> {
    // Use not_followed to ensure we do not eat the first character of the
    // .. operator. This can happen for example when parsing:
    // `for all i in (tests.constants.one..5)`
    let (input, _) = rtrim(not_followed(char('.'), char('.')))(input)?;

    cut(raw_identifier)(input)
}

/// Parse a subscript, e.g. `[5]`.
fn subscript(input: Input) -> ParseResult<Expression> {
    let (input, _) = rtrim(char('['))(input)?;

    cut(terminated(primary_expression, rtrim(char(']'))))(input)
}

/// Parse a function call, e.g. `(foo, bar)`.
fn function_call(input: Input) -> ParseResult<Vec<Expression>> {
    let (input, _) = rtrim(char('('))(input)?;

    cut(terminated(
        separated_list0(rtrim(char(',')), boolean_expression),
        rtrim(char(')')),
    ))(input)
}

/// Parse an identifier operation, i.e. a subfield, subscript or function call.
fn operation(input: Input) -> ParseResult<IdentifierOperationType> {
    alt((
        map(subfield, IdentifierOperationType::Subfield),
        map(subscript, |expr| {
            IdentifierOperationType::Subscript(Box::new(expr))
        }),
        map(function_call, IdentifierOperationType::FunctionCall),
    ))(input)
}

/// Parse an identifier used in expressions.
pub(super) fn identifier(input: Input) -> ParseResult<Identifier> {
    let start = input;
    let (mut input, name) = raw_identifier(input)?;
    let name_span = input.get_span_from(start);
    let mut operations = Vec::new();

    loop {
        let start = input;
        let (i, op) = opt(operation)(input)?;
        match op {
            Some(op) => {
                input = i;
                let span = input.get_span_from(start);
                operations.push(IdentifierOperation { op, span });
            }
            None => break,
        }
    }

    Ok((
        input,
        Identifier {
            name,
            name_span,
            operations,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::ExpressionKind,
        tests::{parse, parse_err},
    };

    #[test]
    fn test_identifier() {
        parse(
            identifier,
            "pe a",
            "a",
            Identifier {
                name: "pe".to_owned(),
                name_span: 0..2,
                operations: vec![],
            },
        );
        parse(
            identifier,
            "a.b]",
            "]",
            Identifier {
                name: "a".to_owned(),
                name_span: 0..1,
                operations: vec![IdentifierOperation {
                    op: IdentifierOperationType::Subfield("b".to_owned()),
                    span: 1..3,
                }],
            },
        );
        parse(
            identifier,
            "a [2 ]",
            "",
            Identifier {
                name: "a".to_owned(),
                name_span: 0..1,
                operations: vec![IdentifierOperation {
                    op: IdentifierOperationType::Subscript(Box::new(Expression {
                        expr: ExpressionKind::Integer(2),
                        span: 3..4,
                    })),
                    span: 2..6,
                }],
            },
        );
        parse(
            identifier,
            "foo()",
            "",
            Identifier {
                name: "foo".to_owned(),
                name_span: 0..3,
                operations: vec![IdentifierOperation {
                    op: IdentifierOperationType::FunctionCall(vec![]),
                    span: 3..5,
                }],
            },
        );
        parse(
            identifier,
            "foo(pe, true)",
            "",
            Identifier {
                name: "foo".to_owned(),
                name_span: 0..3,
                operations: vec![IdentifierOperation {
                    op: IdentifierOperationType::FunctionCall(vec![
                        Expression {
                            expr: ExpressionKind::Identifier(Identifier {
                                name: "pe".to_owned(),
                                name_span: 4..6,
                                operations: vec![],
                            }),
                            span: 4..6,
                        },
                        Expression {
                            expr: ExpressionKind::Boolean(true),
                            span: 8..12,
                        },
                    ]),
                    span: 3..13,
                }],
            },
        );

        parse_err(identifier, "");
        parse_err(identifier, "pe.");
        parse_err(identifier, "pe[");
        parse_err(identifier, "pe[2");
        parse_err(identifier, "pe[]");
        parse_err(identifier, "pe (");
        parse_err(identifier, "pe (1 2)");
    }

    // Test the loop when parsing identifier options works correctly
    #[test]
    fn test_identifier_loop() {
        let arg1 = Expression {
            expr: ExpressionKind::Identifier(Identifier {
                name: "c".to_owned(),
                name_span: 6..7,
                operations: vec![
                    IdentifierOperation {
                        op: IdentifierOperationType::Subscript(Box::new(Expression {
                            expr: ExpressionKind::Bytes(b"d".to_vec()),
                            span: 8..11,
                        })),
                        span: 7..12,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::Subfield("e".to_owned()),
                        span: 12..14,
                    },
                ],
            }),
            span: 6..14,
        };
        let arg2 = Expression {
            expr: ExpressionKind::Identifier(Identifier {
                name: "f".to_owned(),
                name_span: 16..17,
                operations: vec![
                    IdentifierOperation {
                        op: IdentifierOperationType::FunctionCall(vec![]),
                        span: 17..19,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::FunctionCall(vec![Expression {
                            expr: ExpressionKind::Boolean(true),
                            span: 20..24,
                        }]),
                        span: 19..25,
                    },
                ],
            }),
            span: 16..25,
        };

        parse(
            identifier,
            r#"a.b ( c["d"].e ,f()(true) )[3].g.h[1],"#,
            ",",
            Identifier {
                name: "a".to_owned(),
                name_span: 0..1,
                operations: vec![
                    IdentifierOperation {
                        op: IdentifierOperationType::Subfield("b".to_owned()),
                        span: 1..3,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::FunctionCall(vec![arg1, arg2]),
                        span: 4..27,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::Subscript(Box::new(Expression {
                            expr: ExpressionKind::Integer(3),
                            span: 28..29,
                        })),
                        span: 27..30,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::Subfield("g".to_owned()),
                        span: 30..32,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::Subfield("h".to_owned()),
                        span: 32..34,
                    },
                    IdentifierOperation {
                        op: IdentifierOperationType::Subscript(Box::new(Expression {
                            expr: ExpressionKind::Integer(1),
                            span: 35..36,
                        })),
                        span: 34..37,
                    },
                ],
            },
        );
    }
}
