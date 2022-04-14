//! Parsing methods for identifiers used in expressions.
//!
//! This parses the [`crate::expression::Identifier`] object.
//! See the `identifier` rule in `grammar.y` in libyara.
use nom::{
    character::complete::char, combinator::cut, multi::separated_list0, sequence::terminated,
};

use super::{Expression, Identifier, IdentifierOperation};
use crate::nom_recipes::rtrim;
use crate::string::identifier as raw_identifier;
use crate::types::{Input, ParseResult};

use super::boolean_expression::boolean_expression;
use super::primary_expression::primary_expression;

/// Parse a trailing subfield, ie after the `.` has been parsed
fn trailing_subfield(input: Input) -> ParseResult<String> {
    cut(raw_identifier)(input)
}

/// Parse a trailing subscript, i.e. after the `[` has been parsed
fn trailing_subscript(input: Input) -> ParseResult<Expression> {
    cut(terminated(primary_expression, rtrim(char(']'))))(input)
}

/// Parse a trailing argument specification, i.e. after the `(` has been
/// parsed.
fn trailing_arguments(input: Input) -> ParseResult<Vec<Expression>> {
    cut(terminated(
        separated_list0(rtrim(char(',')), boolean_expression),
        rtrim(char(')')),
    ))(input)
}

/// Parse an identifier used in expressions.
pub(super) fn identifier(input: Input) -> ParseResult<Identifier> {
    let (mut input, name) = raw_identifier(input)?;
    let mut operations = Vec::new();

    loop {
        if let Ok((i, _)) = rtrim(char('.'))(input) {
            let (i2, subfield) = trailing_subfield(i)?;
            input = i2;
            operations.push(IdentifierOperation::Subfield(subfield));
            continue;
        }

        if let Ok((i, _)) = rtrim(char('['))(input) {
            let (i2, expr) = trailing_subscript(i)?;
            input = i2;
            operations.push(IdentifierOperation::Subscript(Box::new(expr)));
            continue;
        }

        if let Ok((i, _)) = rtrim(char('('))(input) {
            let (i2, arguments) = trailing_arguments(i)?;
            input = i2;
            operations.push(IdentifierOperation::FunctionCall(arguments));
            continue;
        }

        break;
    }

    Ok((input, Identifier { name, operations }))
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
                operations: vec![],
            },
        );
        parse(
            identifier,
            "a.b]",
            "]",
            Identifier {
                name: "a".to_owned(),
                operations: vec![IdentifierOperation::Subfield("b".to_owned())],
            },
        );
        parse(
            identifier,
            "a [2 ]",
            "",
            Identifier {
                name: "a".to_owned(),
                operations: vec![IdentifierOperation::Subscript(Box::new(Expression {
                    expr: ExpressionKind::Number(2),
                    span: 3..4,
                }))],
            },
        );
        parse(
            identifier,
            "foo()",
            "",
            Identifier {
                name: "foo".to_owned(),
                operations: vec![IdentifierOperation::FunctionCall(vec![])],
            },
        );
        parse(
            identifier,
            "foo(pe, true)",
            "",
            Identifier {
                name: "foo".to_owned(),
                operations: vec![IdentifierOperation::FunctionCall(vec![
                    Expression {
                        expr: ExpressionKind::Identifier(Identifier {
                            name: "pe".to_owned(),
                            operations: vec![],
                        }),
                        span: 4..6,
                    },
                    Expression {
                        expr: ExpressionKind::Boolean(true),
                        span: 8..12,
                    },
                ])],
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
                operations: vec![
                    IdentifierOperation::Subscript(Box::new(Expression {
                        expr: ExpressionKind::String("d".to_owned()),
                        span: 8..11,
                    })),
                    IdentifierOperation::Subfield("e".to_owned()),
                ],
            }),
            span: 6..14,
        };
        let arg2 = Expression {
            expr: ExpressionKind::Identifier(Identifier {
                name: "f".to_owned(),
                operations: vec![
                    IdentifierOperation::FunctionCall(vec![]),
                    IdentifierOperation::FunctionCall(vec![Expression {
                        expr: ExpressionKind::Boolean(true),
                        span: 20..24,
                    }]),
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
                operations: vec![
                    IdentifierOperation::Subfield("b".to_owned()),
                    IdentifierOperation::FunctionCall(vec![arg1, arg2]),
                    IdentifierOperation::Subscript(Box::new(Expression {
                        expr: ExpressionKind::Number(3),
                        span: 28..29,
                    })),
                    IdentifierOperation::Subfield("g".to_owned()),
                    IdentifierOperation::Subfield("h".to_owned()),
                    IdentifierOperation::Subscript(Box::new(Expression {
                        expr: ExpressionKind::Number(1),
                        span: 35..36,
                    })),
                ],
            },
        );
    }
}
