//! Parsing methods for identifiers used in expressions.
//!
//! This parses the [`crate::expression::Identifier`] object.
//! See the `identifier` rule in `grammar.y` in libyara.
use nom::combinator::map;
use nom::{
    character::complete::char, combinator::cut, multi::separated_list0, sequence::terminated,
};

use super::{Expression, Identifier};
use crate::nom_recipes::rtrim;
use crate::string::identifier as raw_identifier;
use crate::types::{Input, ParseResult};

use super::boolean_expression::expression;
use super::primary_expression::primary_expression;

/// Parse a trailing subfield, ie after the `.` has been parsed
fn trailing_subfield(input: Input) -> ParseResult<String> {
    cut(raw_identifier)(input)
}

/// Parse a trailing subscript, i.e. after the `[` has been parsed
fn trailing_subscript(input: Input) -> ParseResult<Expression> {
    cut(terminated(
        map(primary_expression, |v| v.expr),
        rtrim(char(']')),
    ))(input)
}

/// Parse a trailing argument specification, i.e. after the `(` has been
/// parsed.
fn trailing_arguments(input: Input) -> ParseResult<Vec<Expression>> {
    cut(terminated(
        separated_list0(rtrim(char(',')), map(expression, |e| e.expr)),
        rtrim(char(')')),
    ))(input)
}

/// Parse an identifier used in expressions.
pub(super) fn identifier(input: Input) -> ParseResult<Identifier> {
    let (mut input, name) = raw_identifier(input)?;
    let mut identifier = Identifier::Raw(name);

    loop {
        if let Ok((i, _)) = rtrim(char('.'))(input) {
            let (i2, subfield) = trailing_subfield(i)?;
            input = i2;
            identifier = Identifier::Subfield {
                identifier: Box::new(identifier),
                subfield,
            };
            continue;
        }

        if let Ok((i, _)) = rtrim(char('['))(input) {
            let (i2, expr) = trailing_subscript(i)?;
            input = i2;
            identifier = Identifier::Subscript {
                identifier: Box::new(identifier),
                subscript: Box::new(expr),
            };
            continue;
        }

        if let Ok((i, _)) = rtrim(char('('))(input) {
            let (i2, arguments) = trailing_arguments(i)?;
            input = i2;
            identifier = Identifier::FunctionCall {
                identifier: Box::new(identifier),
                arguments,
            };
            continue;
        }

        break;
    }

    Ok((input, identifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::Expression,
        tests::{parse, parse_err},
    };

    #[test]
    fn test_identifier() {
        parse(identifier, "pe a", "a", Identifier::Raw("pe".to_owned()));
        parse(
            identifier,
            "a.b]",
            "]",
            Identifier::Subfield {
                identifier: Box::new(Identifier::Raw("a".to_owned())),
                subfield: "b".to_owned(),
            },
        );
        parse(
            identifier,
            "a [2 ]",
            "",
            Identifier::Subscript {
                identifier: Box::new(Identifier::Raw("a".to_owned())),
                subscript: Box::new(Expression::Number(2)),
            },
        );
        parse(
            identifier,
            "foo()",
            "",
            Identifier::FunctionCall {
                identifier: Box::new(Identifier::Raw("foo".to_owned())),
                arguments: Vec::new(),
            },
        );
        parse(
            identifier,
            "foo(pe, true)",
            "",
            Identifier::FunctionCall {
                identifier: Box::new(Identifier::Raw("foo".to_owned())),
                arguments: vec![
                    Expression::Identifier(Identifier::Raw("pe".to_owned())),
                    Expression::Boolean(true),
                ],
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
        let identifier_call = Identifier::FunctionCall {
            identifier: Box::new(Identifier::Subfield {
                identifier: Box::new(Identifier::Raw("a".to_owned())),
                subfield: "b".to_owned(),
            }),
            arguments: vec![
                Expression::Identifier(Identifier::Subfield {
                    identifier: Box::new(Identifier::Subscript {
                        identifier: Box::new(Identifier::Raw("c".to_owned())),
                        subscript: Box::new(Expression::String("d".to_owned())),
                    }),
                    subfield: "e".to_owned(),
                }),
                Expression::Identifier(Identifier::FunctionCall {
                    identifier: Box::new(Identifier::FunctionCall {
                        identifier: Box::new(Identifier::Raw("f".to_owned())),
                        arguments: vec![],
                    }),
                    arguments: vec![Expression::Boolean(true)],
                }),
            ],
        };

        parse(
            identifier,
            r#"a.b ( c["d"].e ,f()(true) )[3].g.h[1],"#,
            ",",
            Identifier::Subscript {
                identifier: Box::new(Identifier::Subfield {
                    identifier: Box::new(Identifier::Subfield {
                        identifier: Box::new(Identifier::Subscript {
                            identifier: Box::new(identifier_call),
                            subscript: Box::new(Expression::Number(3)),
                        }),
                        subfield: "g".to_owned(),
                    }),
                    subfield: "h".to_owned(),
                }),
                subscript: Box::new(Expression::Number(1)),
            },
        );
    }
}
