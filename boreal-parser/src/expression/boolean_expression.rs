//! Parsing related to expressions.
//!
//! This implements the `expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{cut, opt, value},
    sequence::preceded,
};

use super::{
    super::{
        nom_recipes::{rtrim, textual_tag as ttag},
        string::{regex, string_identifier},
        types::{Input, ParseResult},
    },
    common::range,
    for_expression::{for_expression_non_ambiguous, for_expression_with_expr_selection},
    primary_expression::primary_expression,
    Expression, ParsedExpr,
};

/// parse or operator
pub fn boolean_expression(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = expression_and(input)?;

    while let Ok((i, _)) = rtrim(ttag("or"))(input) {
        let (i2, right_elem) = cut(expression_and)(i)?;
        input = i2;
        res = ParsedExpr {
            expr: Expression::Or(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse and operator
fn expression_and(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = expression_not(input)?;

    while let Ok((i, _)) = rtrim(ttag("and"))(input) {
        let (i2, right_elem) = cut(expression_not)(i)?;
        input = i2;
        res = ParsedExpr {
            expr: Expression::And(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse not operator
fn expression_not(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, not) = opt(rtrim(ttag("not")))(input)?;

    if not.is_some() {
        let (input, expr) = cut(expression_not)(input)?;
        Ok((
            input,
            ParsedExpr {
                expr: Expression::Not(Box::new(expr)),
                span: input.get_span_from(start),
            },
        ))
    } else {
        expression_defined(input)
    }
}

/// parse defined operator
fn expression_defined(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, defined) = opt(rtrim(ttag("defined")))(input)?;

    if defined.is_some() {
        let (input, expr) = cut(expression_item)(input)?;
        Ok((
            input,
            ParsedExpr {
                // FIXME: in libyara, _DEFINED_ takes a boolean expression. That
                // does not look correct though, to investigate.
                expr: Expression::Defined(Box::new(expr)),
                span: input.get_span_from(start),
            },
        ))
    } else {
        expression_item(input)
    }
}

/// parse rest of boolean expressions
fn expression_item(input: Input) -> ParseResult<ParsedExpr> {
    match alt((
        // all variants of for expressions with a non ambiguous first token
        for_expression_non_ambiguous,
        // string_identifier ...
        variable_expression,
    ))(input)
    {
        Ok((input, expr)) => return Ok((input, expr)),
        Err(nom::Err::Failure(e)) => return Err(nom::Err::Failure(e)),
        Err(_) => (),
    }

    // primary_expression ...
    let start = input;
    let (input, expr) = primary_expression_eq_all(input)?;

    // try to parse it as a for expression with a leading expression
    // as the first token. If it fails, it will return the given
    // expression.
    for_expression_with_expr_selection(expr, start, input)
}

/// parse `==`, `!=`, `(i)contains`, `(i)startswith`, `(i)endswith`,
/// `iequals`, `matches` operators.
fn primary_expression_eq_all(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_cmp(input)?;

    while let Ok((i, op)) = rtrim(alt((
        value("==", tag("==")),
        value("!=", tag("!=")),
        ttag("contains"),
        ttag("icontains"),
        ttag("startswith"),
        ttag("istartswith"),
        ttag("endswith"),
        ttag("iendswith"),
        ttag("iequals"),
        ttag("matches"),
    )))(input)
    {
        if op == "matches" {
            let (i2, regexp) = cut(regex)(i)?;
            input = i2;
            res = ParsedExpr {
                expr: Expression::Matches(Box::new(res), regexp),
                span: input.get_span_from(start),
            };
            continue;
        }

        let (i2, right_elem) = cut(primary_expression_cmp)(i)?;
        input = i2;
        let expr = match op {
            "==" => Expression::Eq(Box::new(res), Box::new(right_elem)),
            "!=" => {
                // TODO: improve this generation
                Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Eq(Box::new(res), Box::new(right_elem)),
                    span: input.get_span_from(start),
                }))
            }
            "contains" | "icontains" => Expression::Contains {
                haystack: Box::new(res),
                needle: Box::new(right_elem),
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "startswith" | "istartswith" => Expression::StartsWith {
                expr: Box::new(res),
                prefix: Box::new(right_elem),
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "endswith" | "iendswith" => Expression::EndsWith {
                expr: Box::new(res),
                suffix: Box::new(right_elem),
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "iequals" => Expression::IEquals(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        };
        res = ParsedExpr {
            expr,
            span: input.get_span_from(start),
        };
    }
    Ok((input, res))
}

/// parse `<=`, `>=`, `<`, `>`, operators.
fn primary_expression_cmp(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<="), tag(">="), tag("<"), tag(">"))))(input) {
        let (i2, right_elem) = cut(primary_expression)(i)?;
        input = i2;
        let op = op.cursor();
        let less_than = op.bytes().next() == Some(b'<');
        let can_be_equal = op.len() == 2;
        res = ParsedExpr {
            expr: Expression::Cmp {
                left: Box::new(res),
                right: Box::new(right_elem),
                less_than,
                can_be_equal,
            },
            span: input.get_span_from(start),
        };
    }
    Ok((input, res))
}

/// Parse expressions using variables
fn variable_expression(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, variable_name) = string_identifier(input)?;

    // string_identifier 'at' primary_expression
    if let Ok((input, expr)) = preceded(rtrim(ttag("at")), primary_expression)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableAt(variable_name, Box::new(expr)),
                span: input.get_span_from(start),
            },
        ))
    // string_identifier 'in' range
    } else if let Ok((input, (from, to))) = preceded(rtrim(tag("in")), range)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable_name,
                    from,
                    to,
                },
                span: input.get_span_from(start),
            },
        ))
    // string_identifier
    } else {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::Variable(variable_name),
                span: input.get_span_from(start),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::Identifier,
        string::Regex,
        tests::{parse, parse_check, parse_err},
        types::Span,
    };

    #[track_caller]
    fn test_precedence<F, F2>(
        higher_op: &str,
        lower_op: &str,
        higher_constructor: F,
        lower_constructor: F2,
    ) where
        F: FnOnce(Box<ParsedExpr>, Box<ParsedExpr>) -> Expression,
        F2: FnOnce(Box<ParsedExpr>, Box<ParsedExpr>) -> Expression,
    {
        let input = format!("0 {} 1 {} 2", lower_op, higher_op);

        parse(
            boolean_expression,
            &input,
            "",
            ParsedExpr {
                expr: lower_constructor(
                    Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                        span: 0..1,
                    }),
                    Box::new(ParsedExpr {
                        expr: higher_constructor(
                            Box::new(ParsedExpr {
                                expr: Expression::Number(1),
                                span: Span {
                                    start: 3 + lower_op.len(),
                                    end: 4 + lower_op.len(),
                                },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expression::Number(2),
                                span: Span {
                                    start: 6 + lower_op.len() + higher_op.len(),
                                    end: 7 + lower_op.len() + higher_op.len(),
                                },
                            }),
                        ),
                        span: Span {
                            start: 3 + lower_op.len(),
                            end: 7 + lower_op.len() + higher_op.len(),
                        },
                    }),
                ),
                span: Span {
                    start: 0,
                    end: 7 + lower_op.len() + higher_op.len(),
                },
            },
        );
    }

    #[test]
    fn test_variable_expression() {
        parse(
            variable_expression,
            "$a at 100 b",
            "b",
            ParsedExpr {
                expr: Expression::VariableAt(
                    "a".to_owned(),
                    Box::new(ParsedExpr {
                        expr: Expression::Number(100),
                        span: 6..9,
                    }),
                ),
                span: 0..9,
            },
        );
        parse(
            variable_expression,
            "$_ in (0.. 50) b",
            "b",
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable_name: "_".to_owned(),
                    from: Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                        span: 7..8,
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Number(50),
                        span: 11..13,
                    }),
                },
                span: 0..14,
            },
        );
        parse(
            variable_expression,
            "$ in (-10..-5)",
            "",
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable_name: "".to_owned(),
                    from: Box::new(ParsedExpr {
                        expr: Expression::Neg(Box::new(ParsedExpr {
                            expr: Expression::Number(10),
                            span: 7..9,
                        })),
                        span: 6..9,
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Neg(Box::new(ParsedExpr {
                            expr: Expression::Number(5),
                            span: 12..13,
                        })),
                        span: 11..13,
                    }),
                },
                span: 0..14,
            },
        );
        parse(
            variable_expression,
            "$c in (-10..-5",
            "in (-10..-5",
            ParsedExpr {
                expr: Expression::Variable("c".to_owned()),
                span: 0..2,
            },
        );

        parse_err(variable_expression, "");
        parse_err(variable_expression, "b");
        parse_err(variable_expression, "50");
    }

    // Test operators that require bool operands
    #[test]
    fn test_bool_operators() {
        parse(
            boolean_expression,
            "true and false b",
            "b",
            ParsedExpr {
                expr: Expression::And(
                    Box::new(ParsedExpr {
                        expr: Expression::Boolean(true),
                        span: 0..4,
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::Boolean(false),
                        span: 9..14,
                    }),
                ),
                span: 0..14,
            },
        );
        parse(
            boolean_expression,
            "not true or defined $b",
            "",
            ParsedExpr {
                expr: Expression::Or(
                    Box::new(ParsedExpr {
                        expr: Expression::Not(Box::new(ParsedExpr {
                            expr: Expression::Boolean(true),
                            span: 4..8,
                        })),
                        span: 0..8,
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::Defined(Box::new(ParsedExpr {
                            expr: Expression::Variable("b".to_owned()),
                            span: 20..22,
                        })),
                        span: 12..22,
                    }),
                ),
                span: 0..22,
            },
        );
        parse(
            boolean_expression,
            "not not true",
            "",
            ParsedExpr {
                expr: Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Not(Box::new(ParsedExpr {
                        expr: Expression::Boolean(true),
                        span: 8..12,
                    })),
                    span: 4..12,
                })),
                span: 0..12,
            },
        );
    }

    #[test]
    fn test_rest_operators() {
        #[track_caller]
        fn test_op<F>(op: &str, constructor: F)
        where
            F: FnOnce(Box<ParsedExpr>, Box<ParsedExpr>) -> Expression,
        {
            let input = format!("\"a\" {} \"b\" b", op);

            parse(
                boolean_expression,
                &input,
                "b",
                ParsedExpr {
                    expr: constructor(
                        Box::new(ParsedExpr {
                            expr: Expression::String("a".to_owned()),
                            span: 0..3,
                        }),
                        Box::new(ParsedExpr {
                            expr: Expression::String("b".to_owned()),
                            span: Span {
                                start: 5 + op.len(),
                                end: 8 + op.len(),
                            },
                        }),
                    ),
                    span: Span {
                        start: 0,
                        end: 8 + op.len(),
                    },
                },
            );
        }

        test_op("==", Expression::Eq);
        test_op("!=", |a, b| {
            Expression::Not(Box::new(ParsedExpr {
                expr: Expression::Eq(a, b),
                span: 0..10,
            }))
        });
        test_op("contains", |a, b| Expression::Contains {
            haystack: a,
            needle: b,
            case_insensitive: false,
        });
        test_op("icontains", |a, b| Expression::Contains {
            haystack: a,
            needle: b,
            case_insensitive: true,
        });
        test_op("startswith", |a, b| Expression::StartsWith {
            expr: a,
            prefix: b,
            case_insensitive: false,
        });
        test_op("istartswith", |a, b| Expression::StartsWith {
            expr: a,
            prefix: b,
            case_insensitive: true,
        });
        test_op("endswith", |a, b| Expression::EndsWith {
            expr: a,
            suffix: b,
            case_insensitive: false,
        });
        test_op("iendswith", |a, b| Expression::EndsWith {
            expr: a,
            suffix: b,
            case_insensitive: true,
        });
        test_op("iequals", Expression::IEquals);

        test_op("<", |a, b| Expression::Cmp {
            left: a,
            right: b,
            less_than: true,
            can_be_equal: false,
        });
        test_op("<=", |a, b| Expression::Cmp {
            left: a,
            right: b,
            less_than: true,
            can_be_equal: true,
        });
        test_op(">", |a, b| Expression::Cmp {
            left: a,
            right: b,
            less_than: false,
            can_be_equal: false,
        });
        test_op(">=", |a, b| Expression::Cmp {
            left: a,
            right: b,
            less_than: false,
            can_be_equal: true,
        });
    }

    #[test]
    fn test_matches() {
        parse(
            boolean_expression,
            "\"a\" matches /b/i b",
            "b",
            ParsedExpr {
                expr: Expression::Matches(
                    Box::new(ParsedExpr {
                        expr: Expression::String("a".to_owned()),
                        span: 0..3,
                    }),
                    Regex {
                        expr: "b".to_owned(),
                        case_insensitive: true,
                        dot_all: false,
                    },
                ),
                span: 0..16,
            },
        );

        parse_err(boolean_expression, "\"a\" matches");
        parse_err(boolean_expression, "\"a\" matches 1");
    }

    #[test]
    fn test_expression_precedence_cmp_eq() {
        let build_cmp = |less_than, can_be_equal| {
            move |a, b| Expression::Cmp {
                left: a,
                right: b,
                less_than,
                can_be_equal,
            }
        };

        // Test precedence of <, <=, >=, > over eq, etc
        test_precedence("<", "==", build_cmp(true, false), Expression::Eq);
        test_precedence("<=", "==", build_cmp(true, true), Expression::Eq);
        test_precedence(">", "==", build_cmp(false, false), Expression::Eq);
        test_precedence(">=", "==", build_cmp(false, true), Expression::Eq);
        test_precedence("<", "!=", build_cmp(true, false), |a, b| {
            Expression::Not(Box::new(ParsedExpr {
                expr: Expression::Eq(a, b),
                span: 0..10,
            }))
        });
        test_precedence("<", "contains", build_cmp(true, false), |a, b| {
            Expression::Contains {
                haystack: a,
                needle: b,
                case_insensitive: false,
            }
        });
        test_precedence("<", "icontains", build_cmp(true, false), |a, b| {
            Expression::Contains {
                haystack: a,
                needle: b,
                case_insensitive: true,
            }
        });
        test_precedence("<", "startswith", build_cmp(true, false), |a, b| {
            Expression::StartsWith {
                expr: a,
                prefix: b,
                case_insensitive: false,
            }
        });
        test_precedence("<", "istartswith", build_cmp(true, false), |a, b| {
            Expression::StartsWith {
                expr: a,
                prefix: b,
                case_insensitive: true,
            }
        });
        test_precedence("<", "endswith", build_cmp(true, false), |a, b| {
            Expression::EndsWith {
                expr: a,
                suffix: b,
                case_insensitive: false,
            }
        });
        test_precedence("<", "iendswith", build_cmp(true, false), |a, b| {
            Expression::EndsWith {
                expr: a,
                suffix: b,
                case_insensitive: true,
            }
        });
        test_precedence("<", "iequals", build_cmp(true, false), Expression::IEquals);
    }

    #[test]
    fn test_expression_precedence_eq_and_or() {
        // Test precedence of and over or
        parse(
            boolean_expression,
            "not true or false and true",
            "",
            ParsedExpr {
                expr: Expression::Or(
                    Box::new(ParsedExpr {
                        expr: Expression::Not(Box::new(ParsedExpr {
                            expr: Expression::Boolean(true),
                            span: 4..8,
                        })),
                        span: 0..8,
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::And(
                            Box::new(ParsedExpr {
                                expr: Expression::Boolean(false),
                                span: 12..17,
                            }),
                            Box::new(ParsedExpr {
                                expr: Expression::Boolean(true),
                                span: 22..26,
                            }),
                        ),
                        span: 12..26,
                    }),
                ),
                span: 0..26,
            },
        );

        // Test precedence of over eq, etc over and
        test_precedence("==", "and", Expression::Eq, Expression::And);
        test_precedence(
            "!=",
            "and",
            |a, b| {
                Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Eq(a, b),
                    span: 6..12,
                }))
            },
            Expression::And,
        );
    }

    #[test]
    fn test_expression() {
        parse(
            boolean_expression,
            "true b",
            "b",
            ParsedExpr {
                expr: Expression::Boolean(true),
                span: 0..4,
            },
        );
        parse(
            boolean_expression,
            "((false))",
            "",
            ParsedExpr {
                expr: Expression::Boolean(false),
                span: 2..7,
            },
        );
        parse(
            boolean_expression,
            "not true b",
            "b",
            ParsedExpr {
                expr: Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Boolean(true),
                    span: 4..8,
                })),
                span: 0..8,
            },
        );
        parse(
            boolean_expression,
            "not defined $a  c",
            "c",
            ParsedExpr {
                expr: Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Defined(Box::new(ParsedExpr {
                        expr: Expression::Variable("a".to_owned()),
                        span: 12..14,
                    })),
                    span: 4..14,
                })),
                span: 0..14,
            },
        );

        // primary expression is also an expression
        parse(
            boolean_expression,
            "5 b",
            "b",
            ParsedExpr {
                expr: Expression::Number(5),
                span: 0..1,
            },
        );

        parse_err(boolean_expression, " ");
        parse_err(boolean_expression, "(");
        parse_err(boolean_expression, "()");
        parse_err(boolean_expression, "not");
        parse_err(boolean_expression, "defined");
        parse_err(boolean_expression, "1 == ");
    }

    #[test]
    fn test_textual_tag() {
        // Not parsed as "1 or a", but as "1" with trailing "ora", which
        // makes the parsing of ( expr ) fail.
        parse_err(boolean_expression, "(1ora)");
        parse_err(boolean_expression, "(1anda)");
        parse_check(boolean_expression, "nota", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("nota".to_owned()))
            );
        });
        parse_check(boolean_expression, "defineda", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("defineda".to_owned()))
            );
        });
        parse_check(boolean_expression, "truea", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("truea".to_owned()))
            );
        });
        parse_check(boolean_expression, "falsea", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("falsea".to_owned()))
            );
        });

        parse_err(boolean_expression, "(a containsb)");
        parse_err(boolean_expression, "(a icontainsb)");
        parse_err(boolean_expression, "(a startswitha)");
        parse_err(boolean_expression, "(a istartswitha)");
        parse_err(boolean_expression, "(a endswitha)");
        parse_err(boolean_expression, "(a iendswitha)");
        parse_err(boolean_expression, "(a iequalsa)");

        parse_err(boolean_expression, "($a atb)");

        // However, == and != do not use textual tags:
        parse(
            boolean_expression,
            "0==0",
            "",
            ParsedExpr {
                expr: Expression::Eq(
                    Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                        span: 0..1,
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                        span: 3..4,
                    }),
                ),
                span: 0..4,
            },
        );
        parse(
            boolean_expression,
            "1!=2",
            "",
            ParsedExpr {
                expr: Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Eq(
                        Box::new(ParsedExpr {
                            expr: Expression::Number(1),
                            span: 0..1,
                        }),
                        Box::new(ParsedExpr {
                            expr: Expression::Number(2),
                            span: 3..4,
                        }),
                    ),
                    span: 0..4,
                })),
                span: 0..4,
            },
        );
    }
}
