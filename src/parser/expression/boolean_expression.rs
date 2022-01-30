//! Parsing related to expressions.
//!
//! This implements the `expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, opt},
    sequence::{delimited, preceded},
};

use super::{
    super::{
        nom_recipes::{rtrim, textual_tag as ttag},
        string::{regex, string_identifier},
        types::{Input, ParseResult},
    },
    common::{map_expr, range},
    for_expression::for_expression,
    primary_expression::primary_expression,
    Expression, ParsedExpr,
};

/// parse or operator
pub fn expression(input: Input) -> ParseResult<ParsedExpr> {
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
        let (input, expr) = cut(expression_defined)(input)?;
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
    alt((
        // 'true'
        map_expr(rtrim(ttag("true")), |_| Expression::Boolean(true)),
        // 'false'
        map_expr(rtrim(ttag("false")), |_| Expression::Boolean(false)),
        // '(' expression ')'
        delimited(rtrim(char('(')), expression, rtrim(char(')'))),
        // all variants of for expressions
        for_expression,
        // string_identifier ...
        variable_expression,
        // primary_expression ...
        primary_expression_eq_all,
    ))(input)
}

/// parse `==`, `!=`, `(i)contains`, `(i)startswith`, `(i)endswith`,
/// `iequals`, `matches` operators.
fn primary_expression_eq_all(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_cmp(input)?;

    while let Ok((i, op)) = rtrim(alt((
        ttag("=="),
        ttag("!="),
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
    let (input, variable) = string_identifier(input)?;

    // string_identifier 'at' primary_expression
    if let Ok((input, expr)) = preceded(rtrim(ttag("at")), primary_expression)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableAt(variable, Box::new(expr)),
                span: input.get_span_from(start),
            },
        ))
    // string_identifier 'in' range
    } else if let Ok((input, (from, to))) = preceded(rtrim(tag("in")), range)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableIn { variable, from, to },
                span: input.get_span_from(start),
            },
        ))
    // string_identifier
    } else {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::Variable(variable),
                span: input.get_span_from(start),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{
        expression::Identifier,
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
            expression,
            &input,
            "",
            ParsedExpr {
                expr: lower_constructor(
                    Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                        span: Span { start: 0, end: 1 },
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
                        span: Span { start: 6, end: 9 },
                    }),
                ),
                span: Span { start: 0, end: 9 },
            },
        );
        parse(
            variable_expression,
            "$_ in (0.. 50) b",
            "b",
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable: "_".to_owned(),
                    from: Box::new(ParsedExpr {
                        expr: Expression::Number(0),
                        span: Span { start: 7, end: 8 },
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Number(50),
                        span: Span { start: 11, end: 13 },
                    }),
                },
                span: Span { start: 0, end: 14 },
            },
        );
        parse(
            variable_expression,
            "$ in (-10..-5)",
            "",
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable: "".to_owned(),
                    from: Box::new(ParsedExpr {
                        expr: Expression::Neg(Box::new(ParsedExpr {
                            expr: Expression::Number(10),
                            span: Span { start: 7, end: 9 },
                        })),
                        span: Span { start: 6, end: 9 },
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Neg(Box::new(ParsedExpr {
                            expr: Expression::Number(5),
                            span: Span { start: 12, end: 13 },
                        })),
                        span: Span { start: 11, end: 13 },
                    }),
                },
                span: Span { start: 0, end: 14 },
            },
        );
        parse(
            variable_expression,
            "$c in (-10..-5",
            "in (-10..-5",
            ParsedExpr {
                expr: Expression::Variable("c".to_owned()),
                span: Span { start: 0, end: 2 },
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
            expression,
            "true and false b",
            "b",
            ParsedExpr {
                expr: Expression::And(
                    Box::new(ParsedExpr {
                        expr: Expression::Boolean(true),
                        span: Span { start: 0, end: 4 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::Boolean(false),
                        span: Span { start: 9, end: 14 },
                    }),
                ),
                span: Span { start: 0, end: 14 },
            },
        );
        parse(
            expression,
            "not true or defined $b",
            "",
            ParsedExpr {
                expr: Expression::Or(
                    Box::new(ParsedExpr {
                        expr: Expression::Not(Box::new(ParsedExpr {
                            expr: Expression::Boolean(true),
                            span: Span { start: 4, end: 8 },
                        })),
                        span: Span { start: 0, end: 8 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::Defined(Box::new(ParsedExpr {
                            expr: Expression::Variable("b".to_owned()),
                            span: Span { start: 20, end: 22 },
                        })),
                        span: Span { start: 12, end: 22 },
                    }),
                ),
                span: Span { start: 0, end: 22 },
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
                expression,
                &input,
                "b",
                ParsedExpr {
                    expr: constructor(
                        Box::new(ParsedExpr {
                            expr: Expression::String("a".to_owned()),
                            span: Span { start: 0, end: 3 },
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
                span: Span { start: 0, end: 10 },
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
            expression,
            "\"a\" matches /b/i b",
            "b",
            ParsedExpr {
                expr: Expression::Matches(
                    Box::new(ParsedExpr {
                        expr: Expression::String("a".to_owned()),
                        span: Span { start: 0, end: 3 },
                    }),
                    crate::regex::Regex {
                        expr: "b".to_owned(),
                        case_insensitive: true,
                        dot_all: false,
                    },
                ),
                span: Span { start: 0, end: 16 },
            },
        );

        parse_err(expression, "\"a\" matches");
        parse_err(expression, "\"a\" matches 1");
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
                span: Span { start: 0, end: 10 },
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
            expression,
            "not true or false and true",
            "",
            ParsedExpr {
                expr: Expression::Or(
                    Box::new(ParsedExpr {
                        expr: Expression::Not(Box::new(ParsedExpr {
                            expr: Expression::Boolean(true),
                            span: Span { start: 4, end: 8 },
                        })),
                        span: Span { start: 0, end: 8 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expression::And(
                            Box::new(ParsedExpr {
                                expr: Expression::Boolean(false),
                                span: Span { start: 12, end: 17 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expression::Boolean(true),
                                span: Span { start: 22, end: 26 },
                            }),
                        ),
                        span: Span { start: 12, end: 26 },
                    }),
                ),
                span: Span { start: 0, end: 26 },
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
                    span: Span { start: 6, end: 12 },
                }))
            },
            Expression::And,
        );
    }

    #[test]
    fn test_expression() {
        parse(
            expression,
            "true b",
            "b",
            ParsedExpr {
                expr: Expression::Boolean(true),
                span: Span { start: 0, end: 4 },
            },
        );
        parse(
            expression,
            "((false))",
            "",
            ParsedExpr {
                expr: Expression::Boolean(false),
                span: Span { start: 2, end: 7 },
            },
        );
        parse(
            expression,
            "not true b",
            "b",
            ParsedExpr {
                expr: Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Boolean(true),
                    span: Span { start: 4, end: 8 },
                })),
                span: Span { start: 0, end: 8 },
            },
        );
        parse(
            expression,
            "not defined $a  c",
            "c",
            ParsedExpr {
                expr: Expression::Not(Box::new(ParsedExpr {
                    expr: Expression::Defined(Box::new(ParsedExpr {
                        expr: Expression::Variable("a".to_owned()),
                        span: Span { start: 12, end: 14 },
                    })),
                    span: Span { start: 4, end: 14 },
                })),
                span: Span { start: 0, end: 14 },
            },
        );

        // primary expression is also an expression
        parse(
            expression,
            "5 b",
            "b",
            ParsedExpr {
                expr: Expression::Number(5),
                span: Span { start: 0, end: 1 },
            },
        );

        parse_err(expression, " ");
        parse_err(expression, "(");
        parse_err(expression, "()");
        parse_err(expression, "not");
        parse_err(expression, "defined");
        parse_err(expression, "1 == ");
    }

    #[test]
    fn test_textual_tag() {
        // Not parsed as "1 or a", but as "1" with trailing "ora", which
        // makes the parsing of ( expr ) fail.
        parse_err(expression, "(1ora)");
        parse_err(expression, "(1anda)");
        parse_check(expression, "nota", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("nota".to_owned()))
            );
        });
        parse_check(expression, "defineda", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("defineda".to_owned()))
            );
        });
        parse_check(expression, "truea", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("truea".to_owned()))
            );
        });
        parse_check(expression, "falsea", |e| {
            assert_eq!(
                e.expr,
                Expression::Identifier(Identifier::Raw("falsea".to_owned()))
            );
        });

        parse_err(expression, "(a containsb)");
        parse_err(expression, "(a icontainsb)");
        parse_err(expression, "(a startswitha)");
        parse_err(expression, "(a istartswitha)");
        parse_err(expression, "(a endswitha)");
        parse_err(expression, "(a iendswitha)");
        parse_err(expression, "(a iequalsa)");

        parse_err(expression, "($a atb)");
    }
}
