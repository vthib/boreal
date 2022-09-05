//! Parsing related to expressions.
//!
//! This implements the `expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{cut, value},
    sequence::preceded,
};

use super::{
    super::{
        nom_recipes::{rtrim, textual_tag as ttag},
        regex::regex,
        string::string_identifier,
        types::{Input, ParseResult},
    },
    common::range,
    for_expression::{for_expression_non_ambiguous, for_expression_with_expr_selection},
    primary_expression::primary_expression,
    Expression, ExpressionKind,
};

/// parse or operator
pub fn boolean_expression(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (input, res) = expression_and(input)?;

    match rtrim(ttag("or"))(input) {
        Ok((mut input, _)) => {
            let mut ops = vec![res];
            loop {
                let (i2, elem) = cut(expression_and)(input)?;
                ops.push(elem);
                match rtrim(ttag("or"))(i2) {
                    Ok((i3, _)) => input = i3,
                    Err(_) => {
                        return Ok((
                            i2,
                            Expression {
                                expr: ExpressionKind::Or(ops),
                                span: i2.get_span_from(start),
                            },
                        ))
                    }
                }
            }
        }
        Err(_) => Ok((input, res)),
    }
}

/// parse and operator
fn expression_and(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (input, res) = expression_not(input)?;

    match rtrim(ttag("and"))(input) {
        Ok((mut input, _)) => {
            let mut ops = vec![res];
            loop {
                let (i2, elem) = cut(expression_not)(input)?;
                ops.push(elem);
                match rtrim(ttag("and"))(i2) {
                    Ok((i3, _)) => input = i3,
                    Err(_) => {
                        return Ok((
                            i2,
                            Expression {
                                expr: ExpressionKind::And(ops),
                                span: i2.get_span_from(start),
                            },
                        ))
                    }
                }
            }
        }
        Err(_) => Ok((input, res)),
    }
}

/// parse defined & not operator
fn expression_not(mut input: Input) -> ParseResult<Expression> {
    let mut start = input;
    let mut ops = Vec::new();
    // Push ops into a vec, to prevent a possible stack overflow if we used recursion.
    while let Ok((i, op)) = rtrim(alt((ttag("not"), ttag("defined"))))(input) {
        ops.push((
            if op == "not" {
                ExpressionKind::Not
            } else {
                ExpressionKind::Defined
            },
            start,
        ));
        input = i;
        start = i;
    }

    let (input, mut expr) = expression_item(input)?;
    while let Some((op, start)) = ops.pop() {
        expr = Expression {
            expr: op(Box::new(expr)),
            span: input.get_span_from(start),
        };
    }

    Ok((input, expr))
}

/// parse rest of boolean expressions
fn expression_item(input: Input) -> ParseResult<Expression> {
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
fn primary_expression_eq_all(input: Input) -> ParseResult<Expression> {
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
            res = Expression {
                expr: ExpressionKind::Matches(Box::new(res), regexp),
                span: input.get_span_from(start),
            };
            continue;
        }

        let (i2, right_elem) = cut(primary_expression_cmp)(i)?;
        input = i2;
        let expr = match op {
            "==" => ExpressionKind::Eq(Box::new(res), Box::new(right_elem)),
            "!=" => ExpressionKind::NotEq(Box::new(res), Box::new(right_elem)),
            "contains" | "icontains" => ExpressionKind::Contains {
                haystack: Box::new(res),
                needle: Box::new(right_elem),
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "startswith" | "istartswith" => ExpressionKind::StartsWith {
                expr: Box::new(res),
                prefix: Box::new(right_elem),
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "endswith" | "iendswith" => ExpressionKind::EndsWith {
                expr: Box::new(res),
                suffix: Box::new(right_elem),
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "iequals" => ExpressionKind::IEquals(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        };
        res = Expression {
            expr,
            span: input.get_span_from(start),
        };
    }
    Ok((input, res))
}

/// parse `<=`, `>=`, `<`, `>`, operators.
fn primary_expression_cmp(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (mut input, mut res) = primary_expression(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<="), tag(">="), tag("<"), tag(">"))))(input) {
        let (i2, right_elem) = cut(primary_expression)(i)?;
        input = i2;
        let op = op.cursor();
        let less_than = op.bytes().next() == Some(b'<');
        let can_be_equal = op.len() == 2;
        res = Expression {
            expr: ExpressionKind::Cmp {
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
fn variable_expression(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (input, variable_name) = string_identifier(input)?;

    // string_identifier 'at' primary_expression
    if let Ok((input2, expr)) = preceded(rtrim(ttag("at")), primary_expression)(input) {
        Ok((
            input2,
            Expression {
                expr: ExpressionKind::VariableAt {
                    variable_name,
                    variable_name_span: input.get_span_from(start),
                    offset: Box::new(expr),
                },
                span: input2.get_span_from(start),
            },
        ))
    // string_identifier 'in' range
    } else if let Ok((input2, (from, to))) = preceded(rtrim(tag("in")), range)(input) {
        Ok((
            input2,
            Expression {
                expr: ExpressionKind::VariableIn {
                    variable_name,
                    variable_name_span: input.get_span_from(start),
                    from,
                    to,
                },
                span: input2.get_span_from(start),
            },
        ))
    // string_identifier
    } else {
        Ok((
            input,
            Expression {
                expr: ExpressionKind::Variable(variable_name),
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
        regex::{self, Regex},
        tests::{parse, parse_check, parse_err},
    };
    use std::ops::Range;

    #[track_caller]
    fn test_precedence<F, F2>(
        higher_op: &str,
        lower_op: &str,
        higher_constructor: F,
        lower_constructor: F2,
    ) where
        F: FnOnce(Box<Expression>, Box<Expression>) -> ExpressionKind,
        F2: FnOnce(Box<Expression>, Box<Expression>) -> ExpressionKind,
    {
        let input = format!("0 {} 1 {} 2", lower_op, higher_op);

        parse(
            boolean_expression,
            &input,
            "",
            Expression {
                expr: lower_constructor(
                    Box::new(Expression {
                        expr: ExpressionKind::Integer(0),
                        span: 0..1,
                    }),
                    Box::new(Expression {
                        expr: higher_constructor(
                            Box::new(Expression {
                                expr: ExpressionKind::Integer(1),
                                span: Range {
                                    start: 3 + lower_op.len(),
                                    end: 4 + lower_op.len(),
                                },
                            }),
                            Box::new(Expression {
                                expr: ExpressionKind::Integer(2),
                                span: Range {
                                    start: 6 + lower_op.len() + higher_op.len(),
                                    end: 7 + lower_op.len() + higher_op.len(),
                                },
                            }),
                        ),
                        span: Range {
                            start: 3 + lower_op.len(),
                            end: 7 + lower_op.len() + higher_op.len(),
                        },
                    }),
                ),
                span: Range {
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
            Expression {
                expr: ExpressionKind::VariableAt {
                    variable_name: "a".to_owned(),
                    variable_name_span: 0..2,
                    offset: Box::new(Expression {
                        expr: ExpressionKind::Integer(100),
                        span: 6..9,
                    }),
                },
                span: 0..9,
            },
        );
        parse(
            variable_expression,
            "$_ in (0.. 50) b",
            "b",
            Expression {
                expr: ExpressionKind::VariableIn {
                    variable_name: "_".to_owned(),
                    variable_name_span: 0..2,
                    from: Box::new(Expression {
                        expr: ExpressionKind::Integer(0),
                        span: 7..8,
                    }),
                    to: Box::new(Expression {
                        expr: ExpressionKind::Integer(50),
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
            Expression {
                expr: ExpressionKind::VariableIn {
                    variable_name: "".to_owned(),
                    variable_name_span: 0..1,
                    from: Box::new(Expression {
                        expr: ExpressionKind::Neg(Box::new(Expression {
                            expr: ExpressionKind::Integer(10),
                            span: 7..9,
                        })),
                        span: 6..9,
                    }),
                    to: Box::new(Expression {
                        expr: ExpressionKind::Neg(Box::new(Expression {
                            expr: ExpressionKind::Integer(5),
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
            Expression {
                expr: ExpressionKind::Variable("c".to_owned()),
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
            Expression {
                expr: ExpressionKind::And(vec![
                    Expression {
                        expr: ExpressionKind::Boolean(true),
                        span: 0..4,
                    },
                    Expression {
                        expr: ExpressionKind::Boolean(false),
                        span: 9..14,
                    },
                ]),
                span: 0..14,
            },
        );
        parse(
            boolean_expression,
            "not true or defined $b",
            "",
            Expression {
                expr: ExpressionKind::Or(vec![
                    Expression {
                        expr: ExpressionKind::Not(Box::new(Expression {
                            expr: ExpressionKind::Boolean(true),
                            span: 4..8,
                        })),
                        span: 0..8,
                    },
                    Expression {
                        expr: ExpressionKind::Defined(Box::new(Expression {
                            expr: ExpressionKind::Variable("b".to_owned()),
                            span: 20..22,
                        })),
                        span: 12..22,
                    },
                ]),
                span: 0..22,
            },
        );
        parse(
            boolean_expression,
            "not not true",
            "",
            Expression {
                expr: ExpressionKind::Not(Box::new(Expression {
                    expr: ExpressionKind::Not(Box::new(Expression {
                        expr: ExpressionKind::Boolean(true),
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
            F: FnOnce(Box<Expression>, Box<Expression>) -> ExpressionKind,
        {
            let input = format!("\"a\" {} \"b\" b", op);

            parse(
                boolean_expression,
                &input,
                "b",
                Expression {
                    expr: constructor(
                        Box::new(Expression {
                            expr: ExpressionKind::Bytes(b"a".to_vec()),
                            span: 0..3,
                        }),
                        Box::new(Expression {
                            expr: ExpressionKind::Bytes(b"b".to_vec()),
                            span: Range {
                                start: 5 + op.len(),
                                end: 8 + op.len(),
                            },
                        }),
                    ),
                    span: Range {
                        start: 0,
                        end: 8 + op.len(),
                    },
                },
            );
        }

        test_op("==", ExpressionKind::Eq);
        test_op("!=", ExpressionKind::NotEq);
        test_op("contains", |a, b| ExpressionKind::Contains {
            haystack: a,
            needle: b,
            case_insensitive: false,
        });
        test_op("icontains", |a, b| ExpressionKind::Contains {
            haystack: a,
            needle: b,
            case_insensitive: true,
        });
        test_op("startswith", |a, b| ExpressionKind::StartsWith {
            expr: a,
            prefix: b,
            case_insensitive: false,
        });
        test_op("istartswith", |a, b| ExpressionKind::StartsWith {
            expr: a,
            prefix: b,
            case_insensitive: true,
        });
        test_op("endswith", |a, b| ExpressionKind::EndsWith {
            expr: a,
            suffix: b,
            case_insensitive: false,
        });
        test_op("iendswith", |a, b| ExpressionKind::EndsWith {
            expr: a,
            suffix: b,
            case_insensitive: true,
        });
        test_op("iequals", ExpressionKind::IEquals);

        test_op("<", |a, b| ExpressionKind::Cmp {
            left: a,
            right: b,
            less_than: true,
            can_be_equal: false,
        });
        test_op("<=", |a, b| ExpressionKind::Cmp {
            left: a,
            right: b,
            less_than: true,
            can_be_equal: true,
        });
        test_op(">", |a, b| ExpressionKind::Cmp {
            left: a,
            right: b,
            less_than: false,
            can_be_equal: false,
        });
        test_op(">=", |a, b| ExpressionKind::Cmp {
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
            Expression {
                expr: ExpressionKind::Matches(
                    Box::new(Expression {
                        expr: ExpressionKind::Bytes(b"a".to_vec()),
                        span: 0..3,
                    }),
                    Regex {
                        ast: regex::Node::Literal(b'b'),
                        case_insensitive: true,
                        dot_all: false,
                        span: 12..16,
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
            move |a, b| ExpressionKind::Cmp {
                left: a,
                right: b,
                less_than,
                can_be_equal,
            }
        };

        // Test precedence of <, <=, >=, > over eq, etc
        test_precedence("<", "==", build_cmp(true, false), ExpressionKind::Eq);
        test_precedence("<=", "==", build_cmp(true, true), ExpressionKind::Eq);
        test_precedence(">", "==", build_cmp(false, false), ExpressionKind::Eq);
        test_precedence(">=", "==", build_cmp(false, true), ExpressionKind::Eq);
        test_precedence("<", "!=", build_cmp(true, false), ExpressionKind::NotEq);
        test_precedence("<", "contains", build_cmp(true, false), |a, b| {
            ExpressionKind::Contains {
                haystack: a,
                needle: b,
                case_insensitive: false,
            }
        });
        test_precedence("<", "icontains", build_cmp(true, false), |a, b| {
            ExpressionKind::Contains {
                haystack: a,
                needle: b,
                case_insensitive: true,
            }
        });
        test_precedence("<", "startswith", build_cmp(true, false), |a, b| {
            ExpressionKind::StartsWith {
                expr: a,
                prefix: b,
                case_insensitive: false,
            }
        });
        test_precedence("<", "istartswith", build_cmp(true, false), |a, b| {
            ExpressionKind::StartsWith {
                expr: a,
                prefix: b,
                case_insensitive: true,
            }
        });
        test_precedence("<", "endswith", build_cmp(true, false), |a, b| {
            ExpressionKind::EndsWith {
                expr: a,
                suffix: b,
                case_insensitive: false,
            }
        });
        test_precedence("<", "iendswith", build_cmp(true, false), |a, b| {
            ExpressionKind::EndsWith {
                expr: a,
                suffix: b,
                case_insensitive: true,
            }
        });
        test_precedence(
            "<",
            "iequals",
            build_cmp(true, false),
            ExpressionKind::IEquals,
        );
    }

    #[test]
    fn test_expression_precedence_eq_and_or() {
        // Test precedence of and over or
        parse(
            boolean_expression,
            "not true or false and true",
            "",
            Expression {
                expr: ExpressionKind::Or(vec![
                    Expression {
                        expr: ExpressionKind::Not(Box::new(Expression {
                            expr: ExpressionKind::Boolean(true),
                            span: 4..8,
                        })),
                        span: 0..8,
                    },
                    Expression {
                        expr: ExpressionKind::And(vec![
                            Expression {
                                expr: ExpressionKind::Boolean(false),
                                span: 12..17,
                            },
                            Expression {
                                expr: ExpressionKind::Boolean(true),
                                span: 22..26,
                            },
                        ]),
                        span: 12..26,
                    },
                ]),
                span: 0..26,
            },
        );

        // Test precedence of over eq, etc over and
        test_precedence("==", "and", ExpressionKind::Eq, |a, b| {
            ExpressionKind::And(vec![*a, *b])
        });
        test_precedence("!=", "and", ExpressionKind::NotEq, |a, b| {
            ExpressionKind::And(vec![*a, *b])
        });
    }

    #[test]
    fn test_expression() {
        parse(
            boolean_expression,
            "true b",
            "b",
            Expression {
                expr: ExpressionKind::Boolean(true),
                span: 0..4,
            },
        );
        parse(
            boolean_expression,
            "((false))",
            "",
            Expression {
                expr: ExpressionKind::Boolean(false),
                span: 2..7,
            },
        );
        parse(
            boolean_expression,
            "not true b",
            "b",
            Expression {
                expr: ExpressionKind::Not(Box::new(Expression {
                    expr: ExpressionKind::Boolean(true),
                    span: 4..8,
                })),
                span: 0..8,
            },
        );
        parse(
            boolean_expression,
            "not defined $a  c",
            "c",
            Expression {
                expr: ExpressionKind::Not(Box::new(Expression {
                    expr: ExpressionKind::Defined(Box::new(Expression {
                        expr: ExpressionKind::Variable("a".to_owned()),
                        span: 12..14,
                    })),
                    span: 4..14,
                })),
                span: 0..14,
            },
        );
        parse(
            boolean_expression,
            "defined not $a  c",
            "c",
            Expression {
                expr: ExpressionKind::Defined(Box::new(Expression {
                    expr: ExpressionKind::Not(Box::new(Expression {
                        expr: ExpressionKind::Variable("a".to_owned()),
                        span: 12..14,
                    })),
                    span: 8..14,
                })),
                span: 0..14,
            },
        );

        // primary expression is also an expression
        parse(
            boolean_expression,
            "5 b",
            "b",
            Expression {
                expr: ExpressionKind::Integer(5),
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
                ExpressionKind::Identifier(Identifier {
                    name: "nota".to_owned(),
                    name_span: 0..4,
                    operations: vec![]
                }),
            );
        });
        parse_check(boolean_expression, "defineda", |e| {
            assert_eq!(
                e.expr,
                ExpressionKind::Identifier(Identifier {
                    name: "defineda".to_owned(),
                    name_span: 0..8,
                    operations: vec![]
                }),
            );
        });
        parse_check(boolean_expression, "truea", |e| {
            assert_eq!(
                e.expr,
                ExpressionKind::Identifier(Identifier {
                    name: "truea".to_owned(),
                    name_span: 0..5,
                    operations: vec![]
                }),
            );
        });
        parse_check(boolean_expression, "falsea", |e| {
            assert_eq!(
                e.expr,
                ExpressionKind::Identifier(Identifier {
                    name: "falsea".to_owned(),
                    name_span: 0..6,
                    operations: vec![]
                }),
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
            Expression {
                expr: ExpressionKind::Eq(
                    Box::new(Expression {
                        expr: ExpressionKind::Integer(0),
                        span: 0..1,
                    }),
                    Box::new(Expression {
                        expr: ExpressionKind::Integer(0),
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
            Expression {
                expr: ExpressionKind::NotEq(
                    Box::new(Expression {
                        expr: ExpressionKind::Integer(1),
                        span: 0..1,
                    }),
                    Box::new(Expression {
                        expr: ExpressionKind::Integer(2),
                        span: 3..4,
                    }),
                ),
                span: 0..4,
            },
        );
    }
}
