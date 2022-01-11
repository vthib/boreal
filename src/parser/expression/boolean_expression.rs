//! Parsing related to expressions.
//!
//! This implements the `expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    sequence::{delimited, preceded},
    IResult,
};

use super::super::{
    nom_recipes::rtrim,
    string::{regex, string_identifier},
};
use super::{common::range, primary_expression::primary_expression, ParsedExpr, Type};
use crate::{expression::Expression, parser::expression::nom_err_invalid_expression_type};

/// parse boolean expressions
pub fn boolean_expression(input: &str) -> IResult<&str, Expression> {
    let (input, expr) = expression(input)?;

    if expr.ty != Type::Boolean {
        return Err(nom_err_invalid_expression_type(input, &expr, Type::Boolean));
    }
    Ok((input, expr.expr))
}

/// parse or operator
fn expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = expression_and(input)?;

    while let Ok((i, _)) = rtrim(tag("or"))(input) {
        let (i2, right_elem) = cut(expression_and)(i)?;
        input = i2;
        res = ParsedExpr {
            expr: Expression::Or(
                res.try_unwrap(input, Type::Boolean)?,
                right_elem.try_unwrap(input, Type::Boolean)?,
            ),
            ty: Type::Boolean,
        }
    }
    Ok((input, res))
}

/// parse and operator
fn expression_and(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = expression_not(input)?;

    while let Ok((i, _)) = rtrim(tag("and"))(input) {
        let (i2, right_elem) = cut(expression_not)(i)?;
        input = i2;
        res = ParsedExpr {
            expr: Expression::And(
                res.try_unwrap(input, Type::Boolean)?,
                right_elem.try_unwrap(input, Type::Boolean)?,
            ),
            ty: Type::Boolean,
        }
    }
    Ok((input, res))
}

/// parse not operator
fn expression_not(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, not) = opt(rtrim(tag("not")))(input)?;

    if not.is_some() {
        let (input, expr) = cut(expression_defined)(input)?;
        Ok((
            input,
            ParsedExpr {
                expr: Expression::Not(expr.try_unwrap(input, Type::Boolean)?),
                ty: Type::Boolean,
            },
        ))
    } else {
        expression_defined(input)
    }
}

/// parse defined operator
fn expression_defined(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, defined) = opt(rtrim(tag("defined")))(input)?;

    if defined.is_some() {
        let (input, expr) = cut(expression_item)(input)?;
        Ok((
            input,
            ParsedExpr {
                // FIXME: in libyara, _DEFINED_ takes a boolean expression. That
                // does not look correct though, to investigate.
                expr: Expression::Defined(Box::new(expr.expr)),
                ty: Type::Boolean,
            },
        ))
    } else {
        expression_item(input)
    }
}

/// parse rest of boolean expressions
fn expression_item(input: &str) -> IResult<&str, ParsedExpr> {
    alt((
        // 'true'
        map(rtrim(tag("true")), |_| ParsedExpr {
            expr: Expression::Boolean(true),
            ty: Type::Boolean,
        }),
        // 'false'
        map(rtrim(tag("false")), |_| ParsedExpr {
            expr: Expression::Boolean(false),
            ty: Type::Boolean,
        }),
        // '(' expression ')'
        delimited(rtrim(char('(')), expression, rtrim(char(')'))),
        // string_identifier ...
        variable_expression,
        // primary_expression ...
        primary_expression_eq_all,
    ))(input)
}

/// parse `==`, `!=`, `(i)contains`, `(i)startswith`, `(i)endswith`,
/// `iequals`, `matches` operators.
fn primary_expression_eq_all(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_cmp(input)?;

    while let Ok((i, op)) = rtrim(alt((
        tag("=="),
        tag("!="),
        tag("contains"),
        tag("icontains"),
        tag("startswith"),
        tag("istartswith"),
        tag("endswith"),
        tag("iendswith"),
        tag("iequals"),
        tag("matches"),
    )))(input)
    {
        if op == "matches" {
            let (i2, regexp) = cut(regex)(i)?;
            input = i2;
            res = ParsedExpr {
                expr: Expression::Matches(res.try_unwrap(input, Type::String)?, regexp),
                ty: Type::Boolean,
            };
            continue;
        }

        let (i2, right_elem) = cut(primary_expression_cmp)(i)?;
        input = i2;
        let expr = match op {
            "==" => Expression::Eq(Box::new(res.expr), Box::new(right_elem.expr)),
            "!=" => {
                // TODO: improve this generation
                Expression::Not(Box::new(Expression::Eq(
                    Box::new(res.expr),
                    Box::new(right_elem.expr),
                )))
            }
            "contains" | "icontains" => Expression::Contains {
                haystack: res.try_unwrap(input, Type::String)?,
                needle: right_elem.try_unwrap(input, Type::String)?,
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "startswith" | "istartswith" => Expression::StartsWith {
                expr: res.try_unwrap(input, Type::String)?,
                prefix: right_elem.try_unwrap(input, Type::String)?,
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "endswith" | "iendswith" => Expression::EndsWith {
                expr: res.try_unwrap(input, Type::String)?,
                suffix: right_elem.try_unwrap(input, Type::String)?,
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "iequals" => Expression::IEquals(
                res.try_unwrap(input, Type::String)?,
                right_elem.try_unwrap(input, Type::String)?,
            ),
            _ => unreachable!(),
        };
        res = ParsedExpr {
            expr,
            ty: Type::Boolean,
        };
    }
    Ok((input, res))
}

/// parse `<=`, `>=`, `<`, `>`, operators.
fn primary_expression_cmp(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<="), tag(">="), tag("<"), tag(">"))))(input) {
        let (i2, right_elem) = cut(primary_expression)(i)?;
        input = i2;
        let less_than = op.bytes().next() == Some(b'<');
        let can_be_equal = op.len() == 2;
        res = ParsedExpr {
            expr: Expression::Cmp {
                left: Box::new(res.expr),
                right: Box::new(right_elem.expr),
                less_than,
                can_be_equal,
            },
            ty: Type::Boolean,
        };
    }
    Ok((input, res))
}

/// Parse expressions using variables
fn variable_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, variable) = string_identifier(input)?;

    // string_identifier 'at' primary_expression
    if let Ok((input, expr)) = preceded(rtrim(tag("at")), primary_expression)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableAt(variable, expr.try_unwrap(input, Type::Integer)?),
                ty: Type::Boolean,
            },
        ))
    // string_identifier 'in' range
    } else if let Ok((input, (from, to))) = preceded(rtrim(tag("in")), range)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableIn { variable, from, to },
                ty: Type::Boolean,
            },
        ))
    // string_identifier
    } else {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::Variable(variable),
                ty: Type::Boolean,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::test_utils::{parse, parse_err};

    #[track_caller]
    fn test_precedence<F, F2>(
        higher_op: &str,
        lower_op: &str,
        higher_constructor: F,
        lower_constructor: F2,
    ) where
        F: FnOnce(Box<Expression>, Box<Expression>) -> Expression,
        F2: FnOnce(Box<Expression>, Box<Expression>) -> Expression,
    {
        let input = format!("not true {} 1 {} 2", lower_op, higher_op);

        parse(
            expression,
            &input,
            "",
            ParsedExpr {
                expr: lower_constructor(
                    Box::new(Expression::Not(Box::new(Expression::Boolean(true)))),
                    Box::new(higher_constructor(
                        Box::new(Expression::Number(1)),
                        Box::new(Expression::Number(2)),
                    )),
                ),
                ty: Type::Boolean,
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
                expr: Expression::VariableAt("a".to_owned(), Box::new(Expression::Number(100))),
                ty: Type::Boolean,
            },
        );
        parse(
            variable_expression,
            "$_ in (0.. 50) b",
            "b",
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable: "_".to_owned(),
                    from: Box::new(Expression::Number(0)),
                    to: Box::new(Expression::Number(50)),
                },
                ty: Type::Boolean,
            },
        );
        parse(
            variable_expression,
            "$ in (-10..-5)",
            "",
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable: "".to_owned(),
                    from: Box::new(Expression::Neg(Box::new(Expression::Number(10)))),
                    to: Box::new(Expression::Neg(Box::new(Expression::Number(5)))),
                },
                ty: Type::Boolean,
            },
        );
        parse(
            variable_expression,
            "$c in (-10..-5",
            "in (-10..-5",
            ParsedExpr {
                expr: Expression::Variable("c".to_owned()),
                ty: Type::Boolean,
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
                    Box::new(Expression::Boolean(true)),
                    Box::new(Expression::Boolean(false)),
                ),
                ty: Type::Boolean,
            },
        );
        parse(
            expression,
            "not true or defined $b",
            "",
            ParsedExpr {
                expr: Expression::Or(
                    Box::new(Expression::Not(Box::new(Expression::Boolean(true)))),
                    Box::new(Expression::Defined(Box::new(Expression::Variable(
                        "b".to_owned(),
                    )))),
                ),
                ty: Type::Boolean,
            },
        );
    }

    #[test]
    fn test_rest_operators() {
        #[track_caller]
        fn test_op<F>(op: &str, constructor: F)
        where
            F: FnOnce(Box<Expression>, Box<Expression>) -> Expression,
        {
            let input = format!("\"a\" {} \"b\" b", op);

            parse(
                expression,
                &input,
                "b",
                ParsedExpr {
                    expr: constructor(
                        Box::new(Expression::String("a".to_owned())),
                        Box::new(Expression::String("b".to_owned())),
                    ),
                    ty: Type::Boolean,
                },
            );
        }

        test_op("==", Expression::Eq);
        test_op("!=", |a, b| Expression::Not(Box::new(Expression::Eq(a, b))));
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
                    Box::new(Expression::String("a".to_owned())),
                    crate::regex::Regex {
                        expr: "b".to_owned(),
                        case_insensitive: true,
                        dot_all: false,
                    },
                ),
                ty: Type::Boolean,
            },
        );

        parse_err(expression, "\"a\" matches");
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
                    Box::new(Expression::Not(Box::new(Expression::Boolean(true)))),
                    Box::new(Expression::And(
                        Box::new(Expression::Boolean(false)),
                        Box::new(Expression::Boolean(true)),
                    )),
                ),
                ty: Type::Boolean,
            },
        );

        // Test precedence of over eq, etc over and
        test_precedence("==", "and", Expression::Eq, Expression::And);
        test_precedence(
            "!=",
            "and",
            |a, b| Expression::Not(Box::new(Expression::Eq(a, b))),
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
                ty: Type::Boolean,
            },
        );
        parse(
            expression,
            "((false))",
            "",
            ParsedExpr {
                expr: Expression::Boolean(false),
                ty: Type::Boolean,
            },
        );
        parse(
            expression,
            "not true b",
            "b",
            ParsedExpr {
                expr: Expression::Not(Box::new(Expression::Boolean(true))),
                ty: Type::Boolean,
            },
        );
        parse(
            expression,
            "not defined $a  c",
            "c",
            ParsedExpr {
                expr: Expression::Not(Box::new(Expression::Defined(Box::new(
                    Expression::Variable("a".to_owned()),
                )))),
                ty: Type::Boolean,
            },
        );

        // primary expression is also an expression
        parse(
            expression,
            "5 b",
            "b",
            ParsedExpr {
                expr: Expression::Number(5),
                ty: Type::Integer,
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
    fn test_types() {
        parse_err(expression, "1 contains \"a\"");
        parse_err(expression, "\"a\" contains 1");

        parse_err(expression, "1 icontains \"a\"");
        parse_err(expression, "\"a\" icontains 1");

        parse_err(expression, "1 startswith \"a\"");
        parse_err(expression, "\"a\" startswith 1");

        parse_err(expression, "1 istartswith \"a\"");
        parse_err(expression, "\"a\" istartswith 1");

        parse_err(expression, "1 endswith \"a\"");
        parse_err(expression, "\"a\" endswith 1");

        parse_err(expression, "1 iendswith \"a\"");
        parse_err(expression, "\"a\" iendswith 1");

        parse_err(expression, "1 iequals \"a\"");
        parse_err(expression, "\"a\" iequals 1");

        parse_err(expression, "1 matches /a/");
        parse_err(expression, "\"a\" matches 1");

        parse_err(expression, "true and 1");
        parse_err(expression, "1 and true");

        parse_err(expression, "true or 1");
        parse_err(expression, "1 or true");

        parse_err(expression, "not 1");

        parse_err(expression, "$a at 1.2");
    }
}
