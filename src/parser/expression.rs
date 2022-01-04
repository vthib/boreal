//! Parsing related to expressions.
//!
//! This implements the `expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    sequence::{delimited, pair, preceded},
    IResult,
};

use super::{
    nom_recipes::rtrim,
    primary_expression::{primary_expression, range},
    string::{regex, string_identifier},
};
use crate::expression::Expression;

/// parse or operator
pub fn expression(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = expression_and(input)?;

    while let Ok((i, _)) = rtrim(tag("or"))(input) {
        let (i2, right_elem) = cut(expression_and)(i)?;
        input = i2;
        res = Expression::Or(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse and operator
fn expression_and(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = expression_not(input)?;

    while let Ok((i, _)) = rtrim(tag("and"))(input) {
        let (i2, right_elem) = cut(expression_not)(i)?;
        input = i2;
        res = Expression::And(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse not operator
fn expression_not(input: &str) -> IResult<&str, Expression> {
    map(
        pair(opt(rtrim(tag("not"))), expression_defined),
        |(op, expr)| {
            if op.is_some() {
                Expression::Not(Box::new(expr))
            } else {
                expr
            }
        },
    )(input)
}

/// parse defined operator
fn expression_defined(input: &str) -> IResult<&str, Expression> {
    map(
        pair(opt(rtrim(tag("defined"))), expression_item),
        |(op, expr)| {
            if op.is_some() {
                Expression::Defined(Box::new(expr))
            } else {
                expr
            }
        },
    )(input)
}

/// parse rest of boolean expressions
fn expression_item(input: &str) -> IResult<&str, Expression> {
    alt((
        // 'true'
        map(rtrim(tag("true")), |_| Expression::Boolean(true)),
        // 'false'
        map(rtrim(tag("false")), |_| Expression::Boolean(false)),
        // '(' expression ')'
        delimited(rtrim(char('(')), expression, rtrim(char(')'))),
        // string_identifier ...
        expression_variable,
        // primary_expression ...
        primary_expression_eq_all,
    ))(input)
}

/// parse `==`, `!=`, `(i)contains`, `(i)startswith`, `(i)endswith`,
/// `iequals`, `matches` operators.
fn primary_expression_eq_all(input: &str) -> IResult<&str, Expression> {
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
            dbg!("oui");
            let (i2, regexp) = cut(regex)(i)?;
            input = i2;
            res = Expression::Matches(Box::new(res), regexp);
            continue;
        }

        let (i2, right_elem) = cut(primary_expression_cmp)(i)?;
        input = i2;
        res = match op {
            "==" => Expression::Eq(Box::new(res), Box::new(right_elem)),
            "!=" => {
                // TODO: improve this generation
                Expression::Not(Box::new(Expression::Eq(
                    Box::new(res),
                    Box::new(right_elem),
                )))
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
    }
    Ok((input, res))
}

/// parse `<=`, `>=`, `<`, `>`, operators.
fn primary_expression_cmp(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<="), tag(">="), tag("<"), tag(">"))))(input) {
        let (i2, right_elem) = cut(primary_expression)(i)?;
        input = i2;
        let less_than = op.bytes().next() == Some(b'<');
        let can_be_equal = op.len() == 2;
        res = Expression::Cmp {
            left: Box::new(res),
            right: Box::new(right_elem),
            less_than,
            can_be_equal,
        };
    }
    Ok((input, res))
}

/// Parse expressions using variables
fn expression_variable(input: &str) -> IResult<&str, Expression> {
    let (input, variable) = string_identifier(input)?;

    // string_identifier 'at' primary_expression
    if let Ok((input, expr)) = preceded(rtrim(tag("at")), primary_expression)(input) {
        Ok((input, Expression::VariableAt(variable, Box::new(expr))))
    // string_identifier 'in' range
    } else if let Ok((input, (from, to))) = preceded(rtrim(tag("in")), range)(input) {
        Ok((
            input,
            Expression::VariableIn {
                variable,
                from: Box::new(from),
                to: Box::from(to),
            },
        ))
    // string_identifier
    } else {
        Ok((input, Expression::Variable(variable)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::{parse, parse_err};
    use super::{expression, expression_variable, Expression};

    #[test]
    fn test_expression_variable() {
        parse(
            expression_variable,
            "$a at 100 b",
            "b",
            Expression::VariableAt("a".to_owned(), Box::new(Expression::Number(100))),
        );
        parse(
            expression_variable,
            "$_ in (0.. 50) b",
            "b",
            Expression::VariableIn {
                variable: "_".to_owned(),
                from: Box::new(Expression::Number(0)),
                to: Box::new(Expression::Number(50)),
            },
        );
        parse(
            expression_variable,
            "$ in (-10..-5)",
            "",
            Expression::VariableIn {
                variable: "".to_owned(),
                from: Box::new(Expression::Neg(Box::new(Expression::Number(10)))),
                to: Box::new(Expression::Neg(Box::new(Expression::Number(5)))),
            },
        );
        parse(
            expression_variable,
            "$c in (-10..-5",
            "in (-10..-5",
            Expression::Variable("c".to_owned()),
        );

        parse_err(expression_variable, "");
        parse_err(expression_variable, "b");
        parse_err(expression_variable, "50");
    }

    #[test]
    fn test_operators() {
        #[track_caller]
        fn test_op<F>(op: &str, constructor: F)
        where
            F: FnOnce(Box<Expression>, Box<Expression>) -> Expression,
        {
            let input = format!("1 {} 2 b", op);

            parse(
                expression,
                &input,
                "b",
                constructor(
                    Box::new(Expression::Number(1)),
                    Box::new(Expression::Number(2)),
                ),
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

        test_op("and", Expression::And);
        test_op("or", Expression::Or);

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
            "toto matches /b/i b",
            "b",
            Expression::Matches(
                Box::new(Expression::Identifier("toto".to_owned())),
                crate::regex::Regex {
                    expr: "b".to_owned(),
                    case_insensitive: true,
                    dot_all: false,
                },
            ),
        );

        parse_err(expression, "toto matches");
        parse_err(expression, "toto matches 1");
    }

    // TODO: test operators precedence

    #[test]
    fn test_expression() {
        parse(expression, "true b", "b", Expression::Boolean(true));
        parse(expression, "((false))", "", Expression::Boolean(false));
        parse(
            expression,
            "not true b",
            "b",
            Expression::Not(Box::new(Expression::Boolean(true))),
        );
        parse(
            expression,
            "not defined $a  c",
            "c",
            Expression::Not(Box::new(Expression::Defined(Box::new(
                Expression::Variable("a".to_owned()),
            )))),
        );

        // primary expression is also an expression
        parse(expression, "5 b", "b", Expression::Number(5));

        parse_err(expression, " ");
        parse_err(expression, "(");
        parse_err(expression, "()");
        parse_err(expression, "not");
        parse_err(expression, "defined");
        parse_err(expression, "1 == ");
    }
}
