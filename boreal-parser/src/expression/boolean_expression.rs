//! Parsing related to expressions.
//!
//! This implements the `expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{cut, opt, value},
    sequence::preceded,
};

use crate::{error::ErrorKind, types::Span, Error};

use super::{
    super::{
        nom_recipes::{rtrim, textual_tag as ttag},
        string::{regex, string_identifier},
        types::{Input, ParseResult},
    },
    common::range,
    for_expression::{for_expression_non_ambiguous, for_expression_with_expr_selection},
    primary_expression::primary_expression,
    Expression, ParsedExpr, Type,
};

/// parse or operator
pub(super) fn boolean_expression(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = expression_and(input)?;

    while let Ok((i, _)) = rtrim(ttag("or"))(input) {
        let (i2, right_elem) = cut(expression_and)(i)?;
        input = i2;
        res = ParsedExpr {
            expr: Expression::Or(Box::new(res.expr), Box::new(right_elem.expr)),
            ty: Type::Boolean,
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
            expr: Expression::And(Box::new(res.expr), Box::new(right_elem.expr)),
            ty: Type::Boolean,
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
                expr: Expression::Not(Box::new(expr.expr)),
                ty: Type::Boolean,
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
                expr: Expression::Defined(Box::new(expr.expr)),
                ty: Type::Boolean,
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
        // all variants of for expressions with a non ambiguous first
        // token
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
                expr: Expression::Matches(res.unwrap_expr(Type::String)?, regexp),
                ty: Type::Boolean,
                span: input.get_span_from(start),
            };
            continue;
        }

        let (i2, right_elem) = cut(primary_expression_cmp)(i)?;
        input = i2;
        let expr = match op {
            "==" => {
                let span = input.get_span_from(start);
                let (left, right) = validate_cmp_operands(res, right_elem, span)?;
                Expression::Eq(left, right)
            }
            "!=" => {
                // TODO: improve this generation
                let span = input.get_span_from(start);
                let (left, right) = validate_cmp_operands(res, right_elem, span)?;
                Expression::Not(Box::new(Expression::Eq(left, right)))
            }
            "contains" | "icontains" => Expression::Contains {
                haystack: res.unwrap_expr(Type::String)?,
                needle: right_elem.unwrap_expr(Type::String)?,
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "startswith" | "istartswith" => Expression::StartsWith {
                expr: res.unwrap_expr(Type::String)?,
                prefix: right_elem.unwrap_expr(Type::String)?,
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "endswith" | "iendswith" => Expression::EndsWith {
                expr: res.unwrap_expr(Type::String)?,
                suffix: right_elem.unwrap_expr(Type::String)?,
                case_insensitive: op.bytes().next() == Some(b'i'),
            },
            "iequals" => Expression::IEquals(
                res.unwrap_expr(Type::String)?,
                right_elem.unwrap_expr(Type::String)?,
            ),
            _ => unreachable!(),
        };
        res = ParsedExpr {
            expr,
            ty: Type::Boolean,
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
        let span = input.get_span_from(start);
        let (left, right) = validate_cmp_operands(res, right_elem, span)?;
        res = ParsedExpr {
            expr: Expression::Cmp {
                left,
                right,
                less_than,
                can_be_equal,
            },
            ty: Type::Boolean,
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
                expr: Expression::VariableAt(variable, expr.unwrap_expr(Type::Integer)?),
                ty: Type::Boolean,
                span: input.get_span_from(start),
            },
        ))
    // string_identifier 'in' range
    } else if let Ok((input, (from, to))) = preceded(rtrim(tag("in")), range)(input) {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::VariableIn {
                    variable_name: variable,
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Boolean,
                span: input.get_span_from(start),
            },
        ))
    // string_identifier
    } else {
        Ok((
            input,
            ParsedExpr {
                expr: Expression::Variable(variable),
                ty: Type::Boolean,
                span: input.get_span_from(start),
            },
        ))
    }
}

fn validate_cmp_operands(
    left: ParsedExpr,
    right: ParsedExpr,
    span: Span,
) -> Result<(Box<Expression>, Box<Expression>), nom::Err<Error>> {
    match (left.ty, right.ty) {
        (Type::Integer, Type::Integer) => (),
        (Type::Undefined, Type::Integer) | (Type::Integer, Type::Undefined) => (),
        (Type::Float | Type::Integer, Type::Integer | Type::Float) => (),
        (Type::Undefined, Type::Float) | (Type::Float, Type::Undefined) => (),
        (Type::String, Type::String) => (),
        (Type::Undefined, Type::String) | (Type::String, Type::Undefined) => (),
        (Type::Undefined, Type::Undefined) => (),
        _ => {
            return Err(nom::Err::Failure(Error::new(
                span,
                ErrorKind::ExpressionIncompatibleTypes {
                    left_type: left.ty.to_string(),
                    left_span: left.span,
                    right_type: right.ty.to_string(),
                    right_span: right.span,
                },
            )));
        }
    };

    Ok((Box::new(left.expr), Box::new(right.expr)))
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
        F: FnOnce(Box<Expression>, Box<Expression>) -> Expression,
        F2: FnOnce(Box<Expression>, Box<Expression>) -> Expression,
    {
        let input = format!("0 {} 1 {} 2", lower_op, higher_op);

        parse(
            boolean_expression,
            &input,
            "",
            ParsedExpr {
                expr: lower_constructor(
                    Box::new(Expression::Number(0)),
                    Box::new(higher_constructor(
                        Box::new(Expression::Number(1)),
                        Box::new(Expression::Number(2)),
                    )),
                ),
                ty: Type::Boolean,
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
                expr: Expression::VariableAt("a".to_owned(), Box::new(Expression::Number(100))),
                ty: Type::Boolean,
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
                    from: Box::new(Expression::Number(0)),
                    to: Box::new(Expression::Number(50)),
                },
                ty: Type::Boolean,
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
                    from: Box::new(Expression::Neg(Box::new(Expression::Number(10)))),
                    to: Box::new(Expression::Neg(Box::new(Expression::Number(5)))),
                },
                ty: Type::Boolean,
                span: 0..14,
            },
        );
        parse(
            variable_expression,
            "$c in (-10..-5",
            "in (-10..-5",
            ParsedExpr {
                expr: Expression::Variable("c".to_owned()),
                ty: Type::Boolean,
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
                    Box::new(Expression::Boolean(true)),
                    Box::new(Expression::Boolean(false)),
                ),
                ty: Type::Boolean,
                span: 0..14,
            },
        );
        parse(
            boolean_expression,
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
                span: 0..22,
            },
        );
        parse(
            boolean_expression,
            "not not true",
            "",
            ParsedExpr {
                expr: Expression::Not(Box::new(Expression::Not(Box::new(Expression::Boolean(
                    true,
                ))))),
                ty: Type::Boolean,
                span: 0..12,
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
                boolean_expression,
                &input,
                "b",
                ParsedExpr {
                    expr: constructor(
                        Box::new(Expression::String("a".to_owned())),
                        Box::new(Expression::String("b".to_owned())),
                    ),
                    ty: Type::Boolean,
                    span: Span {
                        start: 0,
                        end: 8 + op.len(),
                    },
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
            boolean_expression,
            "\"a\" matches /b/i b",
            "b",
            ParsedExpr {
                expr: Expression::Matches(
                    Box::new(Expression::String("a".to_owned())),
                    Regex {
                        expr: "b".to_owned(),
                        case_insensitive: true,
                        dot_all: false,
                    },
                ),
                ty: Type::Boolean,
                span: 0..16,
            },
        );

        parse_err(boolean_expression, "\"a\" matches");
        parse_err(boolean_expression, "\"a\" matches 1");
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
                    Box::new(Expression::Not(Box::new(Expression::Boolean(true)))),
                    Box::new(Expression::And(
                        Box::new(Expression::Boolean(false)),
                        Box::new(Expression::Boolean(true)),
                    )),
                ),
                ty: Type::Boolean,
                span: 0..26,
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
            boolean_expression,
            "true b",
            "b",
            ParsedExpr {
                expr: Expression::Boolean(true),
                ty: Type::Boolean,
                span: 0..4,
            },
        );
        parse(
            boolean_expression,
            "((false))",
            "",
            ParsedExpr {
                expr: Expression::Boolean(false),
                ty: Type::Boolean,
                span: 2..7,
            },
        );
        parse(
            boolean_expression,
            "not true b",
            "b",
            ParsedExpr {
                expr: Expression::Not(Box::new(Expression::Boolean(true))),
                ty: Type::Boolean,
                span: 0..8,
            },
        );
        parse(
            boolean_expression,
            "not defined $a  c",
            "c",
            ParsedExpr {
                expr: Expression::Not(Box::new(Expression::Defined(Box::new(
                    Expression::Variable("a".to_owned()),
                )))),
                ty: Type::Boolean,
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
                ty: Type::Integer,
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
                    Box::new(Expression::Number(0)),
                    Box::new(Expression::Number(0)),
                ),
                ty: Type::Boolean,
                span: 0..4,
            },
        );
        parse(
            boolean_expression,
            "1!=2",
            "",
            ParsedExpr {
                expr: Expression::Not(Box::new(Expression::Eq(
                    Box::new(Expression::Number(1)),
                    Box::new(Expression::Number(2)),
                ))),
                ty: Type::Boolean,
                span: 0..4,
            },
        );
    }
}
