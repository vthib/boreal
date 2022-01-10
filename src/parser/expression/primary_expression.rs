//! Parsing related to primary expressions.
//!
//! This implements the `primary_expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};

use super::super::{nom_recipes::rtrim, number, string};
use super::{nom_err_invalid_expression_type, read_integer, ParsedExpr, Type};
use crate::expression::Expression;

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
pub fn range(input: &str) -> IResult<&str, (ParsedExpr, ParsedExpr)> {
    let (input, _) = rtrim(char('('))(input)?;

    cut(terminated(
        separated_pair(primary_expression, rtrim(tag("..")), primary_expression),
        rtrim(char(')')),
    ))(input)
}

/// parse | operator
pub fn primary_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_bitwise_xor(input)?;

    while let Ok((i, _)) = rtrim(char('|'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_xor)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseOr(
                res.try_unwrap(input, Type::Integer)?,
                right_elem.try_unwrap(input, Type::Integer)?,
            ),
            ty: Type::Integer,
        }
    }
    Ok((input, res))
}

/// parse ^ operator
fn primary_expression_bitwise_xor(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_bitwise_and(input)?;

    while let Ok((i, _)) = rtrim(char('^'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_and)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseXor(
                res.try_unwrap(input, Type::Integer)?,
                right_elem.try_unwrap(input, Type::Integer)?,
            ),
            ty: Type::Integer,
        };
    }
    Ok((input, res))
}

/// parse & operator
fn primary_expression_bitwise_and(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_shift(input)?;

    while let Ok((i, _)) = rtrim(char('&'))(input) {
        let (i2, right_elem) = cut(primary_expression_shift)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseAnd(
                res.try_unwrap(input, Type::Integer)?,
                right_elem.try_unwrap(input, Type::Integer)?,
            ),
            ty: Type::Integer,
        }
    }
    Ok((input, res))
}

/// parse <<, >> operators
fn primary_expression_shift(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_add(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<<"), tag(">>"))))(input) {
        let (i2, right_elem) = cut(primary_expression_add)(i)?;
        input = i2;

        let left = res.try_unwrap(input, Type::Integer)?;
        let right = right_elem.try_unwrap(input, Type::Integer)?;
        res = ParsedExpr {
            expr: match op {
                "<<" => Expression::ShiftLeft(left, right),
                ">>" => Expression::ShiftRight(left, right),
                _ => unreachable!(),
            },
            ty: Type::Integer,
        }
    }
    Ok((input, res))
}

/// parse +, - operators
fn primary_expression_add(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_mul(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("+"), tag("-"))))(input) {
        let (i2, right_elem) = cut(primary_expression_mul)(i)?;
        input = i2;

        let ty = match (res.ty, right_elem.ty) {
            (Type::Integer, Type::Integer) => Type::Integer,
            (_, Type::Float) | (Type::Float, _) => Type::Float,
            _ => return Err(nom_err_invalid_expression_type(input, &res, Type::Integer)),
        };
        res = ParsedExpr {
            expr: match op {
                "+" => Expression::Add(Box::new(res.expr), Box::new(right_elem.expr)),
                "-" => Expression::Sub(Box::new(res.expr), Box::new(right_elem.expr)),
                _ => unreachable!(),
            },
            ty,
        }
    }
    Ok((input, res))
}

/// parse *, \, % operators
fn primary_expression_mul(input: &str) -> IResult<&str, ParsedExpr> {
    let (mut input, mut res) = primary_expression_neg(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("*"), tag("\\"), tag("%"))))(input) {
        let (i2, right_elem) = cut(primary_expression_neg)(i)?;
        input = i2;

        let ty = match (res.ty, right_elem.ty) {
            (Type::Integer, Type::Integer) => Type::Integer,
            (Type::Float, _) => {
                if op == "%" {
                    return Err(nom_err_invalid_expression_type(input, &res, Type::Integer));
                }
                Type::Float
            }
            (_, Type::Float) => {
                if op == "%" {
                    return Err(nom_err_invalid_expression_type(
                        input,
                        &right_elem,
                        Type::Integer,
                    ));
                }
                Type::Float
            }
            _ => return Err(nom_err_invalid_expression_type(input, &res, Type::Integer)),
        };
        res = ParsedExpr {
            expr: match op {
                "*" => Expression::Mul(Box::new(res.expr), Box::new(right_elem.expr)),
                "\\" => Expression::Div(Box::new(res.expr), Box::new(right_elem.expr)),
                "%" => Expression::Mod(Box::new(res.expr), Box::new(right_elem.expr)),
                _ => unreachable!(),
            },
            ty,
        }
    }
    Ok((input, res))
}

/// parse ~, - operators
fn primary_expression_neg(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, (op, expr)) =
        tuple((opt(alt((tag("~"), tag("-")))), primary_expression_item))(input)?;

    Ok((
        input,
        match op {
            None => expr,
            Some(op) => match op {
                "~" => ParsedExpr {
                    expr: Expression::BitwiseNot(expr.try_unwrap(input, Type::Integer)?),
                    ty: Type::Integer,
                },
                "-" => {
                    let ty = match expr.ty {
                        Type::Integer => Type::Integer,
                        Type::Float => Type::Float,
                        _ => {
                            return Err(nom_err_invalid_expression_type(
                                input,
                                &expr,
                                Type::Integer,
                            ))
                        }
                    };
                    ParsedExpr {
                        expr: Expression::Neg(Box::new(expr.expr)),
                        ty,
                    }
                }
                _ => unreachable!(),
            },
        },
    ))
}

fn primary_expression_item(input: &str) -> IResult<&str, ParsedExpr> {
    alt((
        // '(' primary_expression ')'
        delimited(
            rtrim(char('(')),
            cut(primary_expression),
            cut(rtrim(char(')'))),
        ),
        // 'filesize'
        map(rtrim(tag("filesize")), |_| ParsedExpr {
            expr: Expression::Filesize,
            ty: Type::Integer,
        }),
        // 'entrypoint'
        map(rtrim(tag("entrypoint")), |_| ParsedExpr {
            expr: Expression::Entrypoint,
            ty: Type::Integer,
        }),
        // read_integer '(' primary_expresion ')'
        read_integer::read_integer_expression,
        // double
        map(number::double, |v| ParsedExpr {
            expr: Expression::Double(v),
            ty: Type::Float,
        }),
        // number
        map(number::number, |v| ParsedExpr {
            expr: Expression::Number(v),
            ty: Type::Integer,
        }),
        // text string
        map(string::quoted, |v| ParsedExpr {
            expr: Expression::String(v),
            ty: Type::String,
        }),
        // regex
        map(string::regex, |v| ParsedExpr {
            expr: Expression::Regex(v),
            ty: Type::Regex,
        }),
        // string_count | string_count 'in' range
        string_count_expression,
        // string_offset | string_offset '[' primary_expression ']'
        string_offset_expression,
        // string_length | string_length '[' primary_expression ']'
        string_length_expression,
        // identifier
        // TODO: wrong rule
        map(string::identifier, |v| ParsedExpr {
            expr: Expression::Identifier(v),
            ty: Type::String,
        }),
    ))(input)
}

fn string_count_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, identifier) = string::count(input)?;
    let (input, range) = opt(preceded(rtrim(tag("in")), cut(range)))(input)?;

    let expr = match range {
        // string_count
        None => Expression::Count(identifier),
        // string_count 'in' range
        Some((a, b)) => Expression::CountInRange {
            identifier,
            from: a.try_unwrap(input, Type::Integer)?,
            to: b.try_unwrap(input, Type::Integer)?,
        },
    };
    Ok((
        input,
        ParsedExpr {
            expr,
            ty: Type::Integer,
        },
    ))
}

fn string_offset_expression(input: &str) -> IResult<&str, ParsedExpr> {
    // string_offset | string_offset '[' primary_expression ']'
    let (input, identifier) = string::offset(input)?;
    let (input, expr) = opt(delimited(
        rtrim(char('[')),
        cut(primary_expression),
        cut(rtrim(char(']'))),
    ))(input)?;

    let expr = Expression::Offset {
        identifier,
        occurence_number: match expr {
            Some(v) => v.try_unwrap(input, Type::Integer)?,
            None => Box::new(Expression::Number(1)),
        },
    };
    Ok((
        input,
        ParsedExpr {
            expr,
            ty: Type::Integer,
        },
    ))
}

fn string_length_expression(input: &str) -> IResult<&str, ParsedExpr> {
    // string_length | string_length '[' primary_expression ']'
    let (input, identifier) = string::length(input)?;
    let (input, expr) = opt(delimited(
        rtrim(char('[')),
        cut(primary_expression),
        cut(rtrim(char(']'))),
    ))(input)?;

    let expr = Expression::Length {
        identifier,
        occurence_number: match expr {
            Some(v) => v.try_unwrap(input, Type::Integer)?,
            None => Box::new(Expression::Number(1)),
        },
    };
    Ok((
        input,
        ParsedExpr {
            expr,
            ty: Type::Integer,
        },
    ))
}
#[cfg(test)]
mod tests {
    use crate::expression::ReadIntegerSize;

    use super::super::super::test_utils::{parse, parse_err};
    use super::{primary_expression as pe, range, Expression as Expr, ParsedExpr, Type};

    #[test]
    fn test_range() {
        parse(
            range,
            "(1..1) b",
            "b",
            (
                ParsedExpr {
                    expr: Expr::Number(1),
                    ty: Type::Integer,
                },
                ParsedExpr {
                    expr: Expr::Number(1),
                    ty: Type::Integer,
                },
            ),
        );
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (
                ParsedExpr {
                    expr: Expr::Filesize,
                    ty: Type::Integer,
                },
                ParsedExpr {
                    expr: Expr::Entrypoint,
                    ty: Type::Integer,
                },
            ),
        );

        parse_err(range, "");
        parse_err(range, "(");
        parse_err(range, "(1)");
        parse_err(range, "()");
        parse_err(range, "(..)");
        parse_err(range, "(1..)");
        parse_err(range, "(..1)");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_primary_expression() {
        parse(
            pe,
            "filesize a",
            "a",
            ParsedExpr {
                expr: Expr::Filesize,
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "( filesize) a",
            "a",
            ParsedExpr {
                expr: Expr::Filesize,
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "entrypoint a",
            "a",
            ParsedExpr {
                expr: Expr::Entrypoint,
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "uint8(3)",
            "",
            ParsedExpr {
                expr: Expr::ReadInteger {
                    unsigned: true,
                    size: ReadIntegerSize::Int8,
                    big_endian: false,
                    addr: Box::new(Expr::Number(3)),
                },
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "15  2",
            "2",
            ParsedExpr {
                expr: Expr::Number(15),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "0.25 c",
            "c",
            ParsedExpr {
                expr: Expr::Double(0.25),
                ty: Type::Float,
            },
        );
        parse(
            pe,
            "\"a\\nb \" b",
            "b",
            ParsedExpr {
                expr: Expr::String("a\nb ".to_owned()),
                ty: Type::String,
            },
        );
        parse(
            pe,
            "#foo bar",
            "bar",
            ParsedExpr {
                expr: Expr::Count("foo".to_owned()),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "#foo in (0 ..filesize ) c",
            "c",
            ParsedExpr {
                expr: Expr::CountInRange {
                    identifier: "foo".to_owned(),
                    from: Box::new(Expr::Number(0)),
                    to: Box::new(Expr::Filesize),
                },
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "@a c",
            "c",
            ParsedExpr {
                expr: Expr::Offset {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(1)),
                },
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "@a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expr::Offset {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(2)),
                },
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "!a c",
            "c",
            ParsedExpr {
                expr: Expr::Length {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(1)),
                },
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "!a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expr::Length {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(2)),
                },
                ty: Type::Integer,
            },
        );

        parse(
            pe,
            "a c",
            "c",
            ParsedExpr {
                expr: Expr::Identifier("a".to_owned()),
                ty: Type::String,
            },
        );
        parse(
            pe,
            "aze",
            "",
            ParsedExpr {
                expr: Expr::Identifier("aze".to_owned()),
                ty: Type::String,
            },
        );
        parse(
            pe,
            "/a*b$/i c",
            "c",
            ParsedExpr {
                expr: Expr::Regex(crate::regex::Regex {
                    expr: "a*b$".to_owned(),
                    case_insensitive: true,
                    dot_all: false,
                }),
                ty: Type::Regex,
            },
        );

        parse_err(pe, "");
        parse_err(pe, "(");
        parse_err(pe, "(a");
        parse_err(pe, "!a[1");
        parse_err(pe, "@a[1");
        parse_err(pe, "()");
        parse_err(pe, "int16");
        parse_err(pe, "uint32(");
        parse_err(pe, "uint32be ( 3");
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_primary_expression_associativity() {
        // Check handling of chain of operators, and associativity
        parse(
            pe,
            "1 + 2 - 3b",
            "b",
            ParsedExpr {
                expr: Expr::Sub(
                    Box::new(Expr::Add(
                        Box::new(Expr::Number(1)),
                        Box::new(Expr::Number(2)),
                    )),
                    Box::new(Expr::Number(3)),
                ),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "1 \\ 2 % 3 * 4",
            "",
            ParsedExpr {
                expr: Expr::Mul(
                    Box::new(Expr::Mod(
                        Box::new(Expr::Div(
                            Box::new(Expr::Number(1)),
                            Box::new(Expr::Number(2)),
                        )),
                        Box::new(Expr::Number(3)),
                    )),
                    Box::new(Expr::Number(4)),
                ),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "1 << 2 >> 3 << 4",
            "",
            ParsedExpr {
                expr: Expr::ShiftLeft(
                    Box::new(Expr::ShiftRight(
                        Box::new(Expr::ShiftLeft(
                            Box::new(Expr::Number(1)),
                            Box::new(Expr::Number(2)),
                        )),
                        Box::new(Expr::Number(3)),
                    )),
                    Box::new(Expr::Number(4)),
                ),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "1 & 2 & 3",
            "",
            ParsedExpr {
                expr: Expr::BitwiseAnd(
                    Box::new(Expr::BitwiseAnd(
                        Box::new(Expr::Number(1)),
                        Box::new(Expr::Number(2)),
                    )),
                    Box::new(Expr::Number(3)),
                ),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "1 ^ 2 ^ 3",
            "",
            ParsedExpr {
                expr: Expr::BitwiseXor(
                    Box::new(Expr::BitwiseXor(
                        Box::new(Expr::Number(1)),
                        Box::new(Expr::Number(2)),
                    )),
                    Box::new(Expr::Number(3)),
                ),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "1 | 2 | 3",
            "",
            ParsedExpr {
                expr: Expr::BitwiseOr(
                    Box::new(Expr::BitwiseOr(
                        Box::new(Expr::Number(1)),
                        Box::new(Expr::Number(2)),
                    )),
                    Box::new(Expr::Number(3)),
                ),
                ty: Type::Integer,
            },
        );

        // FIXME: simplify this into a negative number
        parse(
            pe,
            "-1--2",
            "",
            ParsedExpr {
                expr: Expr::Sub(
                    Box::new(Expr::Neg(Box::new(Expr::Number(1)))),
                    Box::new(Expr::Neg(Box::new(Expr::Number(2)))),
                ),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "~1^~2",
            "",
            ParsedExpr {
                expr: Expr::BitwiseXor(
                    Box::new(Expr::BitwiseNot(Box::new(Expr::Number(1)))),
                    Box::new(Expr::BitwiseNot(Box::new(Expr::Number(2)))),
                ),
                ty: Type::Integer,
            },
        );
    }

    #[test]
    fn test_primary_expression_precedence() {
        #[track_caller]
        fn test_precedence<F, F2>(
            higher_op: &str,
            lower_op: &str,
            higher_constructor: F,
            lower_constructor: F2,
        ) where
            F: FnOnce(Box<Expr>, Box<Expr>) -> Expr,
            F2: FnOnce(Box<Expr>, Box<Expr>) -> Expr,
        {
            let input = format!("1 {} 2 {} 3", lower_op, higher_op);

            parse(
                pe,
                &input,
                "",
                ParsedExpr {
                    expr: lower_constructor(
                        Box::new(Expr::Number(1)),
                        Box::new(higher_constructor(
                            Box::new(Expr::Number(2)),
                            Box::new(Expr::Number(3)),
                        )),
                    ),
                    ty: Type::Integer,
                },
            );
        }

        // Test precedence of *, \\, % over +, %
        test_precedence("*", "+", Expr::Mul, Expr::Add);
        test_precedence("*", "-", Expr::Mul, Expr::Sub);
        test_precedence("\\", "+", Expr::Div, Expr::Add);
        test_precedence("\\", "-", Expr::Div, Expr::Sub);
        test_precedence("%", "+", Expr::Mod, Expr::Add);
        test_precedence("%", "-", Expr::Mod, Expr::Sub);

        // Test precedence of *, \\, %, +, - over >>, <<
        test_precedence("*", ">>", Expr::Mul, Expr::ShiftRight);
        test_precedence("*", "<<", Expr::Mul, Expr::ShiftLeft);
        test_precedence("\\", ">>", Expr::Div, Expr::ShiftRight);
        test_precedence("\\", "<<", Expr::Div, Expr::ShiftLeft);
        test_precedence("%", ">>", Expr::Mod, Expr::ShiftRight);
        test_precedence("%", "<<", Expr::Mod, Expr::ShiftLeft);
        test_precedence("+", ">>", Expr::Add, Expr::ShiftRight);
        test_precedence("+", "<<", Expr::Add, Expr::ShiftLeft);
        test_precedence("-", ">>", Expr::Sub, Expr::ShiftRight);
        test_precedence("-", "<<", Expr::Sub, Expr::ShiftLeft);

        // Test precedence of *, \\, %, +, - over &, |, ^
        test_precedence("*", "&", Expr::Mul, Expr::BitwiseAnd);
        test_precedence("*", "^", Expr::Mul, Expr::BitwiseXor);
        test_precedence("*", "|", Expr::Mul, Expr::BitwiseOr);
        test_precedence("\\", "&", Expr::Div, Expr::BitwiseAnd);
        test_precedence("\\", "^", Expr::Div, Expr::BitwiseXor);
        test_precedence("\\", "|", Expr::Div, Expr::BitwiseOr);
        test_precedence("%", "&", Expr::Mod, Expr::BitwiseAnd);
        test_precedence("%", "^", Expr::Mod, Expr::BitwiseXor);
        test_precedence("%", "|", Expr::Mod, Expr::BitwiseOr);
        test_precedence("+", "&", Expr::Add, Expr::BitwiseAnd);
        test_precedence("+", "^", Expr::Add, Expr::BitwiseXor);
        test_precedence("+", "|", Expr::Add, Expr::BitwiseOr);
        test_precedence("-", "&", Expr::Sub, Expr::BitwiseAnd);
        test_precedence("-", "^", Expr::Sub, Expr::BitwiseXor);
        test_precedence("-", "|", Expr::Sub, Expr::BitwiseOr);
        test_precedence(">>", "&", Expr::ShiftRight, Expr::BitwiseAnd);
        test_precedence(">>", "^", Expr::ShiftRight, Expr::BitwiseXor);
        test_precedence(">>", "|", Expr::ShiftRight, Expr::BitwiseOr);
        test_precedence("<<", "&", Expr::ShiftLeft, Expr::BitwiseAnd);
        test_precedence("<<", "^", Expr::ShiftLeft, Expr::BitwiseXor);
        test_precedence("<<", "|", Expr::ShiftLeft, Expr::BitwiseOr);

        // Test precedence of & over |, ^
        test_precedence("&", "^", Expr::BitwiseAnd, Expr::BitwiseXor);
        test_precedence("&", "|", Expr::BitwiseAnd, Expr::BitwiseOr);

        // Test precedence of ^ over |
        test_precedence("^", "|", Expr::BitwiseXor, Expr::BitwiseOr);
    }

    #[test]
    fn test_primary_expression_precedence_global() {
        // global test on precedence
        let expected = Expr::BitwiseXor(
            Box::new(Expr::Add(
                Box::new(Expr::Number(1)),
                Box::new(Expr::Mul(
                    Box::new(Expr::Number(2)),
                    Box::new(Expr::Number(3)),
                )),
            )),
            Box::new(Expr::Sub(
                Box::new(Expr::Mod(
                    Box::new(Expr::Number(4)),
                    Box::new(Expr::Number(5)),
                )),
                Box::new(Expr::Number(6)),
            )),
        );

        parse(
            pe,
            "1 + 2 * 3 ^ 4 % 5 - 6",
            "",
            ParsedExpr {
                expr: expected.clone(),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "(1 + (2 * 3) ) ^ ((4)%5 - 6)",
            "",
            ParsedExpr {
                expr: expected,
                ty: Type::Integer,
            },
        );
    }

    #[test]
    fn test_types() {
        parse_err(pe, "uint8(/a/)");

        parse_err(pe, "1 | /a/");
        parse_err(pe, "/a/ | 1");
        parse_err(pe, "1 ^ /a/");
        parse_err(pe, "/a/ ^ 1");
        parse_err(pe, "1 & /a/");
        parse_err(pe, "/a/ & 1");
        parse_err(pe, "1.2 << 1");
        parse_err(pe, "1 << 1.2");
        parse_err(pe, "1.2 >> 1");
        parse_err(pe, "1 >> 1.2");

        parse_err(pe, "1 + /a/");
        parse_err(pe, "\"a\" + 1");
        parse_err(pe, "1 - /a/");
        parse_err(pe, "\"a\" - 1");

        parse_err(pe, "1 * /a/");
        parse_err(pe, "\"a\" * 1");

        parse_err(pe, "1 \\ /a/");
        parse_err(pe, "\"a\" \\ 1");

        parse_err(pe, "1 % 1.2");
        parse_err(pe, "1.2 % 1");

        parse_err(pe, "~1.2");
        parse_err(pe, "-/a/");
    }

    #[test]
    fn test_type_integer_or_float() {
        parse(
            pe,
            "1 + 1",
            "",
            ParsedExpr {
                expr: Expr::Add(Box::new(Expr::Number(1)), Box::new(Expr::Number(1))),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "1 + 1.2",
            "",
            ParsedExpr {
                expr: Expr::Add(Box::new(Expr::Number(1)), Box::new(Expr::Double(1.2))),
                ty: Type::Float,
            },
        );
        parse(
            pe,
            "1.2 + 1",
            "",
            ParsedExpr {
                expr: Expr::Add(Box::new(Expr::Double(1.2)), Box::new(Expr::Number(1))),
                ty: Type::Float,
            },
        );

        parse(
            pe,
            "-1",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(Expr::Number(1))),
                ty: Type::Integer,
            },
        );
        parse(
            pe,
            "-1.2",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(Expr::Double(1.2))),
                ty: Type::Float,
            },
        );
    }
}
