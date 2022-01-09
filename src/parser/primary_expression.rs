//! Parsing related to primary expressions.
//!
//! This implements the `primary_expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    error::{Error, ErrorKind, FromExternalError},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

use super::{nom_recipes::rtrim, number, string};
use crate::expression::{Expression, ReadIntegerSize};

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Type {
    Integer,
    Float,
    String,
    Regex,
    Boolean,
}

impl std::fmt::Display for Type {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(match self {
            Self::Integer => "integer",
            Self::Float => "floating-point number",
            Self::String => "string",
            Self::Regex => "regex",
            Self::Boolean => "boolean",
        })
    }
}

#[derive(PartialEq, Debug)]
pub struct ParsedExpr {
    pub expr: Expression,
    ty: Type,
}

impl ParsedExpr {
    fn try_unwrap<I>(
        self,
        input: I,
        expected_type: Type,
    ) -> Result<Box<Expression>, nom::Err<Error<I>>> {
        if self.ty == expected_type {
            Ok(Box::new(self.expr))
        } else {
            Err(nom::Err::Error(Error::from_external_error(
                input,
                ErrorKind::Verify,
                format!("{} expression expected", expected_type),
            )))
        }
    }
}

/// Parse a read of an integer.
///
/// Equivalent to the `_INTEGER_FUNCTION_` lexical pattern in libyara.
/// This is roughly equivalent to `u?int(8|16|32)(be)?`.
///
/// it returns a triple that consists of, in order:
/// - a boolean indicating the sign (true if unsigned).
/// - the size of the integer
/// - a boolean indicating the endianness (true if big-endian).
fn read_integer(input: &str) -> IResult<&str, (bool, ReadIntegerSize, bool)> {
    rtrim(tuple((
        map(opt(char('u')), |v| v.is_some()),
        alt((
            map(tag("int8"), |_| ReadIntegerSize::Int8),
            map(tag("int16"), |_| ReadIntegerSize::Int16),
            map(tag("int32"), |_| ReadIntegerSize::Int32),
        )),
        map(opt(tag("be")), |v| v.is_some()),
    )))(input)
}

fn read_integer_expression(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, ((unsigned, size, big_endian), expr)) = pair(
        read_integer,
        cut(delimited(
            rtrim(char('(')),
            primary_expression,
            rtrim(char(')')),
        )),
    )(input)?;

    Ok((
        input,
        ParsedExpr {
            expr: Expression::ReadInteger {
                unsigned,
                size,
                big_endian,
                addr: expr.try_unwrap(input, Type::Integer)?,
            },
            ty: Type::Integer,
        },
    ))
}

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

        let left = res.try_unwrap(input, Type::Integer)?;
        let right = right_elem.try_unwrap(input, Type::Integer)?;
        res = ParsedExpr {
            expr: match op {
                "+" => Expression::Add(left, right),
                "-" => Expression::Sub(left, right),
                _ => unreachable!(),
            },
            ty: Type::Integer,
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

        let left = res.try_unwrap(input, Type::Integer)?;
        let right = right_elem.try_unwrap(input, Type::Integer)?;
        res = ParsedExpr {
            expr: match op {
                "*" => Expression::Mul(left, right),
                "\\" => Expression::Div(left, right),
                "%" => Expression::Mod(left, right),
                _ => unreachable!(),
            },
            ty: Type::Integer,
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
            Some(op) => {
                let expr = expr.try_unwrap(input, Type::Integer)?;

                ParsedExpr {
                    expr: match op {
                        "~" => Expression::BitwiseNot(expr),
                        "-" => Expression::Neg(expr),
                        _ => unreachable!(),
                    },
                    ty: Type::Integer,
                }
            }
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
        read_integer_expression,
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
    use super::super::test_utils::{parse, parse_err};
    use super::{
        primary_expression as pe, range, read_integer, Expression as Expr, ParsedExpr,
        ReadIntegerSize as RIS, Type,
    };

    #[test]
    fn test_read_integer() {
        parse(read_integer, "int8b", "b", (false, RIS::Int8, false));
        parse(read_integer, "uint8 be", "be", (true, RIS::Int8, false));
        parse(read_integer, "int8bet", "t", (false, RIS::Int8, true));
        parse(read_integer, "uint8be", "", (true, RIS::Int8, true));

        parse(read_integer, "int16b", "b", (false, RIS::Int16, false));
        parse(read_integer, "uint16 be", "be", (true, RIS::Int16, false));
        parse(read_integer, "int16bet", "t", (false, RIS::Int16, true));
        parse(read_integer, "uint16be", "", (true, RIS::Int16, true));

        parse(read_integer, "int32b", "b", (false, RIS::Int32, false));
        parse(read_integer, "uint32 be", "be", (true, RIS::Int32, false));
        parse(read_integer, "int32bet", "t", (false, RIS::Int32, true));
        parse(read_integer, "uint32be", "", (true, RIS::Int32, true));

        parse_err(read_integer, "");
        parse_err(read_integer, "u");
        parse_err(read_integer, "uint");
        parse_err(read_integer, "int");
        parse_err(read_integer, "int9");
        parse_err(read_integer, "uint1");
    }

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
                    size: RIS::Int8,
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

    #[allow(clippy::too_many_lines)]
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

        // global test
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
}
