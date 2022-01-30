//! Parsing related to primary expressions.
//!
//! This implements the `primary_expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, opt, peek},
    sequence::{delimited, tuple},
};

use super::{
    common::map_expr, identifier, read_integer, string_expression, Expression, ParsedExpr,
};
use crate::parser::{
    nom_recipes::{rtrim, textual_tag as ttag},
    number, string,
    types::{Input, ParseResult},
};

/// parse | operator
pub fn primary_expression(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_bitwise_xor(input)?;

    while let Ok((i, _)) = rtrim(char('|'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_xor)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseOr(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse ^ operator
fn primary_expression_bitwise_xor(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_bitwise_and(input)?;

    while let Ok((i, _)) = rtrim(char('^'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_and)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseXor(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        };
    }
    Ok((input, res))
}

/// parse & operator
fn primary_expression_bitwise_and(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_shift(input)?;

    while let Ok((i, _)) = rtrim(char('&'))(input) {
        let (i2, right_elem) = cut(primary_expression_shift)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseAnd(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse <<, >> operators
fn primary_expression_shift(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_add(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<<"), tag(">>"))))(input) {
        let (i2, right_elem) = cut(primary_expression_add)(i)?;
        input = i2;

        let left = Box::new(res);
        let right = Box::new(right_elem);
        res = ParsedExpr {
            expr: match op.cursor() {
                "<<" => Expression::ShiftLeft(left, right),
                ">>" => Expression::ShiftRight(left, right),
                _ => unreachable!(),
            },
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse +, - operators
fn primary_expression_add(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_mul(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("+"), tag("-"))))(input) {
        let (i2, right_elem) = cut(primary_expression_mul)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: match op.cursor() {
                "+" => Expression::Add(Box::new(res), Box::new(right_elem)),
                "-" => Expression::Sub(Box::new(res), Box::new(right_elem)),
                _ => unreachable!(),
            },
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse *, \, % operators
fn primary_expression_mul(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_neg(input)?;

    while let Ok((i, op)) = rtrim(alt((char('*'), char('\\'), char('%'))))(input) {
        if op == '%' {
            // XXX: workaround issue with parsing the for as_percent expression:
            // - '50% of them'
            //   => should parse the expression as '50', not as '50' mod 'of'
            // Not sure how yacc manages to properly handle those rules, but
            // I have no easy solution for this in nom.
            let (_, of) = opt(peek(ttag("of")))(i)?;
            if of.is_some() {
                return Ok((input, res));
            }
        }

        let (i2, right_elem) = primary_expression_neg(i)?;
        input = i2;

        res = ParsedExpr {
            expr: match op {
                '*' => Expression::Mul(Box::new(res), Box::new(right_elem)),
                '\\' => Expression::Div(Box::new(res), Box::new(right_elem)),
                '%' => Expression::Mod(Box::new(res), Box::new(right_elem)),
                _ => unreachable!(),
            },
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse ~, - operators
fn primary_expression_neg(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, (op, expr)) =
        tuple((opt(alt((tag("~"), tag("-")))), primary_expression_item))(input)?;

    Ok((
        input,
        match op {
            None => expr,
            Some(op) => match op.cursor() {
                "~" => ParsedExpr {
                    expr: Expression::BitwiseNot(Box::new(expr)),
                    span: input.get_span_from(start),
                },
                "-" => ParsedExpr {
                    expr: Expression::Neg(Box::new(expr)),
                    span: input.get_span_from(start),
                },
                _ => unreachable!(),
            },
        },
    ))
}

fn primary_expression_item(input: Input) -> ParseResult<ParsedExpr> {
    alt((
        // '(' primary_expression ')'
        delimited(
            rtrim(char('(')),
            cut(primary_expression),
            cut(rtrim(char(')'))),
        ),
        // 'filesize'
        map_expr(rtrim(ttag("filesize")), |_| Expression::Filesize),
        // 'entrypoint'
        map_expr(rtrim(ttag("entrypoint")), |_| Expression::Entrypoint),
        // read_integer '(' primary_expresion ')'
        read_integer::read_integer_expression,
        // double
        map_expr(number::double, Expression::Double),
        // number
        map_expr(number::number, Expression::Number),
        // text string
        map_expr(string::quoted, Expression::String),
        // regex
        map_expr(string::regex, Expression::Regex),
        // string_count | string_count 'in' range
        string_expression::string_count_expression,
        // string_offset | string_offset '[' primary_expression ']'
        string_expression::string_offset_expression,
        // string_length | string_length '[' primary_expression ']'
        string_expression::string_length_expression,
        // identifier
        // TODO: wrong type
        map_expr(identifier::identifier, Expression::Identifier),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::super::Identifier;
    use super::{primary_expression as pe, Expression as Expr, ParsedExpr};
    use crate::expression::ReadIntegerSize;
    use crate::parser::{
        tests::{parse, parse_check, parse_err},
        types::Span,
    };

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_primary_expression() {
        parse(
            pe,
            "filesize a",
            "a",
            ParsedExpr {
                expr: Expr::Filesize,
                span: Span { start: 0, end: 8 },
            },
        );
        parse(
            pe,
            "( filesize) a",
            "a",
            ParsedExpr {
                expr: Expr::Filesize,
                span: Span { start: 2, end: 10 },
            },
        );
        parse(
            pe,
            "entrypoint a",
            "a",
            ParsedExpr {
                expr: Expr::Entrypoint,
                span: Span { start: 0, end: 10 },
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
                    addr: Box::new(ParsedExpr {
                        expr: Expr::Number(3),
                        span: Span { start: 6, end: 7 },
                    }),
                },
                span: Span { start: 0, end: 8 },
            },
        );
        parse(
            pe,
            "15  2",
            "2",
            ParsedExpr {
                expr: Expr::Number(15),
                span: Span { start: 0, end: 2 },
            },
        );
        parse(
            pe,
            "0.25 c",
            "c",
            ParsedExpr {
                expr: Expr::Double(0.25),
                span: Span { start: 0, end: 4 },
            },
        );
        parse(
            pe,
            "\"a\\nb \" b",
            "b",
            ParsedExpr {
                expr: Expr::String("a\nb ".to_owned()),
                span: Span { start: 0, end: 7 },
            },
        );
        parse(
            pe,
            "#foo bar",
            "bar",
            ParsedExpr {
                expr: Expr::Count("foo".to_owned()),
                span: Span { start: 0, end: 4 },
            },
        );
        parse(
            pe,
            "#foo in (0 ..filesize ) c",
            "c",
            ParsedExpr {
                expr: Expr::CountInRange {
                    identifier: "foo".to_owned(),
                    from: Box::new(ParsedExpr {
                        expr: Expr::Number(0),
                        span: Span { start: 9, end: 10 },
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expr::Filesize,
                        span: Span { start: 13, end: 21 },
                    }),
                },
                span: Span { start: 0, end: 23 },
            },
        );
        parse(
            pe,
            "@a c",
            "c",
            ParsedExpr {
                expr: Expr::Offset {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expr::Number(1),
                        span: Span { start: 0, end: 2 },
                    }),
                },
                span: Span { start: 0, end: 2 },
            },
        );
        parse(
            pe,
            "@a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expr::Offset {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expr::Number(2),
                        span: Span { start: 5, end: 6 },
                    }),
                },
                span: Span { start: 0, end: 7 },
            },
        );
        parse(
            pe,
            "!a c",
            "c",
            ParsedExpr {
                expr: Expr::Length {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expr::Number(1),
                        span: Span { start: 0, end: 2 },
                    }),
                },
                span: Span { start: 0, end: 2 },
            },
        );
        parse(
            pe,
            "!a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expr::Length {
                    identifier: "a".to_owned(),
                    occurence_number: Box::new(ParsedExpr {
                        expr: Expr::Number(2),
                        span: Span { start: 5, end: 6 },
                    }),
                },
                span: Span { start: 0, end: 7 },
            },
        );

        parse(
            pe,
            "a c",
            "c",
            ParsedExpr {
                expr: Expr::Identifier(Identifier::Raw("a".to_owned())),
                span: Span { start: 0, end: 1 },
            },
        );
        parse(
            pe,
            "aze",
            "",
            ParsedExpr {
                expr: Expr::Identifier(Identifier::Raw("aze".to_owned())),
                span: Span { start: 0, end: 3 },
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
                span: Span { start: 0, end: 7 },
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
                    Box::new(ParsedExpr {
                        expr: Expr::Add(
                            Box::new(ParsedExpr {
                                expr: Expr::Number(1),
                                span: Span { start: 0, end: 1 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(2),
                                span: Span { start: 4, end: 5 },
                            }),
                        ),
                        span: Span { start: 0, end: 5 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(3),
                        span: Span { start: 8, end: 9 },
                    }),
                ),
                span: Span { start: 0, end: 9 },
            },
        );
        parse(
            pe,
            "1 \\ 2 % 3 * 4",
            "",
            ParsedExpr {
                expr: Expr::Mul(
                    Box::new(ParsedExpr {
                        expr: Expr::Mod(
                            Box::new(ParsedExpr {
                                expr: Expr::Div(
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(1),
                                        span: Span { start: 0, end: 1 },
                                    }),
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(2),
                                        span: Span { start: 4, end: 5 },
                                    }),
                                ),
                                span: Span { start: 0, end: 5 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(3),
                                span: Span { start: 8, end: 9 },
                            }),
                        ),
                        span: Span { start: 0, end: 9 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(4),
                        span: Span { start: 12, end: 13 },
                    }),
                ),
                span: Span { start: 0, end: 13 },
            },
        );
        parse(
            pe,
            "1 << 2 >> 3 << 4",
            "",
            ParsedExpr {
                expr: Expr::ShiftLeft(
                    Box::new(ParsedExpr {
                        expr: Expr::ShiftRight(
                            Box::new(ParsedExpr {
                                expr: Expr::ShiftLeft(
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(1),
                                        span: Span { start: 0, end: 1 },
                                    }),
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(2),
                                        span: Span { start: 5, end: 6 },
                                    }),
                                ),
                                span: Span { start: 0, end: 6 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(3),
                                span: Span { start: 10, end: 11 },
                            }),
                        ),
                        span: Span { start: 0, end: 11 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(4),
                        span: Span { start: 15, end: 16 },
                    }),
                ),
                span: Span { start: 0, end: 16 },
            },
        );
        parse(
            pe,
            "1 & 2 & 3",
            "",
            ParsedExpr {
                expr: Expr::BitwiseAnd(
                    Box::new(ParsedExpr {
                        expr: Expr::BitwiseAnd(
                            Box::new(ParsedExpr {
                                expr: Expr::Number(1),
                                span: Span { start: 0, end: 1 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(2),
                                span: Span { start: 4, end: 5 },
                            }),
                        ),
                        span: Span { start: 0, end: 5 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(3),
                        span: Span { start: 8, end: 9 },
                    }),
                ),
                span: Span { start: 0, end: 9 },
            },
        );
        parse(
            pe,
            "1 ^ 2 ^ 3",
            "",
            ParsedExpr {
                expr: Expr::BitwiseXor(
                    Box::new(ParsedExpr {
                        expr: Expr::BitwiseXor(
                            Box::new(ParsedExpr {
                                expr: Expr::Number(1),
                                span: Span { start: 0, end: 1 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(2),
                                span: Span { start: 4, end: 5 },
                            }),
                        ),
                        span: Span { start: 0, end: 5 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(3),
                        span: Span { start: 8, end: 9 },
                    }),
                ),
                span: Span { start: 0, end: 9 },
            },
        );
        parse(
            pe,
            "1 | 2 | 3",
            "",
            ParsedExpr {
                expr: Expr::BitwiseOr(
                    Box::new(ParsedExpr {
                        expr: Expr::BitwiseOr(
                            Box::new(ParsedExpr {
                                expr: Expr::Number(1),
                                span: Span { start: 0, end: 1 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(2),
                                span: Span { start: 4, end: 5 },
                            }),
                        ),
                        span: Span { start: 0, end: 5 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(3),
                        span: Span { start: 8, end: 9 },
                    }),
                ),
                span: Span { start: 0, end: 9 },
            },
        );

        // FIXME: simplify this into a negative number
        parse(
            pe,
            "-1--2",
            "",
            ParsedExpr {
                expr: Expr::Sub(
                    Box::new(ParsedExpr {
                        expr: Expr::Neg(Box::new(ParsedExpr {
                            expr: Expr::Number(1),
                            span: Span { start: 1, end: 2 },
                        })),
                        span: Span { start: 0, end: 2 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Neg(Box::new(ParsedExpr {
                            expr: Expr::Number(2),
                            span: Span { start: 4, end: 5 },
                        })),
                        span: Span { start: 3, end: 5 },
                    }),
                ),
                span: Span { start: 0, end: 5 },
            },
        );
        parse(
            pe,
            "~1^~2",
            "",
            ParsedExpr {
                expr: Expr::BitwiseXor(
                    Box::new(ParsedExpr {
                        expr: Expr::BitwiseNot(Box::new(ParsedExpr {
                            expr: Expr::Number(1),
                            span: Span { start: 1, end: 2 },
                        })),
                        span: Span { start: 0, end: 2 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::BitwiseNot(Box::new(ParsedExpr {
                            expr: Expr::Number(2),
                            span: Span { start: 4, end: 5 },
                        })),
                        span: Span { start: 3, end: 5 },
                    }),
                ),
                span: Span { start: 0, end: 5 },
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
            F: FnOnce(Box<ParsedExpr>, Box<ParsedExpr>) -> Expr,
            F2: FnOnce(Box<ParsedExpr>, Box<ParsedExpr>) -> Expr,
        {
            let input = format!("1 {} 2 {} 3", lower_op, higher_op);

            parse(
                pe,
                &input,
                "",
                ParsedExpr {
                    expr: lower_constructor(
                        Box::new(ParsedExpr {
                            expr: Expr::Number(1),
                            span: Span { start: 0, end: 1 },
                        }),
                        Box::new(ParsedExpr {
                            expr: higher_constructor(
                                Box::new(ParsedExpr {
                                    expr: Expr::Number(2),
                                    span: Span {
                                        start: 3 + lower_op.len(),
                                        end: 4 + lower_op.len(),
                                    },
                                }),
                                Box::new(ParsedExpr {
                                    expr: Expr::Number(3),
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
        parse(
            pe,
            "1 + 2 * 3 ^ 4 % 5 - 6",
            "",
            ParsedExpr {
                expr: Expr::BitwiseXor(
                    Box::new(ParsedExpr {
                        expr: Expr::Add(
                            Box::new(ParsedExpr {
                                expr: Expr::Number(1),
                                span: Span { start: 0, end: 1 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Mul(
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(2),
                                        span: Span { start: 4, end: 5 },
                                    }),
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(3),
                                        span: Span { start: 8, end: 9 },
                                    }),
                                ),
                                span: Span { start: 4, end: 9 },
                            }),
                        ),
                        span: Span { start: 0, end: 9 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Sub(
                            Box::new(ParsedExpr {
                                expr: Expr::Mod(
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(4),
                                        span: Span { start: 12, end: 13 },
                                    }),
                                    Box::new(ParsedExpr {
                                        expr: Expr::Number(5),
                                        span: Span { start: 16, end: 17 },
                                    }),
                                ),
                                span: Span { start: 12, end: 17 },
                            }),
                            Box::new(ParsedExpr {
                                expr: Expr::Number(6),
                                span: Span { start: 20, end: 21 },
                            }),
                        ),
                        span: Span { start: 12, end: 21 },
                    }),
                ),
                span: Span { start: 0, end: 21 },
            },
        );
    }

    #[test]
    fn test_type_integer_or_float() {
        parse(
            pe,
            "1 + 1",
            "",
            ParsedExpr {
                expr: Expr::Add(
                    Box::new(ParsedExpr {
                        expr: Expr::Number(1),
                        span: Span { start: 0, end: 1 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(1),
                        span: Span { start: 4, end: 5 },
                    }),
                ),
                span: Span { start: 0, end: 5 },
            },
        );
        parse(
            pe,
            "1 + 1.2",
            "",
            ParsedExpr {
                expr: Expr::Add(
                    Box::new(ParsedExpr {
                        expr: Expr::Number(1),
                        span: Span { start: 0, end: 1 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Double(1.2),
                        span: Span { start: 4, end: 7 },
                    }),
                ),
                span: Span { start: 0, end: 7 },
            },
        );
        parse(
            pe,
            "1.2 + 1",
            "",
            ParsedExpr {
                expr: Expr::Add(
                    Box::new(ParsedExpr {
                        expr: Expr::Double(1.2),
                        span: Span { start: 0, end: 3 },
                    }),
                    Box::new(ParsedExpr {
                        expr: Expr::Number(1),
                        span: Span { start: 6, end: 7 },
                    }),
                ),
                span: Span { start: 0, end: 7 },
            },
        );

        parse(
            pe,
            "-1",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(ParsedExpr {
                    expr: Expr::Number(1),
                    span: Span { start: 1, end: 2 },
                })),
                span: Span { start: 0, end: 2 },
            },
        );
        parse(
            pe,
            "-1.2",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(ParsedExpr {
                    expr: Expr::Double(1.2),
                    span: Span { start: 1, end: 4 },
                })),
                span: Span { start: 0, end: 4 },
            },
        );
    }

    #[test]
    fn test_textual_tag() {
        parse_check(pe, "filesizea", |e| {
            assert_eq!(
                e.expr,
                Expr::Identifier(Identifier::Raw("filesizea".to_owned()))
            );
        });
        parse_check(pe, "entrypointa", |e| {
            assert_eq!(
                e.expr,
                Expr::Identifier(Identifier::Raw("entrypointa".to_owned()))
            );
        });
    }
}
