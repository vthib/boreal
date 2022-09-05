//! Parsing related to primary expressions.
//!
//! This implements the `primary_expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, opt, peek},
    sequence::delimited,
    Parser,
};

use super::{expression, identifier, read_integer, string_expression, Expression, ExpressionKind};
use crate::{
    nom_recipes::{rtrim, textual_tag as ttag},
    number, regex, string,
    types::{Input, ParseResult},
};

/// parse | operator
pub fn primary_expression(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (mut input, mut res) = primary_expression_bitwise_xor(input)?;

    while let Ok((i, _)) = rtrim(char('|'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_xor)(i)?;
        input = i2;

        res = Expression {
            expr: ExpressionKind::BitwiseOr(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse ^ operator
fn primary_expression_bitwise_xor(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (mut input, mut res) = primary_expression_bitwise_and(input)?;

    while let Ok((i, _)) = rtrim(char('^'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_and)(i)?;
        input = i2;

        res = Expression {
            expr: ExpressionKind::BitwiseXor(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        };
    }
    Ok((input, res))
}

/// parse & operator
fn primary_expression_bitwise_and(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (mut input, mut res) = primary_expression_shift(input)?;

    while let Ok((i, _)) = rtrim(char('&'))(input) {
        let (i2, right_elem) = cut(primary_expression_shift)(i)?;
        input = i2;

        res = Expression {
            expr: ExpressionKind::BitwiseAnd(Box::new(res), Box::new(right_elem)),
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse <<, >> operators
fn primary_expression_shift(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (mut input, mut res) = primary_expression_add(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<<"), tag(">>"))))(input) {
        let (i2, right_elem) = cut(primary_expression_add)(i)?;
        input = i2;

        let left = Box::new(res);
        let right = Box::new(right_elem);
        res = Expression {
            expr: match op.cursor() {
                "<<" => ExpressionKind::ShiftLeft(left, right),
                ">>" => ExpressionKind::ShiftRight(left, right),
                _ => unreachable!(),
            },
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse +, - operators
fn primary_expression_add(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (mut input, mut res) = primary_expression_mul(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("+"), tag("-"))))(input) {
        let (i2, right_elem) = cut(primary_expression_mul)(i)?;
        input = i2;

        res = Expression {
            expr: match op.cursor() {
                "+" => ExpressionKind::Add(Box::new(res), Box::new(right_elem)),
                "-" => ExpressionKind::Sub(Box::new(res), Box::new(right_elem)),
                _ => unreachable!(),
            },
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse *, \, % operators
fn primary_expression_mul(input: Input) -> ParseResult<Expression> {
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

        res = Expression {
            expr: match op {
                '*' => ExpressionKind::Mul(Box::new(res), Box::new(right_elem)),
                '\\' => ExpressionKind::Div(Box::new(res), Box::new(right_elem)),
                '%' => ExpressionKind::Mod(Box::new(res), Box::new(right_elem)),
                _ => unreachable!(),
            },
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse ~, - operators
fn primary_expression_neg(mut input: Input) -> ParseResult<Expression> {
    let mut start = input;
    let mut ops = Vec::new();
    // Push ops into a vec, to prevent a possible stack overflow if we used recursion.
    while let Ok((i, op)) = rtrim(alt((char('~'), char('-'))))(input) {
        ops.push((
            if op == '~' {
                ExpressionKind::BitwiseNot
            } else {
                ExpressionKind::Neg
            },
            start,
        ));
        input = i;
        start = i;
    }

    let (input, mut expr) = primary_expression_item(input)?;
    while let Some((op, start)) = ops.pop() {
        expr = Expression {
            expr: op(Box::new(expr)),
            span: input.get_span_from(start),
        };
    }

    Ok((input, expr))
}

fn primary_expression_item(input: Input) -> ParseResult<Expression> {
    alt((
        // '(' primary_expression ')'
        delimited(rtrim(char('(')), cut(expression), cut(rtrim(char(')')))),
        // 'true'
        map_expr(rtrim(ttag("true")), |_| ExpressionKind::Boolean(true)),
        // 'false'
        map_expr(rtrim(ttag("false")), |_| ExpressionKind::Boolean(false)),
        // 'filesize'
        map_expr(rtrim(ttag("filesize")), |_| ExpressionKind::Filesize),
        // 'entrypoint'
        map_expr(rtrim(ttag("entrypoint")), |_| ExpressionKind::Entrypoint),
        // read_integer '(' primary_expresion ')'
        read_integer::read_integer_expression,
        // double
        map_expr(number::double, ExpressionKind::Double),
        // number
        map_expr(number::number, ExpressionKind::Integer),
        // text string
        map_expr(string::quoted, ExpressionKind::Bytes),
        // regex
        map_expr(regex::regex, ExpressionKind::Regex),
        // string_count | string_count 'in' range
        string_expression::string_count_expression,
        // string_offset | string_offset '[' primary_expression ']'
        string_expression::string_offset_expression,
        // string_length | string_length '[' primary_expression ']'
        string_expression::string_length_expression,
        // identifier
        map_expr(identifier::identifier, ExpressionKind::Identifier),
    ))(input)
}

fn map_expr<'a, F, C, O>(
    mut f: F,
    constructor: C,
) -> impl FnMut(Input<'a>) -> ParseResult<'a, Expression>
where
    F: Parser<Input<'a>, O, crate::Error>,
    C: Fn(O) -> ExpressionKind,
{
    move |input| {
        let start = input;
        let (input, output) = f.parse(input)?;
        Ok((
            input,
            Expression {
                expr: constructor(output),
                span: input.get_span_from(start),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Identifier;
    use super::{primary_expression as pe, Expression, ExpressionKind as Expr};
    use crate::regex::{AssertionKind, Node, RepetitionKind};
    use crate::{
        expression::ReadIntegerType,
        regex::Regex,
        tests::{parse, parse_check, parse_err},
    };
    use std::ops::Range;

    #[test]
    fn test_primary_expression() {
        parse(
            pe,
            "filesize a",
            "a",
            Expression {
                expr: Expr::Filesize,
                span: 0..8,
            },
        );
        parse(
            pe,
            "( filesize) a",
            "a",
            Expression {
                expr: Expr::Filesize,
                span: 2..10,
            },
        );
        parse(
            pe,
            "entrypoint a",
            "a",
            Expression {
                expr: Expr::Entrypoint,
                span: 0..10,
            },
        );
        parse(
            pe,
            "uint8(3)",
            "",
            Expression {
                expr: Expr::ReadInteger {
                    ty: ReadIntegerType::Uint8,
                    addr: Box::new(Expression {
                        expr: Expr::Integer(3),
                        span: 6..7,
                    }),
                },
                span: 0..8,
            },
        );
        parse(
            pe,
            "15  2",
            "2",
            Expression {
                expr: Expr::Integer(15),
                span: 0..2,
            },
        );
        parse(
            pe,
            "0.25 c",
            "c",
            Expression {
                expr: Expr::Double(0.25),
                span: 0..4,
            },
        );
        parse(
            pe,
            "\"a\\nb \" b",
            "b",
            Expression {
                expr: Expr::Bytes(b"a\nb ".to_vec()),
                span: 0..7,
            },
        );
        parse(
            pe,
            "#foo bar",
            "bar",
            Expression {
                expr: Expr::Count("foo".to_owned()),
                span: 0..4,
            },
        );
        parse(
            pe,
            "#foo in (0 ..filesize ) c",
            "c",
            Expression {
                expr: Expr::CountInRange {
                    variable_name: "foo".to_owned(),
                    variable_name_span: 0..4,
                    from: Box::new(Expression {
                        expr: Expr::Integer(0),
                        span: 9..10,
                    }),
                    to: Box::new(Expression {
                        expr: Expr::Filesize,
                        span: 13..21,
                    }),
                },
                span: 0..23,
            },
        );
        parse(
            pe,
            "@a c",
            "c",
            Expression {
                expr: Expr::Offset {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: Expr::Integer(1),
                        span: 0..2,
                    }),
                },
                span: 0..2,
            },
        );
        parse(
            pe,
            "@a [ 2] c",
            "c",
            Expression {
                expr: Expr::Offset {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: Expr::Integer(2),
                        span: 5..6,
                    }),
                },
                span: 0..7,
            },
        );
        parse(
            pe,
            "!a c",
            "c",
            Expression {
                expr: Expr::Length {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: Expr::Integer(1),
                        span: 0..2,
                    }),
                },
                span: 0..2,
            },
        );
        parse(
            pe,
            "!a [ 2] c",
            "c",
            Expression {
                expr: Expr::Length {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expression {
                        expr: Expr::Integer(2),
                        span: 5..6,
                    }),
                },
                span: 0..7,
            },
        );

        parse(
            pe,
            "a c",
            "c",
            Expression {
                expr: Expr::Identifier(Identifier {
                    name: "a".to_owned(),
                    name_span: 0..1,
                    operations: vec![],
                }),
                span: 0..1,
            },
        );
        parse(
            pe,
            "aze",
            "",
            Expression {
                expr: Expr::Identifier(Identifier {
                    name: "aze".to_owned(),
                    name_span: 0..3,
                    operations: vec![],
                }),
                span: 0..3,
            },
        );
        parse(
            pe,
            "/a*b$/i c",
            "c",
            Expression {
                expr: Expr::Regex(Regex {
                    ast: Node::Concat(vec![
                        Node::Repetition {
                            node: Box::new(Node::Literal(b'a')),
                            kind: RepetitionKind::ZeroOrMore,
                            greedy: true,
                        },
                        Node::Literal(b'b'),
                        Node::Assertion(AssertionKind::EndLine),
                    ]),
                    case_insensitive: true,
                    dot_all: false,
                    span: 0..7,
                }),
                span: 0..7,
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

    #[test]
    fn test_primary_expression_associativity() {
        // Check handling of chain of operators, and associativity
        parse(
            pe,
            "1 + 2 - 3b",
            "b",
            Expression {
                expr: Expr::Sub(
                    Box::new(Expression {
                        expr: Expr::Add(
                            Box::new(Expression {
                                expr: Expr::Integer(1),
                                span: 0..1,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(2),
                                span: 4..5,
                            }),
                        ),
                        span: 0..5,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(3),
                        span: 8..9,
                    }),
                ),
                span: 0..9,
            },
        );
        parse(
            pe,
            "1 \\ 2 % 3 * 4",
            "",
            Expression {
                expr: Expr::Mul(
                    Box::new(Expression {
                        expr: Expr::Mod(
                            Box::new(Expression {
                                expr: Expr::Div(
                                    Box::new(Expression {
                                        expr: Expr::Integer(1),
                                        span: 0..1,
                                    }),
                                    Box::new(Expression {
                                        expr: Expr::Integer(2),
                                        span: 4..5,
                                    }),
                                ),
                                span: 0..5,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(3),
                                span: 8..9,
                            }),
                        ),
                        span: 0..9,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(4),
                        span: 12..13,
                    }),
                ),
                span: 0..13,
            },
        );
        parse(
            pe,
            "1 << 2 >> 3 << 4",
            "",
            Expression {
                expr: Expr::ShiftLeft(
                    Box::new(Expression {
                        expr: Expr::ShiftRight(
                            Box::new(Expression {
                                expr: Expr::ShiftLeft(
                                    Box::new(Expression {
                                        expr: Expr::Integer(1),
                                        span: 0..1,
                                    }),
                                    Box::new(Expression {
                                        expr: Expr::Integer(2),
                                        span: 5..6,
                                    }),
                                ),
                                span: 0..6,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(3),
                                span: 10..11,
                            }),
                        ),
                        span: 0..11,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(4),
                        span: 15..16,
                    }),
                ),
                span: 0..16,
            },
        );
        parse(
            pe,
            "1 & 2 & 3",
            "",
            Expression {
                expr: Expr::BitwiseAnd(
                    Box::new(Expression {
                        expr: Expr::BitwiseAnd(
                            Box::new(Expression {
                                expr: Expr::Integer(1),
                                span: 0..1,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(2),
                                span: 4..5,
                            }),
                        ),
                        span: 0..5,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(3),
                        span: 8..9,
                    }),
                ),
                span: 0..9,
            },
        );
        parse(
            pe,
            "1 ^ 2 ^ 3",
            "",
            Expression {
                expr: Expr::BitwiseXor(
                    Box::new(Expression {
                        expr: Expr::BitwiseXor(
                            Box::new(Expression {
                                expr: Expr::Integer(1),
                                span: 0..1,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(2),
                                span: 4..5,
                            }),
                        ),
                        span: 0..5,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(3),
                        span: 8..9,
                    }),
                ),
                span: 0..9,
            },
        );
        parse(
            pe,
            "1 | 2 | 3",
            "",
            Expression {
                expr: Expr::BitwiseOr(
                    Box::new(Expression {
                        expr: Expr::BitwiseOr(
                            Box::new(Expression {
                                expr: Expr::Integer(1),
                                span: 0..1,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(2),
                                span: 4..5,
                            }),
                        ),
                        span: 0..5,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(3),
                        span: 8..9,
                    }),
                ),
                span: 0..9,
            },
        );

        parse(
            pe,
            "-1--2",
            "",
            Expression {
                expr: Expr::Sub(
                    Box::new(Expression {
                        expr: Expr::Neg(Box::new(Expression {
                            expr: Expr::Integer(1),
                            span: 1..2,
                        })),
                        span: 0..2,
                    }),
                    Box::new(Expression {
                        expr: Expr::Neg(Box::new(Expression {
                            expr: Expr::Integer(2),
                            span: 4..5,
                        })),
                        span: 3..5,
                    }),
                ),
                span: 0..5,
            },
        );
        parse(
            pe,
            "~1^~2",
            "",
            Expression {
                expr: Expr::BitwiseXor(
                    Box::new(Expression {
                        expr: Expr::BitwiseNot(Box::new(Expression {
                            expr: Expr::Integer(1),
                            span: 1..2,
                        })),
                        span: 0..2,
                    }),
                    Box::new(Expression {
                        expr: Expr::BitwiseNot(Box::new(Expression {
                            expr: Expr::Integer(2),
                            span: 4..5,
                        })),
                        span: 3..5,
                    }),
                ),
                span: 0..5,
            },
        );
        parse(
            pe,
            "-~-1",
            "",
            Expression {
                expr: Expr::Neg(Box::new(Expression {
                    expr: Expr::BitwiseNot(Box::new(Expression {
                        expr: Expr::Neg(Box::new(Expression {
                            expr: Expr::Integer(1),
                            span: 3..4,
                        })),
                        span: 2..4,
                    })),
                    span: 1..4,
                })),
                span: 0..4,
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
            F: FnOnce(Box<Expression>, Box<Expression>) -> Expr,
            F2: FnOnce(Box<Expression>, Box<Expression>) -> Expr,
        {
            let input = format!("1 {} 2 {} 3", lower_op, higher_op);

            parse(
                pe,
                &input,
                "",
                Expression {
                    expr: lower_constructor(
                        Box::new(Expression {
                            expr: Expr::Integer(1),
                            span: 0..1,
                        }),
                        Box::new(Expression {
                            expr: higher_constructor(
                                Box::new(Expression {
                                    expr: Expr::Integer(2),
                                    span: Range {
                                        start: 3 + lower_op.len(),
                                        end: 4 + lower_op.len(),
                                    },
                                }),
                                Box::new(Expression {
                                    expr: Expr::Integer(3),
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
            Expression {
                expr: Expr::BitwiseXor(
                    Box::new(Expression {
                        expr: Expr::Add(
                            Box::new(Expression {
                                expr: Expr::Integer(1),
                                span: 0..1,
                            }),
                            Box::new(Expression {
                                expr: Expr::Mul(
                                    Box::new(Expression {
                                        expr: Expr::Integer(2),
                                        span: 4..5,
                                    }),
                                    Box::new(Expression {
                                        expr: Expr::Integer(3),
                                        span: 8..9,
                                    }),
                                ),
                                span: 4..9,
                            }),
                        ),
                        span: 0..9,
                    }),
                    Box::new(Expression {
                        expr: Expr::Sub(
                            Box::new(Expression {
                                expr: Expr::Mod(
                                    Box::new(Expression {
                                        expr: Expr::Integer(4),
                                        span: 12..13,
                                    }),
                                    Box::new(Expression {
                                        expr: Expr::Integer(5),
                                        span: 16..17,
                                    }),
                                ),
                                span: 12..17,
                            }),
                            Box::new(Expression {
                                expr: Expr::Integer(6),
                                span: 20..21,
                            }),
                        ),
                        span: 12..21,
                    }),
                ),
                span: 0..21,
            },
        );
    }

    #[test]
    fn test_type_integer_or_float() {
        parse(
            pe,
            "1 + 1",
            "",
            Expression {
                expr: Expr::Add(
                    Box::new(Expression {
                        expr: Expr::Integer(1),
                        span: 0..1,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(1),
                        span: 4..5,
                    }),
                ),
                span: 0..5,
            },
        );
        parse(
            pe,
            "1 + 1.2",
            "",
            Expression {
                expr: Expr::Add(
                    Box::new(Expression {
                        expr: Expr::Integer(1),
                        span: 0..1,
                    }),
                    Box::new(Expression {
                        expr: Expr::Double(1.2),
                        span: 4..7,
                    }),
                ),
                span: 0..7,
            },
        );
        parse(
            pe,
            "1.2 + 1",
            "",
            Expression {
                expr: Expr::Add(
                    Box::new(Expression {
                        expr: Expr::Double(1.2),
                        span: 0..3,
                    }),
                    Box::new(Expression {
                        expr: Expr::Integer(1),
                        span: 6..7,
                    }),
                ),
                span: 0..7,
            },
        );

        parse(
            pe,
            "-1",
            "",
            Expression {
                expr: Expr::Neg(Box::new(Expression {
                    expr: Expr::Integer(1),
                    span: 1..2,
                })),
                span: 0..2,
            },
        );
        parse(
            pe,
            "-1.2",
            "",
            Expression {
                expr: Expr::Neg(Box::new(Expression {
                    expr: Expr::Double(1.2),
                    span: 1..4,
                })),
                span: 0..4,
            },
        );
    }

    #[test]
    fn test_textual_tag() {
        parse_check(pe, "filesizea", |e| {
            assert_eq!(
                e.expr,
                Expr::Identifier(Identifier {
                    name: "filesizea".to_owned(),
                    name_span: 0..9,
                    operations: vec![],
                }),
            );
        });
        parse_check(pe, "entrypointa", |e| {
            assert_eq!(
                e.expr,
                Expr::Identifier(Identifier {
                    name: "entrypointa".to_owned(),
                    name_span: 0..11,
                    operations: vec![],
                }),
            );
        });
    }
}
