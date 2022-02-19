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

use super::{
    boolean_expression::boolean_expression, identifier, read_integer, string_expression,
    Expression, ParsedExpr, Type,
};
use crate::{
    error::{Error, ErrorKind},
    nom_recipes::{not_followed, rtrim, textual_tag as ttag},
    number, string,
    types::{Input, ParseResult, Span},
};

/// parse | operator
pub(super) fn primary_expression(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_bitwise_xor(input)?;

    // Use not_followed to ensure we do not eat the first character of the
    // || operator
    while let Ok((i, _)) = rtrim(not_followed(char('|'), char('|')))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_xor)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseOr(
                res.unwrap_expr(Type::Integer)?,
                right_elem.unwrap_expr(Type::Integer)?,
            ),
            ty: Type::Integer,
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
            expr: Expression::BitwiseXor(
                res.unwrap_expr(Type::Integer)?,
                right_elem.unwrap_expr(Type::Integer)?,
            ),
            ty: Type::Integer,
            span: input.get_span_from(start),
        };
    }
    Ok((input, res))
}

/// parse & operator
fn primary_expression_bitwise_and(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_shift(input)?;

    // Use not_followed to ensure we do not eat the first character of the
    // && operator
    while let Ok((i, _)) = rtrim(not_followed(char('&'), char('&')))(input) {
        let (i2, right_elem) = cut(primary_expression_shift)(i)?;
        input = i2;

        res = ParsedExpr {
            expr: Expression::BitwiseAnd(
                res.unwrap_expr(Type::Integer)?,
                right_elem.unwrap_expr(Type::Integer)?,
            ),
            ty: Type::Integer,
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

        let left = res.unwrap_expr(Type::Integer)?;
        let right = right_elem.unwrap_expr(Type::Integer)?;
        res = ParsedExpr {
            expr: match op.cursor() {
                "<<" => Expression::ShiftLeft(left, right),
                ">>" => Expression::ShiftRight(left, right),
                _ => unreachable!(),
            },
            ty: Type::Integer,
            span: input.get_span_from(start),
        }
    }
    Ok((input, res))
}

/// parse +, - operators
fn primary_expression_add(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (mut input, mut res) = primary_expression_mul(input)?;

    while let Ok((i, op)) = rtrim(alt((char('+'), char('-'))))(input) {
        let (i2, right_elem) = cut(primary_expression_mul)(i)?;
        input = i2;

        res = match op {
            '+' => validate_arith_operands(
                res,
                right_elem,
                input.get_span_from(start),
                Expression::Add,
            )?,
            '-' => validate_arith_operands(
                res,
                right_elem,
                input.get_span_from(start),
                Expression::Sub,
            )?,
            _ => unreachable!(),
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

        res = match op {
            '*' => validate_arith_operands(
                res,
                right_elem,
                input.get_span_from(start),
                Expression::Mul,
            )?,
            '\\' => validate_arith_operands(
                res,
                right_elem,
                input.get_span_from(start),
                Expression::Div,
            )?,
            '%' => ParsedExpr {
                expr: Expression::Mod(
                    res.unwrap_expr(Type::Integer)?,
                    right_elem.unwrap_expr(Type::Integer)?,
                ),
                span: input.get_span_from(start),
                ty: Type::Integer,
            },
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

fn validate_arith_operands<F>(
    left: ParsedExpr,
    right: ParsedExpr,
    span: Span,
    constructor: F,
) -> Result<ParsedExpr, nom::Err<Error>>
where
    F: Fn(Box<Expression>, Box<Expression>) -> Expression,
{
    let ty = match (left.ty, right.ty) {
        (Type::Integer, Type::Integer) => Type::Integer,
        (Type::Undefined, Type::Integer) | (Type::Integer, Type::Undefined) => Type::Integer,
        (Type::Float | Type::Integer, Type::Integer | Type::Float) => Type::Float,
        (Type::Undefined, Type::Float) | (Type::Float, Type::Undefined) => Type::Float,
        (Type::Undefined, Type::Undefined) => Type::Undefined,
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

    Ok(ParsedExpr {
        expr: constructor(Box::new(left.expr), Box::new(right.expr)),
        span,
        ty,
    })
}

/// parse ~, - operators
fn primary_expression_neg(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, op) = opt(alt((tag("~"), tag("-"))))(input)?;

    match op {
        None => primary_expression_item(input),
        Some(op) => {
            let (input, expr) = cut(primary_expression_neg)(input)?;
            Ok((
                input,
                match op.cursor() {
                    "~" => ParsedExpr {
                        expr: Expression::BitwiseNot(expr.unwrap_expr(Type::Integer)?),
                        ty: Type::Integer,
                        span: input.get_span_from(start),
                    },
                    "-" => {
                        if expr.ty == Type::Float {
                            ParsedExpr {
                                expr: Expression::Neg(Box::new(expr.expr)),
                                ty: Type::Float,
                                span: input.get_span_from(start),
                            }
                        } else {
                            ParsedExpr {
                                expr: Expression::Neg(expr.unwrap_expr(Type::Integer)?),
                                ty: Type::Integer,
                                span: input.get_span_from(start),
                            }
                        }
                    }
                    _ => unreachable!(),
                },
            ))
        }
    }
}

fn primary_expression_item(input: Input) -> ParseResult<ParsedExpr> {
    alt((
        // '(' primary_expression ')'
        delimited(
            rtrim(char('(')),
            cut(boolean_expression),
            cut(rtrim(char(')'))),
        ),
        // 'true'
        map_expr(
            rtrim(ttag("true")),
            |_| Expression::Boolean(true),
            Type::Boolean,
        ),
        // 'false'
        map_expr(
            rtrim(ttag("false")),
            |_| Expression::Boolean(false),
            Type::Boolean,
        ),
        // 'filesize'
        map_expr(
            rtrim(ttag("filesize")),
            |_| Expression::Filesize,
            Type::Integer,
        ),
        // 'entrypoint'
        map_expr(
            rtrim(ttag("entrypoint")),
            |_| Expression::Entrypoint,
            Type::Integer,
        ),
        // read_integer '(' primary_expresion ')'
        read_integer::read_integer_expression,
        // double
        map_expr(number::double, Expression::Double, Type::Float),
        // number
        map_expr(number::number, Expression::Number, Type::Integer),
        // text string
        map_expr(string::quoted, Expression::String, Type::String),
        // regex
        map_expr(string::regex, Expression::Regex, Type::Regex),
        // string_count | string_count 'in' range
        string_expression::string_count_expression,
        // string_offset | string_offset '[' primary_expression ']'
        string_expression::string_offset_expression,
        // string_length | string_length '[' primary_expression ']'
        string_expression::string_length_expression,
        // identifier
        // TODO: wrong type
        map_expr(
            identifier::identifier,
            Expression::Identifier,
            Type::Undefined,
        ),
    ))(input)
}

fn map_expr<'a, F, C, O>(
    mut f: F,
    constructor: C,
    ty: Type,
) -> impl FnMut(Input<'a>) -> ParseResult<'a, ParsedExpr>
where
    F: Parser<Input<'a>, O, Error>,
    C: Fn(O) -> Expression,
{
    move |input| {
        let start = input;
        let (input, output) = f.parse(input)?;
        Ok((
            input,
            ParsedExpr {
                expr: constructor(output),
                ty,
                span: input.get_span_from(start),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Identifier;
    use super::{primary_expression as pe, Expression as Expr, ParsedExpr};
    use crate::expression::Type;
    use crate::{
        expression::ReadIntegerSize,
        string::Regex,
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
                ty: Type::Integer,
                span: 0..8,
            },
        );
        parse(
            pe,
            "( filesize) a",
            "a",
            ParsedExpr {
                expr: Expr::Filesize,
                ty: Type::Integer,
                span: 2..10,
            },
        );
        parse(
            pe,
            "entrypoint a",
            "a",
            ParsedExpr {
                expr: Expr::Entrypoint,
                ty: Type::Integer,
                span: 0..10,
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
                span: 0..8,
            },
        );
        parse(
            pe,
            "15  2",
            "2",
            ParsedExpr {
                expr: Expr::Number(15),
                ty: Type::Integer,
                span: 0..2,
            },
        );
        parse(
            pe,
            "0.25 c",
            "c",
            ParsedExpr {
                expr: Expr::Double(0.25),
                ty: Type::Float,
                span: 0..4,
            },
        );
        parse(
            pe,
            "\"a\\nb \" b",
            "b",
            ParsedExpr {
                expr: Expr::String("a\nb ".to_owned()),
                ty: Type::String,
                span: 0..7,
            },
        );
        parse(
            pe,
            "#foo bar",
            "bar",
            ParsedExpr {
                expr: Expr::Count("foo".to_owned()),
                ty: Type::Integer,
                span: 0..4,
            },
        );
        parse(
            pe,
            "#foo in (0 ..filesize ) c",
            "c",
            ParsedExpr {
                expr: Expr::CountInRange {
                    variable_name: "foo".to_owned(),
                    from: Box::new(Expr::Number(0)),
                    to: Box::new(Expr::Filesize),
                },
                ty: Type::Integer,
                span: 0..23,
            },
        );
        parse(
            pe,
            "@a c",
            "c",
            ParsedExpr {
                expr: Expr::Offset {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(1)),
                },
                ty: Type::Integer,
                span: 0..2,
            },
        );
        parse(
            pe,
            "@a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expr::Offset {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(2)),
                },
                ty: Type::Integer,
                span: 0..7,
            },
        );
        parse(
            pe,
            "!a c",
            "c",
            ParsedExpr {
                expr: Expr::Length {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(1)),
                },
                ty: Type::Integer,
                span: 0..2,
            },
        );
        parse(
            pe,
            "!a [ 2] c",
            "c",
            ParsedExpr {
                expr: Expr::Length {
                    variable_name: "a".to_owned(),
                    occurence_number: Box::new(Expr::Number(2)),
                },
                ty: Type::Integer,
                span: 0..7,
            },
        );

        parse(
            pe,
            "a c",
            "c",
            ParsedExpr {
                expr: Expr::Identifier(Identifier::Raw("a".to_owned())),
                ty: Type::Undefined,
                span: 0..1,
            },
        );
        parse(
            pe,
            "aze",
            "",
            ParsedExpr {
                expr: Expr::Identifier(Identifier::Raw("aze".to_owned())),
                ty: Type::Undefined,
                span: 0..3,
            },
        );
        parse(
            pe,
            "/a*b$/i c",
            "c",
            ParsedExpr {
                expr: Expr::Regex(Regex {
                    expr: "a*b$".to_owned(),
                    case_insensitive: true,
                    dot_all: false,
                }),
                ty: Type::Regex,
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
                span: 0..9,
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
                span: 0..13,
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
                span: 0..16,
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
                span: 0..9,
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
                span: 0..9,
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
                span: 0..9,
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
                span: 0..5,
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
                span: 0..5,
            },
        );
        parse(
            pe,
            "-~-1",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(Expr::BitwiseNot(Box::new(Expr::Neg(Box::new(
                    Expr::Number(1),
                )))))),
                ty: Type::Integer,
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
                ),
                ty: Type::Integer,
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
            ParsedExpr {
                expr: Expr::Add(Box::new(Expr::Number(1)), Box::new(Expr::Number(1))),
                ty: Type::Integer,
                span: 0..5,
            },
        );
        parse(
            pe,
            "1 + 1.2",
            "",
            ParsedExpr {
                expr: Expr::Add(Box::new(Expr::Number(1)), Box::new(Expr::Double(1.2))),
                ty: Type::Float,
                span: 0..7,
            },
        );
        parse(
            pe,
            "1.2 + 1",
            "",
            ParsedExpr {
                expr: Expr::Add(Box::new(Expr::Double(1.2)), Box::new(Expr::Number(1))),
                ty: Type::Float,
                span: 0..7,
            },
        );

        parse(
            pe,
            "-1",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(Expr::Number(1))),
                ty: Type::Integer,
                span: 0..2,
            },
        );
        parse(
            pe,
            "-1.2",
            "",
            ParsedExpr {
                expr: Expr::Neg(Box::new(Expr::Double(1.2))),
                ty: Type::Float,
                span: 0..4,
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
