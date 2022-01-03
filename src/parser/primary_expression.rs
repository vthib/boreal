//! Parsing related to primary expressions.
//!
//! This implements the `primary_expression` element in grammar.y in libyara.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    sequence::{delimited, pair, separated_pair, terminated, tuple},
    IResult,
};

use super::{nom_recipes::rtrim, number, string};
use crate::expression::{Expression, ReadIntegerSize};

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

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

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
fn range(input: &str) -> IResult<&str, (Expression, Expression)> {
    let (input, _) = rtrim(char('('))(input)?;

    cut(terminated(
        separated_pair(primary_expression, rtrim(tag("..")), primary_expression),
        rtrim(char(')')),
    ))(input)
}

/// parse | operator
fn primary_expression(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression_bitwise_xor(input)?;

    while let Ok((i, _)) = rtrim(char('|'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_xor)(i)?;
        input = i2;
        res = Expression::BitwiseOr(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse ^ operator
fn primary_expression_bitwise_xor(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression_bitwise_and(input)?;

    while let Ok((i, _)) = rtrim(char('^'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_and)(i)?;
        input = i2;
        res = Expression::BitwiseXor(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse & operator
fn primary_expression_bitwise_and(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression_shift(input)?;

    while let Ok((i, _)) = rtrim(char('&'))(input) {
        let (i2, right_elem) = cut(primary_expression_shift)(i)?;
        input = i2;
        res = Expression::BitwiseAnd(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse <<, >> operators
fn primary_expression_shift(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression_add(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<<"), tag(">>"))))(input) {
        let (i2, right_elem) = cut(primary_expression_add)(i)?;
        input = i2;
        res = match op {
            "<<" => Expression::ShiftLeft(Box::new(res), Box::new(right_elem)),
            ">>" => Expression::ShiftRight(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

/// parse +, - operators
fn primary_expression_add(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression_mul(input)?;

    while let Ok((i, op)) = rtrim(alt((char('+'), char('-'))))(input) {
        let (i2, right_elem) = cut(primary_expression_mul)(i)?;
        input = i2;
        res = match op {
            '+' => Expression::Add(Box::new(res), Box::new(right_elem)),
            '-' => Expression::Sub(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

/// parse *, \, % operators
fn primary_expression_mul(input: &str) -> IResult<&str, Expression> {
    let (mut input, mut res) = primary_expression_neg(input)?;

    while let Ok((i, op)) = rtrim(alt((char('*'), char('\\'), char('%'))))(input) {
        let (i2, right_elem) = cut(primary_expression_neg)(i)?;
        input = i2;
        res = match op {
            '*' => Expression::Mul(Box::new(res), Box::new(right_elem)),
            '\\' => Expression::Div(Box::new(res), Box::new(right_elem)),
            '%' => Expression::Mod(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

/// parse ~, - operators
fn primary_expression_neg(input: &str) -> IResult<&str, Expression> {
    map(
        tuple((opt(alt((char('~'), char('-')))), primary_expression_item)),
        |(unary_op, expr)| match unary_op {
            Some('~') => Expression::BitwiseNot(Box::new(expr)),
            Some('-') => Expression::Neg(Box::new(expr)),
            _ => expr,
        },
    )(input)
}

fn primary_expression_item(input: &str) -> IResult<&str, Expression> {
    alt((
        // '(' primary_expression ')'
        delimited(
            rtrim(char('(')),
            cut(primary_expression),
            cut(rtrim(char(')'))),
        ),
        // 'filesize'
        map(rtrim(tag("filesize")), |_| Expression::Filesize),
        // 'entrypoint'
        map(rtrim(tag("entrypoint")), |_| Expression::Entrypoint),
        // read_integer '(' primary_expresion ')'
        map(
            pair(
                read_integer,
                cut(delimited(
                    rtrim(char('(')),
                    primary_expression,
                    rtrim(char(')')),
                )),
            ),
            |((unsigned, size, big_endian), expr)| Expression::ReadInteger {
                unsigned,
                size,
                big_endian,
                addr: Box::new(expr),
            },
        ),
        // double
        map(number::double, Expression::Double),
        // number
        map(number::number, Expression::Number),
        // text string
        map(string::quoted, Expression::String),
        // regex
        map(string::regex, Expression::Regex),
        // string_count 'in' range
        map(
            separated_pair(string::count, rtrim(tag("in")), cut(range)),
            |(identifier, (a, b))| Expression::CountInRange {
                identifier,
                from: Box::new(a),
                to: Box::new(b),
            },
        ),
        // string_count
        map(string::count, Expression::Count),
        // string_offset | string_offset '[' primary_expression ']'
        map(
            pair(
                string::offset,
                opt(delimited(
                    rtrim(char('[')),
                    cut(primary_expression),
                    cut(rtrim(char(']'))),
                )),
            ),
            |(identifier, expr)| Expression::Offset {
                identifier,
                occurence_number: Box::new(expr.unwrap_or(Expression::Number(1))),
            },
        ),
        // string_length | string_length '[' primary_expression ']'
        map(
            pair(
                string::length,
                opt(delimited(
                    rtrim(char('[')),
                    cut(primary_expression),
                    cut(rtrim(char(']'))),
                )),
            ),
            |(identifier, expr)| Expression::Length {
                identifier,
                occurence_number: Box::new(expr.unwrap_or(Expression::Number(1))),
            },
        ),
        // identifier
        // TODO: wrong rule
        map(string::identifier, Expression::Identifier),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::{parse, parse_err};
    use super::{
        primary_expression as pe, range, read_integer, Expression as Expr, ReadIntegerSize as RIS,
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
        parse(range, "(1..1) b", "b", (Expr::Number(1), Expr::Number(1)));
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (Expr::Filesize, Expr::Entrypoint),
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
        parse(pe, "filesize a", "a", Expr::Filesize);
        parse(pe, "( filesize) a", "a", Expr::Filesize);
        parse(pe, "entrypoint a", "a", Expr::Entrypoint);
        parse(
            pe,
            "uint8(3)",
            "",
            Expr::ReadInteger {
                unsigned: true,
                size: RIS::Int8,
                big_endian: false,
                addr: Box::new(Expr::Number(3)),
            },
        );
        parse(pe, "15  2", "2", Expr::Number(15));
        parse(pe, "0.25 c", "c", Expr::Double(0.25));
        parse(pe, "\"a\\nb \" b", "b", Expr::String("a\nb ".to_owned()));
        parse(pe, "#foo bar", "bar", Expr::Count("foo".to_owned()));
        parse(
            pe,
            "#foo in (0 ..filesize ) c",
            "c",
            Expr::CountInRange {
                identifier: "foo".to_owned(),
                from: Box::new(Expr::Number(0)),
                to: Box::new(Expr::Filesize),
            },
        );
        parse(
            pe,
            "@a c",
            "c",
            Expr::Offset {
                identifier: "a".to_owned(),
                occurence_number: Box::new(Expr::Number(1)),
            },
        );
        parse(
            pe,
            "@a [ 2] c",
            "c",
            Expr::Offset {
                identifier: "a".to_owned(),
                occurence_number: Box::new(Expr::Number(2)),
            },
        );
        parse(
            pe,
            "!a c",
            "c",
            Expr::Length {
                identifier: "a".to_owned(),
                occurence_number: Box::new(Expr::Number(1)),
            },
        );
        parse(
            pe,
            "!a [ 2] c",
            "c",
            Expr::Length {
                identifier: "a".to_owned(),
                occurence_number: Box::new(Expr::Number(2)),
            },
        );

        parse(pe, "a c", "c", Expr::Identifier("a".to_owned()));
        parse(pe, "aze", "", Expr::Identifier("aze".to_owned()));
        parse(
            pe,
            "/a*b$/i c",
            "c",
            Expr::Regex(crate::regex::Regex {
                expr: "a*b$".to_owned(),
                case_insensitive: true,
                dot_all: false,
            }),
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
            Expr::Sub(
                Box::new(Expr::Add(
                    Box::new(Expr::Number(1)),
                    Box::new(Expr::Number(2)),
                )),
                Box::new(Expr::Number(3)),
            ),
        );
        parse(
            pe,
            "1 \\ 2 % 3 * 4",
            "",
            Expr::Mul(
                Box::new(Expr::Mod(
                    Box::new(Expr::Div(
                        Box::new(Expr::Number(1)),
                        Box::new(Expr::Number(2)),
                    )),
                    Box::new(Expr::Number(3)),
                )),
                Box::new(Expr::Number(4)),
            ),
        );
        parse(
            pe,
            "1 << 2 >> 3 << 4",
            "",
            Expr::ShiftLeft(
                Box::new(Expr::ShiftRight(
                    Box::new(Expr::ShiftLeft(
                        Box::new(Expr::Number(1)),
                        Box::new(Expr::Number(2)),
                    )),
                    Box::new(Expr::Number(3)),
                )),
                Box::new(Expr::Number(4)),
            ),
        );
        parse(
            pe,
            "1 & 2 & 3",
            "",
            Expr::BitwiseAnd(
                Box::new(Expr::BitwiseAnd(
                    Box::new(Expr::Number(1)),
                    Box::new(Expr::Number(2)),
                )),
                Box::new(Expr::Number(3)),
            ),
        );
        parse(
            pe,
            "1 ^ 2 ^ 3",
            "",
            Expr::BitwiseXor(
                Box::new(Expr::BitwiseXor(
                    Box::new(Expr::Number(1)),
                    Box::new(Expr::Number(2)),
                )),
                Box::new(Expr::Number(3)),
            ),
        );
        parse(
            pe,
            "1 | 2 | 3",
            "",
            Expr::BitwiseOr(
                Box::new(Expr::BitwiseOr(
                    Box::new(Expr::Number(1)),
                    Box::new(Expr::Number(2)),
                )),
                Box::new(Expr::Number(3)),
            ),
        );

        parse(
            pe,
            "-1--2",
            "",
            Expr::Sub(
                Box::new(Expr::Neg(Box::new(Expr::Number(1)))),
                Box::new(Expr::Neg(Box::new(Expr::Number(2)))),
            ),
        );
        parse(
            pe,
            "~1^~2",
            "",
            Expr::BitwiseXor(
                Box::new(Expr::BitwiseNot(Box::new(Expr::Number(1)))),
                Box::new(Expr::BitwiseNot(Box::new(Expr::Number(2)))),
            ),
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
                lower_constructor(
                    Box::new(Expr::Number(1)),
                    Box::new(higher_constructor(
                        Box::new(Expr::Number(2)),
                        Box::new(Expr::Number(3)),
                    )),
                ),
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

        parse(pe, "1 + 2 * 3 ^ 4 % 5 - 6", "", expected.clone());
        parse(pe, "(1 + (2 * 3) ) ^ ((4)%5 - 6)", "", expected);
    }
}
