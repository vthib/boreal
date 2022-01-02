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

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

/// Size of the integer to read, see [`PrimaryExpression::ReadInteger`].
#[derive(Clone, Debug, PartialEq)]
pub enum ReadIntegerSize {
    /// 8 bits
    Int8,
    /// 16 bits
    Int16,
    /// 32 bits
    Int32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrimaryExpression {
    /// Size of the file being analyzed.
    Filesize,
    /// Entrypoint address if the file is executable.
    Entrypoint,
    /// Read an integer at the given position.
    ReadInteger {
        /// size of the integer to read.
        size: ReadIntegerSize,
        /// Is the integer unsigned.
        unsigned: bool,
        /// Use big-endian to read the integer, instead of little-endian.
        big_endian: bool,
        /// Offset or virtual address at which to read the integer.
        addr: Box<PrimaryExpression>,
    },
    /// A literal number.
    Number(i64),
    /// A literal floating-point number.
    Double(f64),
    /// A literal string.
    String(String),
    /// Is the number of occurences of an identifier in a given range.
    CountInRange {
        /// The identifier being counted.
        identifier: String,
        /// From value, included.
        from: Box<PrimaryExpression>,
        /// To value, included.
        to: Box<PrimaryExpression>,
    },
    /// Count number of occurences of an identifier.
    Count(String),
    /// Offset of an occurence of an identifier.
    Offset {
        /// Identifier to find the offset of.
        identifier: String,
        /// Which occurence of the identifier to look for.
        ///
        /// This starts at 1:
        ///  - 1: first occurence
        ///  - 2: second occurence
        ///  ...
        occurence_number: Box<PrimaryExpression>,
    },
    /// String length of an occurence of an identifier.
    Length {
        /// Identifier to find the length of.
        identifier: String,
        /// Which occurence of the identifier to look for.
        ///
        /// This starts at 1:
        ///  - 1: first occurence
        ///  - 2: second occurence
        ///  ...
        occurence_number: Box<PrimaryExpression>,
    },
    /// A raw identifier.
    Identifier {
        /// Name of the identifier.
        name: String,
        /// True if a wildcard was used at the end of the identifier.
        ///
        /// e.g. `Rule*`
        wildcard_at_end: bool,
    },
    /// Negation
    Neg(Box<PrimaryExpression>),
    /// Addition
    Add(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Substraction
    Sub(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Multiplication
    Mul(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Division
    Div(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Modulo
    Mod(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Bitwise Xor
    BitwiseXor(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Bitwise and
    BitwiseAnd(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Bitwise or
    BitwiseOr(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Bitwise not
    BitwiseNot(Box<PrimaryExpression>),
    /// Shift left
    ShiftLeft(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Shift right
    ShiftRight(Box<PrimaryExpression>, Box<PrimaryExpression>),
    /// Regex
    Regex(string::Regex),
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

/// Parse a 'in' range for primary expressions.
///
/// Equivalent to the range pattern in grammar.y in libyara.
fn range(input: &str) -> IResult<&str, (PrimaryExpression, PrimaryExpression)> {
    let (input, _) = rtrim(char('('))(input)?;

    cut(terminated(
        separated_pair(primary_expression, rtrim(tag("..")), primary_expression),
        rtrim(char(')')),
    ))(input)
}

/// parse | operator
fn primary_expression(input: &str) -> IResult<&str, PrimaryExpression> {
    let (mut input, mut res) = primary_expression_bitwise_xor(input)?;

    while let Ok((i, _)) = rtrim(char('|'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_xor)(i)?;
        input = i2;
        res = PrimaryExpression::BitwiseOr(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse ^ operator
fn primary_expression_bitwise_xor(input: &str) -> IResult<&str, PrimaryExpression> {
    let (mut input, mut res) = primary_expression_bitwise_and(input)?;

    while let Ok((i, _)) = rtrim(char('^'))(input) {
        let (i2, right_elem) = cut(primary_expression_bitwise_and)(i)?;
        input = i2;
        res = PrimaryExpression::BitwiseXor(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse & operator
fn primary_expression_bitwise_and(input: &str) -> IResult<&str, PrimaryExpression> {
    let (mut input, mut res) = primary_expression_shift(input)?;

    while let Ok((i, _)) = rtrim(char('&'))(input) {
        let (i2, right_elem) = cut(primary_expression_shift)(i)?;
        input = i2;
        res = PrimaryExpression::BitwiseAnd(Box::new(res), Box::new(right_elem));
    }
    Ok((input, res))
}

/// parse <<, >> operators
fn primary_expression_shift(input: &str) -> IResult<&str, PrimaryExpression> {
    let (mut input, mut res) = primary_expression_add(input)?;

    while let Ok((i, op)) = rtrim(alt((tag("<<"), tag(">>"))))(input) {
        let (i2, right_elem) = cut(primary_expression_add)(i)?;
        input = i2;
        res = match op {
            "<<" => PrimaryExpression::ShiftLeft(Box::new(res), Box::new(right_elem)),
            ">>" => PrimaryExpression::ShiftRight(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

/// parse +, - operators
fn primary_expression_add(input: &str) -> IResult<&str, PrimaryExpression> {
    let (mut input, mut res) = primary_expression_mul(input)?;

    while let Ok((i, op)) = rtrim(alt((char('+'), char('-'))))(input) {
        let (i2, right_elem) = cut(primary_expression_mul)(i)?;
        input = i2;
        res = match op {
            '+' => PrimaryExpression::Add(Box::new(res), Box::new(right_elem)),
            '-' => PrimaryExpression::Sub(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

/// parse *, \, % operators
fn primary_expression_mul(input: &str) -> IResult<&str, PrimaryExpression> {
    let (mut input, mut res) = primary_expression_neg(input)?;

    while let Ok((i, op)) = rtrim(alt((char('*'), char('\\'), char('%'))))(input) {
        let (i2, right_elem) = cut(primary_expression_neg)(i)?;
        input = i2;
        res = match op {
            '*' => PrimaryExpression::Mul(Box::new(res), Box::new(right_elem)),
            '\\' => PrimaryExpression::Div(Box::new(res), Box::new(right_elem)),
            '%' => PrimaryExpression::Mod(Box::new(res), Box::new(right_elem)),
            _ => unreachable!(),
        }
    }
    Ok((input, res))
}

/// parse ~, - operators
fn primary_expression_neg(input: &str) -> IResult<&str, PrimaryExpression> {
    map(
        tuple((opt(alt((char('~'), char('-')))), primary_expression_item)),
        |(unary_op, expr)| match unary_op {
            Some('~') => PrimaryExpression::BitwiseNot(Box::new(expr)),
            Some('-') => PrimaryExpression::Neg(Box::new(expr)),
            _ => expr,
        },
    )(input)
}

fn primary_expression_item(input: &str) -> IResult<&str, PrimaryExpression> {
    alt((
        // '(' primary_expression ')'
        delimited(
            rtrim(char('(')),
            cut(primary_expression),
            cut(rtrim(char(')'))),
        ),
        // 'filesize'
        map(rtrim(tag("filesize")), |_| PrimaryExpression::Filesize),
        // 'entrypoint'
        map(rtrim(tag("entrypoint")), |_| PrimaryExpression::Entrypoint),
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
            |((unsigned, size, big_endian), expr)| PrimaryExpression::ReadInteger {
                unsigned,
                size,
                big_endian,
                addr: Box::new(expr),
            },
        ),
        // double
        map(number::double, PrimaryExpression::Double),
        // number
        map(number::number, PrimaryExpression::Number),
        // text string
        map(string::quoted, PrimaryExpression::String),
        // regex
        map(string::regex, PrimaryExpression::Regex),
        // string_count 'in' range
        map(
            separated_pair(string::count, rtrim(tag("in")), cut(range)),
            |(identifier, (a, b))| PrimaryExpression::CountInRange {
                identifier,
                from: Box::new(a),
                to: Box::new(b),
            },
        ),
        // string_count
        map(string::count, PrimaryExpression::Count),
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
            |(identifier, expr)| PrimaryExpression::Offset {
                identifier,
                occurence_number: Box::new(expr.unwrap_or(PrimaryExpression::Number(1))),
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
            |(identifier, expr)| PrimaryExpression::Length {
                identifier,
                occurence_number: Box::new(expr.unwrap_or(PrimaryExpression::Number(1))),
            },
        ),
        // identifier
        map(string::identifier, |(name, wildcard_at_end)| {
            PrimaryExpression::Identifier {
                name,
                wildcard_at_end,
            }
        }),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::{parse, parse_err};
    use super::{
        primary_expression as pe, range, read_integer, PrimaryExpression as PE,
        ReadIntegerSize as RIS,
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
        parse(range, "(1..1) b", "b", (PE::Number(1), PE::Number(1)));
        parse(
            range,
            "( filesize .. entrypoint )",
            "",
            (PE::Filesize, PE::Entrypoint),
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
        parse(pe, "filesize a", "a", PE::Filesize);
        parse(pe, "( filesize) a", "a", PE::Filesize);
        parse(pe, "entrypoint a", "a", PE::Entrypoint);
        parse(
            pe,
            "uint8(3)",
            "",
            PE::ReadInteger {
                unsigned: true,
                size: RIS::Int8,
                big_endian: false,
                addr: Box::new(PE::Number(3)),
            },
        );
        parse(pe, "15  2", "2", PE::Number(15));
        parse(pe, "0.25 c", "c", PE::Double(0.25));
        parse(pe, "\"a\\nb \" b", "b", PE::String("a\nb ".to_owned()));
        parse(pe, "#foo bar", "bar", PE::Count("foo".to_owned()));
        parse(
            pe,
            "#foo in (0 ..filesize ) c",
            "c",
            PE::CountInRange {
                identifier: "foo".to_owned(),
                from: Box::new(PE::Number(0)),
                to: Box::new(PE::Filesize),
            },
        );
        parse(
            pe,
            "@a c",
            "c",
            PE::Offset {
                identifier: "a".to_owned(),
                occurence_number: Box::new(PE::Number(1)),
            },
        );
        parse(
            pe,
            "@a [ 2] c",
            "c",
            PE::Offset {
                identifier: "a".to_owned(),
                occurence_number: Box::new(PE::Number(2)),
            },
        );
        parse(
            pe,
            "!a c",
            "c",
            PE::Length {
                identifier: "a".to_owned(),
                occurence_number: Box::new(PE::Number(1)),
            },
        );
        parse(
            pe,
            "!a [ 2] c",
            "c",
            PE::Length {
                identifier: "a".to_owned(),
                occurence_number: Box::new(PE::Number(2)),
            },
        );

        parse(
            pe,
            "a c",
            "c",
            PE::Identifier {
                name: "a".to_owned(),
                wildcard_at_end: false,
            },
        );
        parse(
            pe,
            "aze* c",
            "c",
            PE::Identifier {
                name: "aze".to_owned(),
                wildcard_at_end: true,
            },
        );
        parse(
            pe,
            "/a*b$/i c",
            "c",
            PE::Regex(super::string::Regex {
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
            PE::Sub(
                Box::new(PE::Add(Box::new(PE::Number(1)), Box::new(PE::Number(2)))),
                Box::new(PE::Number(3)),
            ),
        );
        parse(
            pe,
            "1 \\ 2 % 3 * 4",
            "",
            PE::Mul(
                Box::new(PE::Mod(
                    Box::new(PE::Div(Box::new(PE::Number(1)), Box::new(PE::Number(2)))),
                    Box::new(PE::Number(3)),
                )),
                Box::new(PE::Number(4)),
            ),
        );
        parse(
            pe,
            "1 << 2 >> 3 << 4",
            "",
            PE::ShiftLeft(
                Box::new(PE::ShiftRight(
                    Box::new(PE::ShiftLeft(
                        Box::new(PE::Number(1)),
                        Box::new(PE::Number(2)),
                    )),
                    Box::new(PE::Number(3)),
                )),
                Box::new(PE::Number(4)),
            ),
        );
        parse(
            pe,
            "1 & 2 & 3",
            "",
            PE::BitwiseAnd(
                Box::new(PE::BitwiseAnd(
                    Box::new(PE::Number(1)),
                    Box::new(PE::Number(2)),
                )),
                Box::new(PE::Number(3)),
            ),
        );
        parse(
            pe,
            "1 ^ 2 ^ 3",
            "",
            PE::BitwiseXor(
                Box::new(PE::BitwiseXor(
                    Box::new(PE::Number(1)),
                    Box::new(PE::Number(2)),
                )),
                Box::new(PE::Number(3)),
            ),
        );
        parse(
            pe,
            "1 | 2 | 3",
            "",
            PE::BitwiseOr(
                Box::new(PE::BitwiseOr(
                    Box::new(PE::Number(1)),
                    Box::new(PE::Number(2)),
                )),
                Box::new(PE::Number(3)),
            ),
        );

        parse(
            pe,
            "-1--2",
            "",
            PE::Sub(
                Box::new(PE::Neg(Box::new(PE::Number(1)))),
                Box::new(PE::Neg(Box::new(PE::Number(2)))),
            ),
        );
        parse(
            pe,
            "~1^~2",
            "",
            PE::BitwiseXor(
                Box::new(PE::BitwiseNot(Box::new(PE::Number(1)))),
                Box::new(PE::BitwiseNot(Box::new(PE::Number(2)))),
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
            F: FnOnce(Box<PE>, Box<PE>) -> PE,
            F2: FnOnce(Box<PE>, Box<PE>) -> PE,
        {
            let input = format!("1 {} 2 {} 3", lower_op, higher_op);

            parse(
                pe,
                &input,
                "",
                lower_constructor(
                    Box::new(PE::Number(1)),
                    Box::new(higher_constructor(
                        Box::new(PE::Number(2)),
                        Box::new(PE::Number(3)),
                    )),
                ),
            );
        }

        // Test precedence of *, \\, % over +, %
        test_precedence("*", "+", PE::Mul, PE::Add);
        test_precedence("*", "-", PE::Mul, PE::Sub);
        test_precedence("\\", "+", PE::Div, PE::Add);
        test_precedence("\\", "-", PE::Div, PE::Sub);
        test_precedence("%", "+", PE::Mod, PE::Add);
        test_precedence("%", "-", PE::Mod, PE::Sub);

        // Test precedence of *, \\, %, +, - over >>, <<
        test_precedence("*", ">>", PE::Mul, PE::ShiftRight);
        test_precedence("*", "<<", PE::Mul, PE::ShiftLeft);
        test_precedence("\\", ">>", PE::Div, PE::ShiftRight);
        test_precedence("\\", "<<", PE::Div, PE::ShiftLeft);
        test_precedence("%", ">>", PE::Mod, PE::ShiftRight);
        test_precedence("%", "<<", PE::Mod, PE::ShiftLeft);
        test_precedence("+", ">>", PE::Add, PE::ShiftRight);
        test_precedence("+", "<<", PE::Add, PE::ShiftLeft);
        test_precedence("-", ">>", PE::Sub, PE::ShiftRight);
        test_precedence("-", "<<", PE::Sub, PE::ShiftLeft);

        // Test precedence of *, \\, %, +, - over &, |, ^
        test_precedence("*", "&", PE::Mul, PE::BitwiseAnd);
        test_precedence("*", "^", PE::Mul, PE::BitwiseXor);
        test_precedence("*", "|", PE::Mul, PE::BitwiseOr);
        test_precedence("\\", "&", PE::Div, PE::BitwiseAnd);
        test_precedence("\\", "^", PE::Div, PE::BitwiseXor);
        test_precedence("\\", "|", PE::Div, PE::BitwiseOr);
        test_precedence("%", "&", PE::Mod, PE::BitwiseAnd);
        test_precedence("%", "^", PE::Mod, PE::BitwiseXor);
        test_precedence("%", "|", PE::Mod, PE::BitwiseOr);
        test_precedence("+", "&", PE::Add, PE::BitwiseAnd);
        test_precedence("+", "^", PE::Add, PE::BitwiseXor);
        test_precedence("+", "|", PE::Add, PE::BitwiseOr);
        test_precedence("-", "&", PE::Sub, PE::BitwiseAnd);
        test_precedence("-", "^", PE::Sub, PE::BitwiseXor);
        test_precedence("-", "|", PE::Sub, PE::BitwiseOr);
        test_precedence(">>", "&", PE::ShiftRight, PE::BitwiseAnd);
        test_precedence(">>", "^", PE::ShiftRight, PE::BitwiseXor);
        test_precedence(">>", "|", PE::ShiftRight, PE::BitwiseOr);
        test_precedence("<<", "&", PE::ShiftLeft, PE::BitwiseAnd);
        test_precedence("<<", "^", PE::ShiftLeft, PE::BitwiseXor);
        test_precedence("<<", "|", PE::ShiftLeft, PE::BitwiseOr);

        // Test precedence of & over |, ^
        test_precedence("&", "^", PE::BitwiseAnd, PE::BitwiseXor);
        test_precedence("&", "|", PE::BitwiseAnd, PE::BitwiseOr);

        // Test precedence of ^ over |
        test_precedence("^", "|", PE::BitwiseXor, PE::BitwiseOr);

        // global test
        let expected = PE::BitwiseXor(
            Box::new(PE::Add(
                Box::new(PE::Number(1)),
                Box::new(PE::Mul(Box::new(PE::Number(2)), Box::new(PE::Number(3)))),
            )),
            Box::new(PE::Sub(
                Box::new(PE::Mod(Box::new(PE::Number(4)), Box::new(PE::Number(5)))),
                Box::new(PE::Number(6)),
            )),
        );

        parse(pe, "1 + 2 * 3 ^ 4 % 5 - 6", "", expected.clone());
        parse(pe, "(1 + (2 * 3) ) ^ ((4)%5 - 6)", "", expected);
    }
}
