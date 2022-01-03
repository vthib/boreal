//! Types related to expressions used in conditions of rules.
use crate::regex::Regex;

/// Size of the integer to read, see [`Expression::ReadInteger`].
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
pub enum Expression {
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
        addr: Box<Expression>,
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
        from: Box<Expression>,
        /// To value, included.
        to: Box<Expression>,
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
        occurence_number: Box<Expression>,
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
        occurence_number: Box<Expression>,
    },
    /// A raw identifier.
    Identifier(String),
    /// Negation
    Neg(Box<Expression>),
    /// Addition
    Add(Box<Expression>, Box<Expression>),
    /// Substraction
    Sub(Box<Expression>, Box<Expression>),
    /// Multiplication
    Mul(Box<Expression>, Box<Expression>),
    /// Division
    Div(Box<Expression>, Box<Expression>),
    /// Modulo
    Mod(Box<Expression>, Box<Expression>),
    /// Bitwise Xor
    BitwiseXor(Box<Expression>, Box<Expression>),
    /// Bitwise and
    BitwiseAnd(Box<Expression>, Box<Expression>),
    /// Bitwise or
    BitwiseOr(Box<Expression>, Box<Expression>),
    /// Bitwise not
    BitwiseNot(Box<Expression>),
    /// Shift left
    ShiftLeft(Box<Expression>, Box<Expression>),
    /// Shift right
    ShiftRight(Box<Expression>, Box<Expression>),
    /// Regex
    Regex(Regex),
}
