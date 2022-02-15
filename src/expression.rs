//! Types related to expressions used in conditions of rules.
use crate::parser::Regex;

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

/// Identifier used in expressions.
#[derive(Clone, Debug, PartialEq)]
pub enum Identifier {
    /// Raw identifier, i.e. `pe`.
    Raw(String),
    /// Array subscript, i.e. `identifier[subscript]`.
    Subscript {
        identifier: Box<Identifier>,
        subscript: Box<Expression>,
    },
    /// Object subfield, i.e. `identifier.subfield`.
    Subfield {
        identifier: Box<Identifier>,
        subfield: String,
    },
    /// Function call, i.e. `identifier(arguments)`.
    FunctionCall {
        identifier: Box<Identifier>,
        arguments: Vec<Expression>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    // Numeric expressions
    //
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

    // Boolean expressions
    //
    /// Boolean and operator
    And(Box<Expression>, Box<Expression>),
    /// Boolean or operator
    Or(Box<Expression>, Box<Expression>),
    /// Comparison
    Cmp {
        /// Left side of the comparison
        left: Box<Expression>,
        /// Right side of the comparison
        right: Box<Expression>,
        /// If true, test `left < right`, otherwise test `left > right`.
        less_than: bool,
        /// If true, `left == right` also matches.
        can_be_equal: bool,
    },
    /// Equality
    Eq(Box<Expression>, Box<Expression>),
    /// Contains
    Contains {
        /// Expression containing the other one.
        haystack: Box<Expression>,
        /// Expression contained in the other one.
        needle: Box<Expression>,
        /// If true, comparisons are not case sensitive.
        case_insensitive: bool,
    },
    /// Starts with
    StartsWith {
        /// Expression to test
        expr: Box<Expression>,
        /// Prefix to look for in the expression.
        prefix: Box<Expression>,
        /// If true, comparisons are not case sensitive.
        case_insensitive: bool,
    },
    /// Ends with
    EndsWith {
        /// Expression to test
        expr: Box<Expression>,
        /// Suffix to look for in the expression.
        suffix: Box<Expression>,
        /// If true, comparisons are not case sensitive.
        case_insensitive: bool,
    },
    /// Case-insensitive equality
    IEquals(Box<Expression>, Box<Expression>),
    /// Matching a regular expression
    Matches(Box<Expression>, Regex),
    /// Is an expression `defined`, ie not `undefined`.
    Defined(Box<Expression>),
    /// Negation of a boolean expression
    Not(Box<Expression>),
    /// Boolean value
    Boolean(bool),
    /// Is a variable ("strings" in yara terms) found
    Variable(String),
    /// Is a variable found at a given index.
    VariableAt(String, Box<Expression>),
    /// Is a variable found in a given range.
    VariableIn {
        /// Name of the variable
        variable: String,
        /// Starting offset, included
        from: Box<Expression>,
        /// Ending offset, included
        to: Box<Expression>,
    },

    // Boolean for expression
    //
    /// Iterate over a set of variables.
    ///
    /// This expression is true if a given amount of
    /// variables in a given set matches a given condition.
    ///
    /// e.g. `for 2 of ($a, $b, $c) : ( $ at entrypoint )`
    For {
        /// Decides how many variables in the set must match the condition
        /// for this condition to be considered true.
        selection: ForSelection,

        /// List of variables considered.
        ///
        /// If empty, all variables declared in the rule are part of the set.
        set: Vec<String>,

        /// Optional condition.
        ///
        /// If set, the expression is evaluated for every variable in the
        /// set. '$' can be used to refer to the picked variable.
        ///
        /// If unset, this is equivalent to `$`, ie the [`Expression::Variable`]
        /// expression for the picked variable.
        condition: Option<Box<Expression>>,
    },

    /// Iterate over a set of bound identifiers.
    ///
    /// This expression is true if a given amount of
    /// conditions are true, while binding some given identifiers to a set
    /// of possible values.
    ///
    /// e.g. `for any i of (1..#a) : ( @a[i] < 100 )`
    ForIdentifiers {
        /// Decides how many times the condition must be true in order
        /// for this condition to be considered true.
        selection: ForSelection,

        /// Identifiers to bind to values from the iterator.
        ///
        /// Usually, should contain a single element.
        /// However, if the iterator is an object that evaluates to an
        /// array or a dict, multiple identifiers can be bound accordingly.
        identifiers: Vec<String>,

        /// Set of values to bind to the given identifiers in order.
        iterator: ForIterator,

        /// Condition to evaluate on every binding until the selection
        /// is matched.
        condition: Box<Expression>,
    },

    // String expressions
    //
    /// A raw identifier.
    Identifier(Identifier),
    /// A literal string.
    String(String),

    // Regex expressions
    //
    /// Regex
    Regex(Regex),
}

/// Selection in a 'for' expression.
///
/// This indicates how many times the condition of a for expression
/// must be true for the expression to be considered true.
/// See [`Expression::For`].
#[derive(Clone, Debug, PartialEq)]
pub enum ForSelection {
    /// Any variable/identifier in the set must match the condition.
    Any,

    /// All of the variables/identifiers in the set must match the condition.
    All,

    /// None of the variables/identifiers in the set must match the condition.
    None,

    /// Expression that should evaluate to a number, indicating:
    /// - if as_percent is false, how many variables/identifiers in the set
    ///   must match the condition.
    /// - if as_percent is true, which percentage of variables in the set
    ///   msut match the condition.
    ///
    /// Usually, the expression is a simple number.
    Expr {
        expr: Box<Expression>,
        as_percent: bool,
    },
}

/// Iterator for a 'for' expression over an identifier.
///
/// See [`Expression::ForIdentifiers`].
#[derive(Clone, Debug, PartialEq)]
pub enum ForIterator {
    /// An identifier.
    ///
    /// This can be an array or a dictionary.
    Identifier(Identifier),

    /// A numeric range.
    Range {
        from: Box<Expression>,
        to: Box<Expression>,
    },

    /// A list of values.
    List(Vec<Expression>),
}

impl From<crate::parser::expression::ReadIntegerSize> for ReadIntegerSize {
    fn from(size: crate::parser::expression::ReadIntegerSize) -> Self {
        match size {
            crate::parser::expression::ReadIntegerSize::Int8 => Self::Int8,
            crate::parser::expression::ReadIntegerSize::Int16 => Self::Int16,
            crate::parser::expression::ReadIntegerSize::Int32 => Self::Int32,
        }
    }
}
