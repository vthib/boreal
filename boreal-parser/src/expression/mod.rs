mod boolean_expression;
mod common;
mod for_expression;
mod identifier;
mod primary_expression;
mod read_integer;
mod string_expression;
mod validation;

use crate::{
    error::{Error, ErrorKind},
    string::Regex,
    types::Span,
};

pub(super) fn expression(input: crate::types::Input) -> crate::types::ParseResult<Expression> {
    let (input, parsed_expr) = boolean_expression::boolean_expression(input)?;
    // All types are convertible to bool, so just return the inner expr.
    Ok((input, parsed_expr.expr))
}

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

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

/// Parsed identifier used in expressions.
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

/// An expression parsed in a Rule.
#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    /// Size of the file being scanned.
    Filesize,

    /// Entrypoint of the file being scanned, if it is a PE or ELF.
    ///
    /// Deprecated, use the `pe` or `elf` module instead.
    Entrypoint,

    /// An integer read at a given address.
    ///
    /// See the yara documentation on `int8`, `uint16be` etc.
    ReadInteger {
        /// Size of the integer to read.
        size: ReadIntegerSize,
        /// If true, read an unsigned integer, otherwise signed.
        unsigned: bool,
        /// If true, read in big-endian, otherwise little-endian.
        big_endian: bool,
        /// Address/Offset of the input where to read.
        addr: Box<Expression>,
    },

    /// A i64 value.
    Number(i64),

    /// A f64 floating-point value.
    Double(f64),

    /// Count number of matches on a given variable.
    Count(String),

    /// Count number of matches on a given variable in a specific range of the input.
    CountInRange {
        /// Name of the variable being counted
        variable_name: String,
        /// Starting offset, included.
        from: Box<Expression>,
        /// Ending offset, included.
        to: Box<Expression>,
    },

    /// Offset of a variable match
    Offset {
        /// Name of the variable
        variable_name: String,

        /// Occurrence number.
        ///
        /// `1` is the first match on the variable, `2` is the next one, etc.
        occurence_number: Box<Expression>,
    },

    /// Length of a variable match
    Length {
        /// Name of the variable
        variable_name: String,

        /// Occurrence number.
        ///
        /// `1` is the first match on the variable, `2` is the next one, etc.
        occurence_number: Box<Expression>,
    },

    /// Opposite value, for integers and floats.
    Neg(Box<Expression>),

    /// Addition, for integers and floats.
    Add(Box<Expression>, Box<Expression>),
    /// Substraction, for integers and floats.
    Sub(Box<Expression>, Box<Expression>),
    /// Multiplication, for integers and floats.
    Mul(Box<Expression>, Box<Expression>),
    /// Division, for integers and floats.
    Div(Box<Expression>, Box<Expression>),

    /// Modulo, for integers.
    Mod(Box<Expression>, Box<Expression>),

    /// Bitwise xor, for integers.
    BitwiseXor(Box<Expression>, Box<Expression>),
    /// Bitwise and, for integers.
    BitwiseAnd(Box<Expression>, Box<Expression>),
    /// Bitwise or, for integers.
    BitwiseOr(Box<Expression>, Box<Expression>),

    /// Bitwise negation, for integers.
    BitwiseNot(Box<Expression>),

    /// Shift left, both elements must be integers.
    ShiftLeft(Box<Expression>, Box<Expression>),
    /// Shift right, both elements must be integers.
    ShiftRight(Box<Expression>, Box<Expression>),

    /// Boolean and operation.
    And(Box<Expression>, Box<Expression>),
    /// Boolean or operation.
    Or(Box<Expression>, Box<Expression>),

    /// Boolean negation.
    Not(Box<Expression>),

    /// Comparison.
    ///
    /// Integers and floats can be compared to integers and floats.
    /// Strings can be compared to strings.
    Cmp {
        /// Left operand.
        left: Box<Expression>,
        /// Right operand.
        right: Box<Expression>,
        /// If true this is '<', otherwise '>'
        less_than: bool,
        /// If true, left == right returns true.
        can_be_equal: bool,
    },

    /// Equality test
    Eq(Box<Expression>, Box<Expression>),

    /// Does a string contains another string
    Contains {
        /// String to search in
        haystack: Box<Expression>,
        /// String to search
        needle: Box<Expression>,
        /// If true, the search is case insensitive.
        case_insensitive: bool,
    },

    /// Does a string starts with another string
    StartsWith {
        /// String to search in
        expr: Box<Expression>,
        /// Prefix to search
        prefix: Box<Expression>,
        /// If true, the search is case insensitive.
        case_insensitive: bool,
    },

    /// Does a string ends with another string
    EndsWith {
        /// String to search in
        expr: Box<Expression>,
        /// Prefix to search
        suffix: Box<Expression>,
        /// If true, the search is case insensitive.
        case_insensitive: bool,
    },

    /// Case insensitive equality test. Both elements must be strings.
    IEquals(Box<Expression>, Box<Expression>),

    /// Does a string matches a regex.
    Matches(Box<Expression>, Regex),

    /// Is a given value defined.
    ///
    /// For example, `defined filesize` will be true when scanning a file,
    /// false otherwise.
    Defined(Box<Expression>),

    /// A boolean value.
    Boolean(bool),

    /// Does a variable matches
    Variable(String),

    /// Does a variable matches at a given offset.
    VariableAt(String, Box<Expression>),

    /// Does a variable matches in a given offset range.
    VariableIn {
        /// Name of the variable.
        variable_name: String,
        /// Starting offset, included.
        from: Box<Expression>,
        /// Ending offset, included.
        to: Box<Expression>,
    },

    /// Evaluate multiple variables on a given expression.
    ///
    /// For each variable in `set`, evaluate `body`.
    /// Then, if the number of evaluations returning true
    /// matches the `selection`, then this expression returns true.
    For {
        /// How many variables must match for this expression to be true.
        selection: ForSelection,

        /// Which variables to select.
        set: VariableSet,

        /// Expression to evaluate for each variable.
        ///
        /// The body can contain `$`, `#`, `@` or `!` to refer to the
        /// currently selected variable.
        ///
        /// If unset, this is equivalent to `$`, i.e. true if the selected
        /// variable matches.
        body: Option<Box<Expression>>,
    },

    /// Evaluate multiple variables on a given range.
    ///
    /// This is equivalent to a [`Self::For`] value, with a body
    /// set to `$ in (from..to)`.
    // TODO: remove this to use `For` directly?
    ForIn {
        /// How many variables must match for this expresion to be true.
        selection: ForSelection,
        /// Which variables to select.
        set: VariableSet,
        /// Starting offset, included.
        from: Box<Expression>,
        /// Ending offset, included.
        to: Box<Expression>,
    },

    /// Evaluate an identifier with multiple values on a given expression.
    ///
    /// Same as [`Self::For`], but instead of binding a variable,
    /// an identifier is bounded to multiple values.
    ///
    /// For example: `for all i in (0..#a): ( @a[i] < 100 )`
    ForIdentifiers {
        /// How many times the body must evaluate to true for this expresion
        /// to be true.
        selection: ForSelection,

        /// List of identifiers to bind.
        ///
        /// This is a list because the values bounded can be complex, ie
        /// arrays or dictionaries. This list is the same length as the
        /// cardinality of the values in the iterator.
        identifiers: Vec<String>,

        /// Values to bind to the identifiers.
        iterator: ForIterator,

        /// Body to evaluate for each binding.
        body: Box<Expression>,
    },

    /// An identifier.
    Identifier(Identifier),
    /// A string.
    String(String),
    /// A regex.
    Regex(Regex),
}

/// Selection of variables in a 'for' expression.
///
/// This indicates how many variables must match the for condition
/// for it to be considered true.
#[derive(Clone, Debug, PartialEq)]
pub enum ForSelection {
    /// Any variable in the set must match the condition.
    Any,
    /// All of the variables in the set must match the condition.
    All,
    /// None of the variables in the set must match the condition.
    None,
    /// Expression that should evaluate to a number, indicating:
    /// - if as_percent is false, how many variables in the set must match
    ///   the condition.
    /// - if as_percent is true, which percentage of variables in the set
    ///   msut match the condition.
    ///   the condition.
    ///
    /// Usually, the expression is a simple number.
    Expr {
        expr: Box<Expression>,
        as_percent: bool,
    },
}

/// Iterator for a 'for' expression over an identifier.
#[derive(Clone, Debug, PartialEq)]
pub enum ForIterator {
    Identifier(Identifier),
    Range {
        from: Box<Expression>,
        to: Box<Expression>,
    },
    List(Vec<Expression>),
}

/// Set of multiple variables.
#[derive(Clone, Debug, PartialEq)]
pub struct VariableSet {
    /// Names of the variables in the set.
    ///
    /// If empty, the set is considered as containing *all* variables.
    /// The associated boolean indicates if the name has a trailing
    /// wildcard.
    pub elements: Vec<(String, bool)>,
}

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
enum Type {
    Integer,
    Float,
    String,
    Regex,
    Boolean,
    // TODO: afaict, we shouldn't need this type.
    // It's used for the moment for unknown symbols.
    Undefined,
}

impl std::fmt::Display for Type {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(match self {
            Self::Integer => "integer",
            Self::Float => "floating-point number",
            Self::String => "string",
            Self::Regex => "regex",
            Self::Boolean => "boolean",
            Self::Undefined => "undefined",
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ParsedExpr {
    // The raw expression.
    pub expr: Expression,

    // Type of the expression.
    pub ty: Type,

    // Span of the expression.
    pub span: Span,
}

impl ParsedExpr {
    fn check_type(&self, expected_type: Type) -> Result<(), nom::Err<Error>> {
        if self.ty != expected_type && self.ty != Type::Undefined {
            return Err(nom::Err::Failure(Error::new(
                self.span.clone(),
                ErrorKind::ExpressionInvalidType {
                    ty: self.ty.to_string(),
                    expected_type: expected_type.to_string(),
                },
            )));
        }
        Ok(())
    }

    fn unwrap_expr(self, expected_type: Type) -> Result<Box<Expression>, nom::Err<Error>> {
        self.check_type(expected_type)?;
        Ok(Box::new(self.expr))
    }
}
