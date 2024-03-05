//! Types related to the condition part of YARA rules.
use std::ops::Range;

mod boolean_expression;
mod common;
mod for_expression;
mod identifier;
mod primary_expression;
mod read_integer;
mod string_expression;

use crate::regex::Regex;

pub(crate) use boolean_expression::boolean_expression as expression;

const MAX_EXPR_RECURSION: usize = 20;

/// Integer read type, see [`ExpressionKind::ReadInteger`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReadIntegerType {
    /// 8 bits, signed
    Int8,
    /// 8 bits, unsigned
    Uint8,
    /// 16 bits, signed
    Int16,
    /// 16 bits, signed, big-endian
    Int16BE,
    /// 16 bits, unsigned
    Uint16,
    /// 16 bits, unsigned, big-endian
    Uint16BE,
    /// 32 bits, signed
    Int32,
    /// 32 bits, signed, big-endian
    Int32BE,
    /// 32 bits, unsigned
    Uint32,
    /// 32 bits, unsigned, big-endian
    Uint32BE,
}

/// Parsed identifier used in expressions.
#[derive(Clone, Debug, PartialEq)]
pub struct Identifier {
    /// Name of the identifier
    pub name: String,

    /// Span covering the name of the identifier.
    pub name_span: Range<usize>,

    /// Operations on the identifier, stored in the order of operations.
    ///
    /// For example, `pe.sections[2].name` would give `pe` for the name, and
    /// `[Subfield("sections"), Subscript(Expr::Integer(2)), Subfield("name")]` for the operations.
    pub operations: Vec<IdentifierOperation>,
}

/// Operation applied on an identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentifierOperation {
    /// Type of the operation
    pub op: IdentifierOperationType,

    /// Span covering the operation
    pub span: Range<usize>,
}

/// Type of operation applied on an identifier.
#[derive(Clone, Debug, PartialEq)]
pub enum IdentifierOperationType {
    /// Array subscript, i.e. `identifier[subscript]`.
    Subscript(Box<Expression>),
    /// Object subfield, i.e. `identifier.subfield`.
    Subfield(String),
    /// Function call, i.e. `identifier(arguments)`.
    FunctionCall(Vec<Expression>),
}

/// An expression parsed in a Rule.
#[derive(Clone, Debug, PartialEq)]
pub enum ExpressionKind {
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
        /// Which size and endianness to read.
        ty: ReadIntegerType,
        /// Address/Offset of the input where to read.
        addr: Box<Expression>,
    },

    /// A i64 value.
    Integer(i64),

    /// A f64 floating-point value.
    Double(f64),

    /// Count number of matches on a given variable.
    Count(String),

    /// Count number of matches on a given variable in a specific range of the input.
    CountInRange {
        /// Name of the variable being counted
        variable_name: String,
        /// Span for the name of the variable
        variable_name_span: Range<usize>,
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
    And(Vec<Expression>),
    /// Boolean or operation.
    Or(Vec<Expression>),

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

    /// Equal
    Eq(Box<Expression>, Box<Expression>),

    /// Not equal
    NotEq(Box<Expression>, Box<Expression>),

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
    VariableAt {
        /// Name of the variable
        variable_name: String,
        /// Span for the name of the variable
        variable_name_span: Range<usize>,
        /// Offset
        offset: Box<Expression>,
    },

    /// Does a variable matches in a given offset range.
    VariableIn {
        /// Name of the variable.
        variable_name: String,
        /// Span for the name of the variable
        variable_name_span: Range<usize>,
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

        /// `ParsedExpr` to evaluate for each variable.
        ///
        /// The body can contain `$`, `#`, `@` or `!` to refer to the
        /// currently selected variable.
        ///
        /// If unset, this is equivalent to `$`, i.e. true if the selected
        /// variable matches.
        body: Option<Box<Expression>>,
    },

    /// Evaluate the presence of multiple variables in a given range.
    ///
    /// This is equivalent to a [`Self::For`] value, with a body
    /// set to `$ in (from..to)`.
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

    /// Evaluate the presence of multiple variables at a given offset.
    ///
    /// This is equivalent to a [`Self::For`] value, with a body
    /// set to `$ at expr`.
    ForAt {
        /// How many variables must match for this expresion to be true.
        selection: ForSelection,
        /// Which variables to select.
        set: VariableSet,
        /// Offset of the variable match.
        offset: Box<Expression>,
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

        /// Span covering the identifiers declaration
        identifiers_span: Range<usize>,

        /// Values to bind to the identifiers.
        iterator: ForIterator,

        /// Span covering the iterator
        iterator_span: Range<usize>,

        /// Body to evaluate for each binding.
        body: Box<Expression>,
    },

    /// Depend on multiple rules already declared in the namespace.
    ///
    /// If the number of matching rules in the set matches the `selection`,
    /// this expression returns true.
    ForRules {
        /// How many variables must match for this expression to be true.
        selection: ForSelection,

        /// Which rules are selected.
        set: RuleSet,
    },

    /// An identifier.
    Identifier(Identifier),
    /// A byte string.
    Bytes(Vec<u8>),
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
    /// `ParsedExpr` that should evaluate to a number, indicating:
    /// - if `as_percent` is false, how many variables in the set must match
    ///   the condition.
    /// - if `as_percent` is true, which percentage of variables in the set
    ///   msut match the condition.
    ///   the condition.
    ///
    /// Usually, the expression is a simple number.
    Expr {
        /// Number of variables selected
        expr: Box<Expression>,
        /// Should the number be a percentage.
        as_percent: bool,
    },
}

/// Iterator for a 'for' expression over an identifier.
#[derive(Clone, Debug, PartialEq)]
pub enum ForIterator {
    /// Identifier to pick values from.
    Identifier(Identifier),
    /// Every value between two numbers
    Range {
        /// Start of the range, included
        from: Box<Expression>,
        /// End of the range, included
        to: Box<Expression>,
    },
    /// List of values
    List(Vec<Expression>),
}

/// Set of multiple variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableSet {
    /// Names of the variables in the set.
    ///
    /// If empty, the set is considered as containing *all* variables.
    pub elements: Vec<SetElement>,
}

/// Element of a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetElement {
    /// Name of the element.
    pub name: String,

    /// Is the name a wildcard, i.e. the element is `name*`.
    pub is_wildcard: bool,

    /// Span for the element.
    pub span: Range<usize>,
}

/// Set of multiple rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    /// Names of the rules in the set.
    ///
    /// The associated boolean indicates if the name has a trailing
    /// wildcard.
    pub elements: Vec<SetElement>,
}

/// A parsed expression with associated span
#[derive(Clone, Debug, PartialEq)]
pub struct Expression {
    /// Kind of the expression.
    pub expr: ExpressionKind,

    /// Span of the whole expression in the input.
    pub span: Range<usize>,
}
