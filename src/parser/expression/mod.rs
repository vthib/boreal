mod boolean_expression;
mod common;
mod for_expression;
mod identifier;
mod primary_expression;
mod read_integer;
mod string_expression;
mod validation;

use super::types::Span;

pub use boolean_expression::expression;
pub use validation::Validator;

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

/// Parsed identifier used in expressions.
#[derive(Clone, Debug, PartialEq)]
enum Identifier {
    /// Raw identifier, i.e. `pe`.
    Raw(String),
    /// Array subscript, i.e. `identifier[subscript]`.
    Subscript {
        identifier: Box<Identifier>,
        subscript: Box<ParsedExpr>,
    },
    /// Object subfield, i.e. `identifier.subfield`.
    Subfield {
        identifier: Box<Identifier>,
        subfield: String,
    },
    /// Function call, i.e. `identifier(arguments)`.
    FunctionCall {
        identifier: Box<Identifier>,
        arguments: Vec<ParsedExpr>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedExpr {
    expr: Expression,

    // Span of the expression.
    span: Span,
}

/// An expression parsed in a Rule.
///
/// This represents an expression immediately parsed, which may be invalid.
/// It is then compiled into a [`crate::expression::Expression`] after
/// validation. See this aforementioned type for more documentation
/// on every type.
#[derive(Clone, Debug, PartialEq)]
enum Expression {
    Filesize,
    Entrypoint,
    ReadInteger {
        size: crate::expression::ReadIntegerSize,
        unsigned: bool,
        big_endian: bool,
        addr: Box<ParsedExpr>,
    },
    Number(i64),
    Double(f64),
    CountInRange {
        identifier: String,
        from: Box<ParsedExpr>,
        to: Box<ParsedExpr>,
    },
    Count(String),
    Offset {
        identifier: String,
        occurence_number: Box<ParsedExpr>,
    },
    Length {
        identifier: String,
        occurence_number: Box<ParsedExpr>,
    },
    Neg(Box<ParsedExpr>),
    Add(Box<ParsedExpr>, Box<ParsedExpr>),
    Sub(Box<ParsedExpr>, Box<ParsedExpr>),
    Mul(Box<ParsedExpr>, Box<ParsedExpr>),
    Div(Box<ParsedExpr>, Box<ParsedExpr>),
    Mod(Box<ParsedExpr>, Box<ParsedExpr>),
    BitwiseXor(Box<ParsedExpr>, Box<ParsedExpr>),
    BitwiseAnd(Box<ParsedExpr>, Box<ParsedExpr>),
    BitwiseOr(Box<ParsedExpr>, Box<ParsedExpr>),
    BitwiseNot(Box<ParsedExpr>),
    ShiftLeft(Box<ParsedExpr>, Box<ParsedExpr>),
    ShiftRight(Box<ParsedExpr>, Box<ParsedExpr>),

    And(Box<ParsedExpr>, Box<ParsedExpr>),
    Or(Box<ParsedExpr>, Box<ParsedExpr>),
    Cmp {
        left: Box<ParsedExpr>,
        right: Box<ParsedExpr>,
        less_than: bool,
        can_be_equal: bool,
    },
    Eq(Box<ParsedExpr>, Box<ParsedExpr>),
    Contains {
        haystack: Box<ParsedExpr>,
        needle: Box<ParsedExpr>,
        case_insensitive: bool,
    },
    StartsWith {
        expr: Box<ParsedExpr>,
        prefix: Box<ParsedExpr>,
        case_insensitive: bool,
    },
    EndsWith {
        expr: Box<ParsedExpr>,
        suffix: Box<ParsedExpr>,
        case_insensitive: bool,
    },
    IEquals(Box<ParsedExpr>, Box<ParsedExpr>),
    Matches(Box<ParsedExpr>, crate::regex::Regex),
    Defined(Box<ParsedExpr>),
    Not(Box<ParsedExpr>),
    Boolean(bool),
    Variable(String),
    VariableAt(String, Box<ParsedExpr>),
    VariableIn {
        variable: String,
        from: Box<ParsedExpr>,
        to: Box<ParsedExpr>,
    },

    // selection 'of' set
    // 'for' selection 'of' set ':' '(' body ')'
    For {
        selection: ForSelection,
        set: VariableSet,
        body: Option<Box<ParsedExpr>>,
    },
    // selection 'of' set 'in' '(' from '..' to ')'
    ForIn {
        selection: ForSelection,
        set: VariableSet,
        from: Box<ParsedExpr>,
        to: Box<ParsedExpr>,
    },
    // 'for' selection identifiers 'of' iterator ':' '(' body ')'
    ForIdentifiers {
        selection: ForSelection,
        identifiers: Vec<String>,
        iterator: ForIterator,
        body: Box<ParsedExpr>,
    },

    Identifier(Identifier),
    String(String),
    Regex(crate::regex::Regex),
}

/// Selection of variables in a 'for' expression.
///
/// This indicates how many variables must match the for condition
/// for it to be considered true.
#[derive(Clone, Debug, PartialEq)]
enum ForSelection {
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
        expr: Box<ParsedExpr>,
        as_percent: bool,
    },
}

/// Iterator for a 'for' expression over an identifier.
#[derive(Clone, Debug, PartialEq)]
enum ForIterator {
    Identifier(Identifier),
    Range {
        from: Box<ParsedExpr>,
        to: Box<ParsedExpr>,
    },
    List(Vec<ParsedExpr>),
}

/// Set of multiple variables.
#[derive(Clone, Debug, PartialEq)]
struct VariableSet {
    /// Names of the variables in the set.
    ///
    /// If empty, the set is considered as containing *all* variables.
    /// The associated boolean indicates if the name has a trailing
    /// wildcard.
    elements: Vec<(String, bool)>,
}
