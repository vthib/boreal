mod boolean_expression;
mod common;
mod identifier;
mod primary_expression;
mod read_integer;
mod string_expression;
mod validation;

pub use boolean_expression::expression;

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

/// Parsed identifier used in expressions.
#[derive(Clone, Debug, PartialEq)]
pub enum Identifier {
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

    Identifier(Identifier),
    String(String),
    Regex(crate::regex::Regex),
}

impl ParsedExpr {
    /// Validate a boolean parsed expression.
    ///
    /// Ensure the expression is well-formed, and returns a boolean.
    pub fn validate_boolean_expression(self) -> Result<crate::expression::Expression, String> {
        validation::validate_boolean_expression(self)
    }
}
