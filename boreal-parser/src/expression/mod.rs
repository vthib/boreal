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

pub(crate) use boolean_expression::expression;

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

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Type {
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
pub struct ParsedExpr {
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

/// An expression parsed in a Rule.
///
/// This represents an expression immediately parsed, which may be invalid.
/// It is then compiled into a [`crate::expression::Expression`] after
/// validation. See this aforementioned type for more documentation
/// on every type.
#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    Filesize,
    Entrypoint,
    ReadInteger {
        size: ReadIntegerSize,
        unsigned: bool,
        big_endian: bool,
        addr: Box<Expression>,
    },
    Number(i64),
    Double(f64),
    CountInRange {
        identifier: String,
        from: Box<Expression>,
        to: Box<Expression>,
    },
    Count(String),
    Offset {
        identifier: String,
        occurence_number: Box<Expression>,
    },
    Length {
        identifier: String,
        occurence_number: Box<Expression>,
    },
    Neg(Box<Expression>),
    Add(Box<Expression>, Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    Mul(Box<Expression>, Box<Expression>),
    Div(Box<Expression>, Box<Expression>),
    Mod(Box<Expression>, Box<Expression>),
    BitwiseXor(Box<Expression>, Box<Expression>),
    BitwiseAnd(Box<Expression>, Box<Expression>),
    BitwiseOr(Box<Expression>, Box<Expression>),
    BitwiseNot(Box<Expression>),
    ShiftLeft(Box<Expression>, Box<Expression>),
    ShiftRight(Box<Expression>, Box<Expression>),

    And(Box<Expression>, Box<Expression>),
    Or(Box<Expression>, Box<Expression>),
    Cmp {
        left: Box<Expression>,
        right: Box<Expression>,
        less_than: bool,
        can_be_equal: bool,
    },
    Eq(Box<Expression>, Box<Expression>),
    Contains {
        haystack: Box<Expression>,
        needle: Box<Expression>,
        case_insensitive: bool,
    },
    StartsWith {
        expr: Box<Expression>,
        prefix: Box<Expression>,
        case_insensitive: bool,
    },
    EndsWith {
        expr: Box<Expression>,
        suffix: Box<Expression>,
        case_insensitive: bool,
    },
    IEquals(Box<Expression>, Box<Expression>),
    Matches(Box<Expression>, Regex),
    Defined(Box<Expression>),
    Not(Box<Expression>),
    Boolean(bool),
    Variable(String),
    VariableAt(String, Box<Expression>),
    VariableIn {
        variable: String,
        from: Box<Expression>,
        to: Box<Expression>,
    },

    // selection 'of' set
    // 'for' selection 'of' set ':' '(' body ')'
    For {
        selection: ForSelection,
        set: VariableSet,
        body: Option<Box<Expression>>,
    },
    // selection 'of' set 'in' '(' from '..' to ')'
    ForIn {
        selection: ForSelection,
        set: VariableSet,
        from: Box<Expression>,
        to: Box<Expression>,
    },
    // 'for' selection identifiers 'of' iterator ':' '(' body ')'
    ForIdentifiers {
        selection: ForSelection,
        identifiers: Vec<String>,
        iterator: ForIterator,
        body: Box<Expression>,
    },

    Identifier(Identifier),
    String(String),
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
