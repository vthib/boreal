//! Compiled expression used in a rule.
//!
//! This module contains all types describing a rule condition, built from the parsed AST.
use std::ops::Range;

use regex::Regex;

use boreal_parser as parser;

use super::{CompilationError, CompilationErrorKind, Compiler};

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

#[derive(Debug)]
pub struct Expr {
    // The raw expression.
    pub expr: Expression,

    // Type of the expression.
    ty: Type,

    // Span of the expression.
    span: Range<usize>,
}

impl Expr {
    fn check_type(&self, expected_type: Type) -> Result<(), CompilationError> {
        if self.ty != expected_type && self.ty != Type::Undefined {
            return Err(CompilationError {
                kind: CompilationErrorKind::ExpressionInvalidType {
                    ty: self.ty.to_string(),
                    expected_type: expected_type.to_string(),
                },
                span: self.span.clone(),
            });
        }
        Ok(())
    }

    fn unwrap_expr(self, expected_type: Type) -> Result<Box<Expression>, CompilationError> {
        self.check_type(expected_type)?;
        Ok(Box::new(self.expr))
    }
}

#[derive(Debug)]
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
        size: parser::ReadIntegerSize,
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
        set: parser::VariableSet,

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
        set: parser::VariableSet,
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

#[allow(clippy::too_many_lines)]
pub fn compile_expression(
    compiler: &Compiler,
    expression: parser::Expression,
) -> Result<Expr, CompilationError> {
    let span = expression.span;

    match expression.expr {
        parser::ExpressionKind::Filesize => Ok(Expr {
            expr: Expression::Filesize,
            ty: Type::Integer,
            span,
        }),
        parser::ExpressionKind::Entrypoint => Ok(Expr {
            expr: Expression::Entrypoint,
            ty: Type::Integer,
            span,
        }),
        parser::ExpressionKind::ReadInteger {
            size,
            unsigned,
            big_endian,
            addr,
        } => {
            let addr = compile_expression(compiler, *addr)?;

            Ok(Expr {
                expr: Expression::ReadInteger {
                    size,
                    unsigned,
                    big_endian,
                    addr: addr.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
                span,
            })
        }

        parser::ExpressionKind::Number(v) => Ok(Expr {
            expr: Expression::Number(v),
            ty: Type::Integer,
            span,
        }),

        parser::ExpressionKind::Double(v) => Ok(Expr {
            expr: Expression::Double(v),
            ty: Type::Float,
            span,
        }),

        parser::ExpressionKind::Count(variable_name) => Ok(Expr {
            expr: Expression::Count(variable_name),
            ty: Type::Integer,
            span,
        }),

        parser::ExpressionKind::CountInRange {
            variable_name,
            from,
            to,
        } => {
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            Ok(Expr {
                expr: Expression::CountInRange {
                    variable_name,
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
                span,
            })
        }

        parser::ExpressionKind::Offset {
            variable_name,
            occurence_number,
        } => {
            let occurence_number = compile_expression(compiler, *occurence_number)?;

            Ok(Expr {
                expr: Expression::Offset {
                    variable_name,
                    occurence_number: occurence_number.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
                span,
            })
        }

        parser::ExpressionKind::Length {
            variable_name,
            occurence_number,
        } => {
            let occurence_number = compile_expression(compiler, *occurence_number)?;

            Ok(Expr {
                expr: Expression::Length {
                    variable_name,
                    occurence_number: occurence_number.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
                span,
            })
        }

        parser::ExpressionKind::Neg(expr) => {
            let expr = compile_expression(compiler, *expr)?;

            if expr.ty == Type::Float {
                Ok(Expr {
                    expr: Expression::Neg(Box::new(expr.expr)),
                    ty: Type::Float,
                    span,
                })
            } else {
                Ok(Expr {
                    expr: Expression::Neg(expr.unwrap_expr(Type::Integer)?),
                    ty: Type::Integer,
                    span,
                })
            }
        }

        parser::ExpressionKind::Add(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Add, false)
        }
        parser::ExpressionKind::Sub(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Sub, false)
        }
        parser::ExpressionKind::Mul(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Mul, false)
        }
        parser::ExpressionKind::Div(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Div, false)
        }

        parser::ExpressionKind::Mod(left, right) => {
            compile_arith_binary_op(compiler, *left, *right, span, Expression::Mod)
        }

        parser::ExpressionKind::BitwiseXor(left, right) => {
            compile_arith_binary_op(compiler, *left, *right, span, Expression::BitwiseXor)
        }
        parser::ExpressionKind::BitwiseAnd(left, right) => {
            compile_arith_binary_op(compiler, *left, *right, span, Expression::BitwiseAnd)
        }
        parser::ExpressionKind::BitwiseOr(left, right) => {
            compile_arith_binary_op(compiler, *left, *right, span, Expression::BitwiseOr)
        }

        parser::ExpressionKind::BitwiseNot(expr) => {
            let expr = compile_expression(compiler, *expr)?;

            Ok(Expr {
                expr: Expression::BitwiseNot(expr.unwrap_expr(Type::Integer)?),
                ty: Type::Integer,
                span,
            })
        }

        parser::ExpressionKind::ShiftLeft(left, right) => {
            compile_arith_binary_op(compiler, *left, *right, span, Expression::ShiftLeft)
        }
        parser::ExpressionKind::ShiftRight(left, right) => {
            compile_arith_binary_op(compiler, *left, *right, span, Expression::ShiftRight)
        }

        parser::ExpressionKind::And(left, right) => {
            let left = compile_expression(compiler, *left)?;
            let right = compile_expression(compiler, *right)?;

            Ok(Expr {
                expr: Expression::And(Box::new(left.expr), Box::new(right.expr)),
                ty: Type::Boolean,
                span,
            })
        }
        parser::ExpressionKind::Or(left, right) => {
            let left = compile_expression(compiler, *left)?;
            let right = compile_expression(compiler, *right)?;

            Ok(Expr {
                expr: Expression::Or(Box::new(left.expr), Box::new(right.expr)),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Not(expr) => {
            let expr = compile_expression(compiler, *expr)?;

            Ok(Expr {
                expr: Expression::Not(Box::new(expr.expr)),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Cmp {
            left,
            right,
            less_than,
            can_be_equal,
        } => {
            let mut res = compile_primary_op(
                compiler,
                *left,
                *right,
                span,
                |left, right| Expression::Cmp {
                    left,
                    right,
                    less_than,
                    can_be_equal,
                },
                true,
            )?;
            res.ty = Type::Boolean;
            Ok(res)
        }

        parser::ExpressionKind::Eq(left, right) => {
            let mut res = compile_primary_op(compiler, *left, *right, span, Expression::Eq, true)?;
            res.ty = Type::Boolean;
            Ok(res)
        }

        parser::ExpressionKind::Contains {
            haystack,
            needle,
            case_insensitive,
        } => {
            let haystack = compile_expression(compiler, *haystack)?;
            let needle = compile_expression(compiler, *needle)?;

            Ok(Expr {
                expr: Expression::Contains {
                    haystack: haystack.unwrap_expr(Type::String)?,
                    needle: needle.unwrap_expr(Type::String)?,
                    case_insensitive,
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::StartsWith {
            expr,
            prefix,
            case_insensitive,
        } => {
            let expr = compile_expression(compiler, *expr)?;
            let prefix = compile_expression(compiler, *prefix)?;

            Ok(Expr {
                expr: Expression::StartsWith {
                    expr: expr.unwrap_expr(Type::String)?,
                    prefix: prefix.unwrap_expr(Type::String)?,
                    case_insensitive,
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::EndsWith {
            expr,
            suffix,
            case_insensitive,
        } => {
            let expr = compile_expression(compiler, *expr)?;
            let suffix = compile_expression(compiler, *suffix)?;

            Ok(Expr {
                expr: Expression::EndsWith {
                    expr: expr.unwrap_expr(Type::String)?,
                    suffix: suffix.unwrap_expr(Type::String)?,
                    case_insensitive,
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::IEquals(left, right) => {
            let left = compile_expression(compiler, *left)?;
            let right = compile_expression(compiler, *right)?;

            Ok(Expr {
                expr: Expression::IEquals(
                    left.unwrap_expr(Type::String)?,
                    right.unwrap_expr(Type::String)?,
                ),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Matches(expr, regex) => {
            let expr = compile_expression(compiler, *expr)?;

            Ok(Expr {
                expr: Expression::Matches(expr.unwrap_expr(Type::String)?, compile_regex(regex)?),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Defined(expr) => {
            let expr = compile_expression(compiler, *expr)?;

            Ok(Expr {
                expr: Expression::Defined(Box::new(expr.expr)),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Boolean(b) => Ok(Expr {
            expr: Expression::Boolean(b),
            ty: Type::Boolean,
            span,
        }),

        parser::ExpressionKind::Variable(variable_name) => Ok(Expr {
            expr: Expression::Variable(variable_name),
            ty: Type::Boolean,
            span,
        }),

        parser::ExpressionKind::VariableAt(variable_name, expr_offset) => {
            let expr_offset = compile_expression(compiler, *expr_offset)?;

            Ok(Expr {
                expr: Expression::VariableAt(
                    variable_name,
                    expr_offset.unwrap_expr(Type::Integer)?,
                ),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::VariableIn {
            variable_name,
            from,
            to,
        } => {
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            Ok(Expr {
                expr: Expression::VariableIn {
                    variable_name,
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::For {
            selection,
            set,
            body,
        } => Ok(Expr {
            expr: Expression::For {
                selection: compile_for_selection(compiler, selection)?,
                set,
                body: match body {
                    Some(body) => {
                        let body = compile_expression(compiler, *body)?;
                        Some(Box::new(body.expr))
                    }
                    None => None,
                },
            },
            ty: Type::Boolean,
            span,
        }),

        parser::ExpressionKind::ForIn {
            selection,
            set,
            from,
            to,
        } => {
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            Ok(Expr {
                expr: Expression::ForIn {
                    selection: compile_for_selection(compiler, selection)?,
                    set,
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::ForIdentifiers {
            selection,

            identifiers,

            iterator,

            body,
        } => {
            let body = compile_expression(compiler, *body)?;

            Ok(Expr {
                expr: Expression::ForIdentifiers {
                    selection: compile_for_selection(compiler, selection)?,
                    identifiers,
                    iterator: compile_for_iterator(compiler, iterator)?,
                    body: Box::new(body.expr),
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Identifier(identifier) => Ok(Expr {
            expr: Expression::Identifier(compile_identifier(compiler, identifier)?),
            ty: Type::Undefined,
            span,
        }),
        parser::ExpressionKind::String(s) => Ok(Expr {
            expr: Expression::String(s),
            ty: Type::String,
            span,
        }),
        parser::ExpressionKind::Regex(regex) => Ok(Expr {
            expr: Expression::Regex(compile_regex(regex)?),
            ty: Type::Regex,
            span,
        }),
    }
}

fn compile_primary_op<F>(
    compiler: &Compiler,
    a: parser::Expression,
    b: parser::Expression,
    span: Range<usize>,
    constructor: F,
    string_allowed: bool,
) -> Result<Expr, CompilationError>
where
    F: Fn(Box<Expression>, Box<Expression>) -> Expression,
{
    let a = compile_expression(compiler, a)?;
    let b = compile_expression(compiler, b)?;

    let ty = match (a.ty, b.ty) {
        (Type::Integer, Type::Integer) => Type::Integer,
        (Type::Undefined, Type::Integer) | (Type::Integer, Type::Undefined) => Type::Integer,
        (Type::Float | Type::Integer, Type::Integer | Type::Float) => Type::Float,
        (Type::Undefined, Type::Float) | (Type::Float, Type::Undefined) => Type::Float,
        (Type::String, Type::String) if string_allowed => Type::String,
        (Type::Undefined, Type::String) | (Type::String, Type::Undefined) if string_allowed => {
            Type::String
        }
        (Type::Undefined, Type::Undefined) => Type::Undefined,
        _ => {
            return Err(CompilationError {
                span,
                kind: CompilationErrorKind::ExpressionIncompatibleTypes {
                    left_type: a.ty.to_string(),
                    left_span: a.span,
                    right_type: b.ty.to_string(),
                    right_span: b.span,
                },
            });
        }
    };

    Ok(Expr {
        expr: constructor(Box::new(a.expr), Box::new(b.expr)),
        ty,
        span,
    })
}

fn compile_arith_binary_op<F>(
    compiler: &Compiler,
    a: parser::Expression,
    b: parser::Expression,
    span: Range<usize>,
    constructor: F,
) -> Result<Expr, CompilationError>
where
    F: Fn(Box<Expression>, Box<Expression>) -> Expression,
{
    let a = compile_expression(compiler, a)?;
    let b = compile_expression(compiler, b)?;

    Ok(Expr {
        expr: constructor(a.unwrap_expr(Type::Integer)?, b.unwrap_expr(Type::Integer)?),
        ty: Type::Integer,
        span,
    })
}

/// Selection of variables in a 'for' expression.
///
/// This indicates how many variables must match the for condition
/// for it to be considered true.
#[derive(Debug)]
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

fn compile_for_selection(
    compiler: &Compiler,
    selection: parser::ForSelection,
) -> Result<ForSelection, CompilationError> {
    match selection {
        parser::ForSelection::Any => Ok(ForSelection::Any),
        parser::ForSelection::All => Ok(ForSelection::All),
        parser::ForSelection::None => Ok(ForSelection::None),
        parser::ForSelection::Expr { expr, as_percent } => {
            let expr = compile_expression(compiler, *expr)?;

            Ok(ForSelection::Expr {
                expr: expr.unwrap_expr(Type::Integer)?,
                as_percent,
            })
        }
    }
}

/// Iterator for a 'for' expression over an identifier.
#[derive(Debug)]
pub enum ForIterator {
    Identifier(Identifier),
    Range {
        from: Box<Expression>,
        to: Box<Expression>,
    },
    List(Vec<Expression>),
}

fn compile_for_iterator(
    compiler: &Compiler,
    selection: parser::ForIterator,
) -> Result<ForIterator, CompilationError> {
    match selection {
        parser::ForIterator::Identifier(identifier) => Ok(ForIterator::Identifier(
            compile_identifier(compiler, identifier)?,
        )),
        parser::ForIterator::Range { from, to } => {
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            Ok(ForIterator::Range {
                from: from.unwrap_expr(Type::Integer)?,
                to: to.unwrap_expr(Type::Integer)?,
            })
        }
        parser::ForIterator::List(exprs) => Ok(ForIterator::List(
            exprs
                .into_iter()
                .map(|expr| compile_expression(compiler, expr).map(|v| v.expr))
                .collect::<Result<Vec<_>, _>>()?,
        )),
    }
}

/// Parsed identifier used in expressions.
#[derive(Debug)]
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

fn compile_identifier(
    compiler: &Compiler,
    identifier: parser::Identifier,
) -> Result<Identifier, CompilationError> {
    match identifier {
        parser::Identifier::Raw(s) => Ok(Identifier::Raw(s)),
        parser::Identifier::Subscript {
            identifier,
            subscript,
        } => {
            let subscript = compile_expression(compiler, *subscript)?;

            Ok(Identifier::Subscript {
                identifier: Box::new(compile_identifier(compiler, *identifier)?),
                subscript: Box::new(subscript.expr),
            })
        }
        parser::Identifier::Subfield {
            identifier,
            subfield,
        } => Ok(Identifier::Subfield {
            identifier: Box::new(compile_identifier(compiler, *identifier)?),
            subfield,
        }),
        parser::Identifier::FunctionCall {
            identifier,
            arguments,
        } => {
            let arguments: Result<Vec<_>, _> = arguments
                .into_iter()
                .map(|expr| compile_expression(compiler, expr).map(|v| v.expr))
                .collect();
            Ok(Identifier::FunctionCall {
                identifier: Box::new(compile_identifier(compiler, *identifier)?),
                arguments: arguments?,
            })
        }
    }
}

fn compile_regex(regex: parser::Regex) -> Result<Regex, CompilationError> {
    let parser::Regex {
        mut expr,
        case_insensitive,
        dot_all,
    } = regex;

    let flags = match (case_insensitive, dot_all) {
        (false, false) => "",
        (true, false) => "i",
        (false, true) => "s",
        (true, true) => "is",
    };
    if !flags.is_empty() {
        expr = format!("(?{}){}", flags, expr);
    }

    Regex::new(&expr).map_err(|error| CompilationError {
        // FIXME: get span
        span: 0..1,
        kind: CompilationErrorKind::RegexError { expr, error },
    })
}

#[cfg(test)]
mod tests {
    use super::{Compiler, Type};
    use crate::AddRuleError;
    use boreal_parser::parse_str;

    #[track_caller]
    fn test_compilation(expression_str: &str, expected_type: Type) {
        let rule_str = format!("rule a {{ condition: {} }}", expression_str);
        let mut rules = parse_str(&rule_str).unwrap_or_else(|err| {
            panic!(
                "failed parsing: {}",
                AddRuleError::ParseError(err).to_short_description("mem", &rule_str)
            )
        });
        let rule = rules.pop().unwrap();

        let compiler = Compiler {};
        let res = super::compile_expression(&compiler, rule.condition).unwrap();
        assert_eq!(res.ty, expected_type);
    }

    #[track_caller]
    fn test_compilation_err(expression_str: &str) {
        let rule_str = format!("rule a {{ condition: {} }}", expression_str);
        let mut rules = parse_str(&rule_str).unwrap();
        let rule = rules.pop().unwrap();

        let compiler = Compiler {};
        let res = super::compile_expression(&compiler, rule.condition);
        assert!(res.is_err());
    }

    #[test]
    fn test_primary_expression_types() {
        test_compilation_err("uint8(/a/)");

        test_compilation_err("1 | /a/");
        test_compilation_err("/a/ | 1");
        test_compilation_err("1 ^ /a/");
        test_compilation_err("/a/ ^ 1");
        test_compilation_err("1 & /a/");
        test_compilation_err("/a/ & 1");
        test_compilation_err("1.2 << 1");
        test_compilation_err("1 << 1.2");
        test_compilation_err("1.2 >> 1");
        test_compilation_err("1 >> 1.2");

        test_compilation_err("1 + /a/");
        test_compilation_err("\"a\" + 1");
        test_compilation_err("1 - /a/");
        test_compilation_err("\"a\" - 1");

        test_compilation_err("1 * /a/");
        test_compilation_err("\"a\" * 1");

        test_compilation_err("1 \\ /a/");
        test_compilation_err("\"a\" \\ 1");

        test_compilation_err("1 % 1.2");
        test_compilation_err("1.2 % 1");

        test_compilation_err("~1.2");
        test_compilation_err("-/a/");
    }

    #[test]
    fn test_expression_types() {
        test_compilation_err("1 contains \"a\"");
        test_compilation_err("\"a\" contains 1");

        test_compilation_err("1 icontains \"a\"");
        test_compilation_err("\"a\" icontains 1");

        test_compilation_err("1 startswith \"a\"");
        test_compilation_err("\"a\" startswith 1");

        test_compilation_err("1 istartswith \"a\"");
        test_compilation_err("\"a\" istartswith 1");

        test_compilation_err("1 endswith \"a\"");
        test_compilation_err("\"a\" endswith 1");

        test_compilation_err("1 iendswith \"a\"");
        test_compilation_err("\"a\" iendswith 1");

        test_compilation_err("1 iequals \"a\"");
        test_compilation_err("\"a\" iequals 1");

        test_compilation_err("1 matches /a/");

        test_compilation_err("$a at 1.2");

        test_compilation_err("$a in (1..\"a\")");
        test_compilation_err("$a in (/a/ .. 1)");

        test_compilation_err("!foo [ 1.2 ]");
        test_compilation_err("!foo[/a/]");
        test_compilation_err("#foo in (0../a/)");
        test_compilation_err("#foo in (1.2 .. 3)");
    }

    #[test]
    fn test_compilation_cmp() {
        test_compilation("1 < 2", Type::Boolean);
        test_compilation("1 <= 2.2", Type::Boolean);
        test_compilation("1.1 > 2", Type::Boolean);
        test_compilation("1.1 >= 2.2", Type::Boolean);

        test_compilation("\"a\" > \"b\"", Type::Boolean);
        test_compilation("\"a\" == \"b\"", Type::Boolean);
        test_compilation("\"a\" != \"b\"", Type::Boolean);

        test_compilation_err("\"a\" < 1");
        test_compilation_err("2 == \"b\"");
        test_compilation_err("/a/ != 1");
    }

    #[test]
    fn test_compilation_for_expression() {
        test_compilation("any of them", Type::Boolean);
        test_compilation("all of ($a, $b*)", Type::Boolean);
        test_compilation("all of them in (1..3)", Type::Boolean);
        test_compilation("for any of them: (true)", Type::Boolean);
        test_compilation("for all i in (1, 2): (true)", Type::Boolean);
        test_compilation("for any of them: (1)", Type::Boolean);

        test_compilation_err("/a/ of them");
        test_compilation_err("1.2% of them");
        test_compilation_err("1.2% of them");
        test_compilation_err("any of them in (1../a/)");
        test_compilation_err("any of them in (/a/..2)");
        test_compilation_err("for any i in (1../a/): (true)");
        test_compilation_err("for any i in (/a/..1): (true)");
    }

    #[test]
    fn test_compilation_types() {
        fn test_cmp(op: &str) {
            test_compilation(&format!("1 {} 3", op), Type::Boolean);
            test_compilation(&format!("1 {} 3.5", op), Type::Boolean);
            test_compilation(&format!("1.2 {} 3", op), Type::Boolean);
            test_compilation(&format!("1.2 {} 3.5", op), Type::Boolean);
            test_compilation(&format!("\"a\" {} \"b\"", op), Type::Boolean);
        }

        test_compilation("filesize", Type::Integer);
        test_compilation("entrypoint", Type::Integer);

        test_compilation("uint16(0)", Type::Integer);

        test_compilation("5", Type::Integer);
        test_compilation("5.3", Type::Float);
        test_compilation("-5", Type::Integer);
        test_compilation("-5.3", Type::Float);

        test_compilation("#a in (0..10)", Type::Integer);
        test_compilation("#a", Type::Integer);

        test_compilation("!a", Type::Integer);
        test_compilation("@a", Type::Integer);

        test_compilation("5 + 3", Type::Integer);
        test_compilation("5 + 3.3", Type::Float);
        test_compilation("5.2 + 3", Type::Float);
        test_compilation("5.2 + 3.3", Type::Float);

        test_compilation("5 - 3", Type::Integer);
        test_compilation("5 - 3.3", Type::Float);
        test_compilation("5.2 - 3", Type::Float);
        test_compilation("5.2 - 3.3", Type::Float);

        test_compilation("5 * 3", Type::Integer);
        test_compilation("5 * 3.3", Type::Float);
        test_compilation("5.2 * 3", Type::Float);
        test_compilation("5.2 * 3.3", Type::Float);

        test_compilation("5 \\ 3", Type::Integer);
        test_compilation("5 \\ 3.3", Type::Float);
        test_compilation("5.2 \\ 3", Type::Float);
        test_compilation("5.2 \\ 3.3", Type::Float);

        test_compilation("5 % 3", Type::Integer);

        test_compilation("5 ^ 3", Type::Integer);
        test_compilation("5 | 3", Type::Integer);
        test_compilation("5 & 3", Type::Integer);
        test_compilation("~5", Type::Integer);

        test_compilation("5 << 3", Type::Integer);
        test_compilation("5 >> 3", Type::Integer);

        test_compilation("true and false", Type::Boolean);
        test_compilation("true or false", Type::Boolean);

        test_cmp("<");
        test_cmp("<=");
        test_cmp("<");
        test_cmp(">=");
        test_cmp("==");
        test_cmp("!=");

        test_compilation("\"a\" contains \"b\"", Type::Boolean);
        test_compilation("\"a\" icontains \"b\"", Type::Boolean);
        test_compilation("\"a\" startswith \"b\"", Type::Boolean);
        test_compilation("\"a\" istartswith \"b\"", Type::Boolean);
        test_compilation("\"a\" endswith \"b\"", Type::Boolean);
        test_compilation("\"a\" iequals \"b\"", Type::Boolean);

        test_compilation("\"a\" matches /b/", Type::Boolean);

        test_compilation("defined b", Type::Boolean);
        test_compilation("not true", Type::Boolean);

        test_compilation("true and 1", Type::Boolean);
        test_compilation("1 and true", Type::Boolean);

        test_compilation("true or 1", Type::Boolean);
        test_compilation("1 or true", Type::Boolean);

        test_compilation("not 1", Type::Boolean);

        test_compilation("$a", Type::Boolean);
        test_compilation("$a at 100", Type::Boolean);
        test_compilation("$a in (0..10)", Type::Boolean);

        test_compilation("pe", Type::Undefined);

        test_compilation("\"a\"", Type::String);
        test_compilation("/a/", Type::Regex);

        test_compilation("any of them", Type::Boolean);
        test_compilation("any of them in (0..10)", Type::Boolean);
        test_compilation("for all i in (1,2): (true)", Type::Boolean);
    }
}
