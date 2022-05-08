//! Compiled expression used in a rule.
//!
//! This module contains all types describing a rule condition, built from the parsed AST.
use std::collections::HashSet;
use std::ops::Range;

use regex::bytes::{Regex, RegexBuilder};

use boreal_parser as parser;

use super::{compile_module_identifier, CompilationError, RuleCompiler, ValueOperation};

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(super) enum Type {
    Integer,
    Float,
    String,
    Regex,
    Boolean,
}

impl std::fmt::Display for Type {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(match self {
            Self::Integer => "integer",
            Self::Float => "floating-point number",
            Self::String => "string",
            Self::Regex => "regex",
            Self::Boolean => "boolean",
        })
    }
}

#[derive(Debug)]
pub(super) struct Expr {
    // The raw expression.
    pub(super) expr: Expression,

    // Type of the expression.
    pub(super) ty: Type,

    // Span of the expression.
    pub(super) span: Range<usize>,
}

impl Expr {
    fn check_type(&self, expected_type: Type) -> Result<(), CompilationError> {
        if self.ty != expected_type {
            return Err(CompilationError::ExpressionInvalidType {
                ty: self.ty.to_string(),
                expected_type: expected_type.to_string(),
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

/// Index of a variable in the array of compiled variables stored in the evaluator.
///
/// If None, this indicates an unnamed variable, and the one selected in a for expression must be
/// used (e.g. '$').
#[derive(Copy, Clone, Debug)]
pub struct VariableIndex(pub Option<usize>);

/// Set of multiple variables.
#[derive(Clone, Debug, PartialEq)]
pub struct VariableSet {
    /// Indexes of the variables selected in the set.
    ///
    /// The indexes are relative to the array of compiled variable stored in the compiled rule.
    /// If empty, all variables are selected.
    pub elements: Vec<usize>,
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
        /// Which size and endianness to read.
        ty: parser::ReadIntegerType,
        /// Address/Offset of the input where to read.
        addr: Box<Expression>,
    },

    /// A i64 value.
    Number(i64),

    /// A f64 floating-point value.
    Double(f64),

    /// Count number of matches on a given variable.
    Count(VariableIndex),

    /// Count number of matches on a given variable in a specific range of the input.
    CountInRange {
        /// Index of the variable in the variable array of the compiled rule.
        variable_index: VariableIndex,
        /// Starting offset, included.
        from: Box<Expression>,
        /// Ending offset, included.
        to: Box<Expression>,
    },

    /// Offset of a variable match
    Offset {
        /// Index of the variable in the variable array of the compiled rule.
        variable_index: VariableIndex,

        /// Occurrence number.
        ///
        /// `1` is the first match on the variable, `2` is the next one, etc.
        occurence_number: Box<Expression>,
    },

    /// Length of a variable match
    Length {
        /// Index of the variable in the variable array of the compiled rule.
        variable_index: VariableIndex,

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
    ///
    /// The value is the index of the variable in the variable array in
    /// the compiled rule.
    Variable(VariableIndex),

    /// Does a variable matches at a given offset.
    ///
    /// The first value is the index of the variable in the variable array in
    /// the compiled rule.
    VariableAt {
        /// Index of the variable in the variable array in the compiled rule.
        variable_index: VariableIndex,
        /// Offset where the variable should be searched.
        offset: Box<Expression>,
    },

    /// Does a variable matches in a given offset range.
    VariableIn {
        /// Index of the variable in the variable array in the compiled rule.
        variable_index: VariableIndex,
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
        body: Box<Expression>,
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

        /// Identifiers names & values to bind.
        iterator: ForIterator,

        /// Body to evaluate for each binding.
        body: Box<Expression>,
    },

    /// A value coming from an array exposed by a module.
    ModuleArray {
        /// The function to call with the computed index
        fun: fn(u64) -> Option<crate::module::Value>,
        /// The expression giving the index to use with the function.
        subscript: Box<Expression>,
        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },

    /// A value coming from a dictionary exposed by a module.
    ModuleDictionary {
        /// The function to call with the computed index
        fun: fn(String) -> Option<crate::module::Value>,
        /// The expression giving the index to use with the function.
        subscript: Box<Expression>,
        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },

    /// A value coming from a function exposed by a module.
    ModuleFunction {
        /// The function to call with the computed index
        fun: fn(Vec<crate::module::Value>) -> Option<crate::module::Value>,
        /// The expressions that provides the arguments of the function.
        arguments: Vec<Expression>,
        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },

    /// Dependency on another rule.
    ///
    /// The value is the index of the rule result in the stored rules result vector.
    Rule(usize),

    /// A Bound identifier from a for expression.
    ///
    /// The value is the index on the stack of bounded identifiers that is populated during
    /// scanning.
    BoundIdentifier(usize),

    /// A string.
    String(String),
    /// A regex.
    Regex(Regex),
}

pub(super) fn compile_expression(
    compiler: &mut RuleCompiler<'_>,
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
        parser::ExpressionKind::ReadInteger { ty, addr } => {
            let addr = compile_expression(compiler, *addr)?;

            Ok(Expr {
                expr: Expression::ReadInteger {
                    ty,
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

        parser::ExpressionKind::Count(variable_name) => {
            let variable_index = compiler.find_variable(&variable_name, &span)?;

            Ok(Expr {
                expr: Expression::Count(variable_index),
                ty: Type::Integer,
                span,
            })
        }

        parser::ExpressionKind::CountInRange {
            variable_name,
            from,
            to,
        } => {
            let variable_index = compiler.find_variable(&variable_name, &span)?;
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            Ok(Expr {
                expr: Expression::CountInRange {
                    variable_index,
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
            let variable_index = compiler.find_variable(&variable_name, &span)?;
            let occurence_number = compile_expression(compiler, *occurence_number)?;

            Ok(Expr {
                expr: Expression::Offset {
                    variable_index,
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
            let variable_index = compiler.find_variable(&variable_name, &span)?;
            let occurence_number = compile_expression(compiler, *occurence_number)?;

            Ok(Expr {
                expr: Expression::Length {
                    variable_index,
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

        parser::ExpressionKind::Variable(variable_name) => {
            let variable_index = compiler.find_variable(&variable_name, &span)?;

            Ok(Expr {
                expr: Expression::Variable(variable_index),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::VariableAt {
            variable_name,
            offset,
        } => {
            let variable_index = compiler.find_variable(&variable_name, &span)?;
            let offset = compile_expression(compiler, *offset)?;

            Ok(Expr {
                expr: Expression::VariableAt {
                    variable_index,
                    offset: offset.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::VariableIn {
            variable_name,
            from,
            to,
        } => {
            let variable_index = compiler.find_variable(&variable_name, &span)?;
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            Ok(Expr {
                expr: Expression::VariableIn {
                    variable_index,
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
                set: compile_variable_set(compiler, set, span.clone())?,
                body: match body {
                    Some(body) => {
                        let body = compile_expression(compiler, *body)?;
                        Box::new(body.expr)
                    }
                    None => Box::new(Expression::Variable(VariableIndex(None))),
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
                expr: Expression::For {
                    selection: compile_for_selection(compiler, selection)?,
                    set: compile_variable_set(compiler, set, span.clone())?,
                    body: Box::new(Expression::VariableIn {
                        variable_index: VariableIndex(None),
                        from: from.unwrap_expr(Type::Integer)?,
                        to: to.unwrap_expr(Type::Integer)?,
                    }),
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::ForIdentifiers {
            selection,
            identifiers,
            identifiers_span,
            iterator,
            iterator_span,
            body,
        } => {
            let selection = compile_for_selection(compiler, selection)?;
            let identifiers_len = identifiers.len();
            let iterator = compile_for_iterator(
                compiler,
                iterator,
                iterator_span,
                identifiers_len,
                identifiers_span.clone(),
            )?;

            for name in &identifiers {
                let index = compiler.bounded_identifiers.len();
                if compiler
                    .bounded_identifiers
                    .insert(name.clone(), index)
                    .is_some()
                {
                    return Err(CompilationError::DuplicatedIdentifierBinding {
                        identifier: name.clone(),
                        span: identifiers_span,
                    });
                }
            }
            let body = compile_expression(compiler, *body)?;
            for name in &identifiers {
                let _ = compiler.bounded_identifiers.remove(name);
            }

            Ok(Expr {
                expr: Expression::ForIdentifiers {
                    selection,
                    iterator,
                    body: Box::new(body.expr),
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Identifier(identifier) => {
            let (expr, ty) = compile_identifier(compiler, identifier, &span)?;

            Ok(Expr { expr, ty, span })
        }
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
    compiler: &mut RuleCompiler<'_>,
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
        (Type::Float | Type::Integer, Type::Integer | Type::Float) => Type::Float,
        (Type::String, Type::String) if string_allowed => Type::String,
        _ => {
            return Err(CompilationError::ExpressionIncompatibleTypes {
                left_type: a.ty.to_string(),
                left_span: a.span,
                right_type: b.ty.to_string(),
                right_span: b.span,
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
    compiler: &mut RuleCompiler<'_>,
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
    ///   must match the condition.
    ///   the condition.
    ///
    /// Usually, the expression is a simple number.
    Expr {
        expr: Box<Expression>,
        as_percent: bool,
    },
}

fn compile_for_selection(
    compiler: &mut RuleCompiler<'_>,
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

fn compile_variable_set(
    compiler: &mut RuleCompiler<'_>,
    set: parser::VariableSet,
    span: Range<usize>,
) -> Result<VariableSet, CompilationError> {
    // selected indexes.
    let mut indexes = Vec::new();
    // hashset of already selected indexes.
    let mut indexes_set = HashSet::new();

    for elem in set.elements {
        if elem.1 {
            let mut found = false;

            for (name, index) in &compiler.variables_map {
                if name.starts_with(&elem.0) {
                    found = true;
                    if indexes_set.insert(*index) {
                        indexes.push(*index);
                    }
                }
            }
            if !found {
                // TODO: get better span
                return Err(CompilationError::UnknownVariable {
                    variable_name: elem.0,
                    span,
                });
            }
        } else {
            // TODO: get better span
            let index = compiler.find_named_variable(&elem.0, &span)?;
            if indexes_set.insert(index) {
                indexes.push(index);
            }
        }
    }

    Ok(VariableSet { elements: indexes })
}

/// Iterator for a 'for' expression over an identifier.
#[derive(Debug)]
pub enum ForIterator {
    Range {
        from: Box<Expression>,
        to: Box<Expression>,
    },
    List(Vec<Expression>),
}

fn compile_for_iterator(
    compiler: &mut RuleCompiler<'_>,
    iterator: parser::ForIterator,
    iterator_span: Range<usize>,
    identifiers_len: usize,
    identifiers_span: Range<usize>,
) -> Result<ForIterator, CompilationError> {
    let check_identifiers_len = move |expected_number| {
        if identifiers_len != expected_number {
            return Err(CompilationError::InvalidIdentifierBinding {
                actual_number: identifiers_len,
                expected_number,
                identifiers_span,
                iterator_span,
            });
        }
        Ok(())
    };

    match iterator {
        parser::ForIterator::Identifier(_) => todo!(),
        parser::ForIterator::Range { from, to } => {
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            check_identifiers_len(1)?;

            Ok(ForIterator::Range {
                from: from.unwrap_expr(Type::Integer)?,
                to: to.unwrap_expr(Type::Integer)?,
            })
        }
        parser::ForIterator::List(exprs) => {
            check_identifiers_len(1)?;

            let mut res = Vec::with_capacity(exprs.len());
            for expr in exprs {
                let expr = compile_expression(compiler, expr)?;
                expr.check_type(Type::Integer)?;
                res.push(expr.expr);
            }
            Ok(ForIterator::List(res))
        }
    }
}

fn compile_regex(regex: parser::Regex) -> Result<Regex, CompilationError> {
    let parser::Regex {
        expr,
        case_insensitive,
        dot_all,
        span,
    } = regex;

    RegexBuilder::new(&expr)
        .unicode(false)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_all)
        .build()
        .map_err(|error| CompilationError::RegexError { expr, error, span })
}

fn compile_identifier(
    compiler: &mut RuleCompiler<'_>,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(Expression, Type), CompilationError> {
    // First, try to resolve to a bound identifier.
    if let Some(v) = compiler.bounded_identifiers.get(&identifier.name) {
        if identifier.operations.is_empty() {
            Ok((Expression::BoundIdentifier(*v), Type::Integer))
        } else {
            Err(CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
        }
    // Then, try to resolve to a module. This has precedence over rule names.
    } else if let Some(v) = compiler.namespace.imported_modules.get(&identifier.name) {
        compile_module_identifier(compiler, v, identifier, identifier_span)
    // Finally, try to resolve to an existing rule in the namespace.
    } else if let Some(index) = compiler.namespace.rules_names.get(&identifier.name) {
        if identifier.operations.is_empty() {
            Ok((Expression::Rule(*index), Type::Boolean))
        } else {
            Err(CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
        }
    } else {
        Err(CompilationError::UnknownIdentifier {
            name: identifier.name,
            span: identifier.name_span,
        })
    }
}
