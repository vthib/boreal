//! Compiled expression used in a rule.
//!
//! This module contains all types describing a rule condition, built from the parsed AST.
use std::ops::Range;

use boreal_parser::expression as parser;

use super::module::ModuleExpression;
use super::rule::RuleCompiler;
use super::{module, CompilationError};
use crate::module::Type as ModuleType;
use crate::regex::{regex_ast_to_hir, regex_hir_to_string, Regex};

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(super) enum Type {
    Integer,
    Float,
    Bytes,
    Regex,
    Boolean,
}

impl std::fmt::Display for Type {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(match self {
            Self::Integer => "integer",
            Self::Float => "floating-point number",
            Self::Bytes => "bytes",
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
#[derive(Clone, Debug)]
pub struct VariableSet {
    /// Indexes of the variables selected in the set.
    ///
    /// The indexes are relative to the array of compiled variable stored in the compiled rule.
    pub elements: Vec<usize>,
}

/// Set of multiple rules.
#[derive(Clone, Debug)]
pub struct RuleSet {
    /// Indexes of the rules selected in the set.
    ///
    /// The indexes are relative to the array of rule result.
    pub elements: Vec<usize>,

    /// Number of already matched elements.
    ///
    /// This is set for global rules that are guaranteed to be matched, and have no indexes to
    /// add in the elements vec.
    pub already_matched: usize,
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
    Integer(i64),

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

    /// Not Equal
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

    /// Depend on multiple rules already declared in the namespace.
    ///
    /// If the number of matching rules in the set matches the `selection`,
    /// this expression returns true.
    ForRules {
        /// How many rules must match for this expression to be true.
        selection: ForSelection,

        /// Which rules to select.
        set: RuleSet,
    },

    /// Call into a module
    Module(ModuleExpression),

    /// Dependency on another rule.
    ///
    /// The value is the index of the rule result in the stored rules result vector.
    Rule(usize),

    /// Dependency on an externally defined symbol.
    ///
    /// The value is the index into the external symbols vector stored in the compiled rules.
    ExternalSymbol(usize),

    /// A byte string.
    Bytes(Vec<u8>),

    /// A regex.
    Regex(Regex),
}

pub(super) fn compile_bool_expression(
    compiler: &mut RuleCompiler<'_>,
    expression: parser::Expression,
) -> Result<Expression, CompilationError> {
    compile_expression(compiler, expression).and_then(|e| to_bool_expr(compiler, e))
}

// TODO: have a limit to ensure we do not grow the stack too much. About 33 chained ANDs was
// enough previously.
pub(super) fn compile_expression(
    compiler: &mut RuleCompiler<'_>,
    expression: parser::Expression,
) -> Result<Expr, CompilationError> {
    let span = expression.span;

    compiler.condition_depth += 1;
    if compiler.condition_depth >= compiler.params.max_condition_depth {
        return Err(CompilationError::ConditionTooDeep { span });
    }

    let res = match expression.expr {
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

        parser::ExpressionKind::Integer(v) => Ok(Expr {
            expr: Expression::Integer(v),
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
            variable_name_span,
            from,
            to,
        } => {
            let variable_index = compiler.find_variable(&variable_name, &variable_name_span)?;
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
            compile_primary_op(compiler, *left, *right, span, Expression::Add, false, false)
        }
        parser::ExpressionKind::Sub(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Sub, false, false)
        }
        parser::ExpressionKind::Mul(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Mul, false, false)
        }
        parser::ExpressionKind::Div(left, right) => {
            compile_primary_op(compiler, *left, *right, span, Expression::Div, false, false)
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

        parser::ExpressionKind::And(ops) => {
            let ops = ops
                .into_iter()
                .map(|op| compile_expression(compiler, op).and_then(|e| to_bool_expr(compiler, e)))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Expr {
                expr: Expression::And(ops),
                ty: Type::Boolean,
                span,
            })
        }
        parser::ExpressionKind::Or(ops) => {
            let ops = ops
                .into_iter()
                .map(|op| compile_expression(compiler, op).and_then(|e| to_bool_expr(compiler, e)))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Expr {
                expr: Expression::Or(ops),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Not(expr) => {
            let expr = compile_expression(compiler, *expr)?;
            let expr = to_bool_expr(compiler, expr)?;

            Ok(Expr {
                expr: Expression::Not(Box::new(expr)),
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
                false,
            )?;
            res.ty = Type::Boolean;
            Ok(res)
        }

        parser::ExpressionKind::Eq(left, right) => {
            let mut res =
                compile_primary_op(compiler, *left, *right, span, Expression::Eq, true, true)?;
            res.ty = Type::Boolean;
            Ok(res)
        }

        parser::ExpressionKind::NotEq(left, right) => {
            let mut res =
                compile_primary_op(compiler, *left, *right, span, Expression::NotEq, true, true)?;
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
                    haystack: haystack.unwrap_expr(Type::Bytes)?,
                    needle: needle.unwrap_expr(Type::Bytes)?,
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
                    expr: expr.unwrap_expr(Type::Bytes)?,
                    prefix: prefix.unwrap_expr(Type::Bytes)?,
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
                    expr: expr.unwrap_expr(Type::Bytes)?,
                    suffix: suffix.unwrap_expr(Type::Bytes)?,
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
                    left.unwrap_expr(Type::Bytes)?,
                    right.unwrap_expr(Type::Bytes)?,
                ),
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::Matches(expr, regex) => {
            let expr = compile_expression(compiler, *expr)?;

            Ok(Expr {
                expr: Expression::Matches(
                    expr.unwrap_expr(Type::Bytes)?,
                    compile_regex(compiler, regex)?,
                ),
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
            variable_name_span,
            offset,
        } => {
            let variable_index = compiler.find_variable(&variable_name, &variable_name_span)?;
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
            variable_name_span,
            from,
            to,
        } => {
            let variable_index = compiler.find_variable(&variable_name, &variable_name_span)?;
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
                        Box::new(to_bool_expr(compiler, body)?)
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

        parser::ExpressionKind::ForAt {
            selection,
            set,
            offset,
        } => {
            let offset = compile_expression(compiler, *offset)?;

            Ok(Expr {
                expr: Expression::For {
                    selection: compile_for_selection(compiler, selection)?,
                    set: compile_variable_set(compiler, set, span.clone())?,
                    body: Box::new(Expression::VariableAt {
                        variable_index: VariableIndex(None),
                        offset: offset.unwrap_expr(Type::Integer)?,
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
            let iterator = compile_for_iterator(
                compiler,
                iterator,
                &iterator_span,
                &identifiers,
                &identifiers_span,
            )?;
            let body = compile_expression(compiler, *body)?;
            for name in &identifiers {
                compiler.remove_bounded_identifier(name);
            }

            Ok(Expr {
                expr: Expression::ForIdentifiers {
                    selection,
                    iterator,
                    body: Box::new(to_bool_expr(compiler, body)?),
                },
                ty: Type::Boolean,
                span,
            })
        }

        parser::ExpressionKind::ForRules { selection, set } => Ok(Expr {
            expr: Expression::ForRules {
                selection: compile_for_selection(compiler, selection)?,
                set: compile_rule_set(compiler, set)?,
            },
            ty: Type::Boolean,
            span,
        }),

        parser::ExpressionKind::Identifier(identifier) => {
            let (expr, ty) = compile_identifier(compiler, identifier, &span)?;

            Ok(Expr { expr, ty, span })
        }
        parser::ExpressionKind::Bytes(s) => Ok(Expr {
            expr: Expression::Bytes(s),
            ty: Type::Bytes,
            span,
        }),
        parser::ExpressionKind::Regex(regex) => Ok(Expr {
            expr: Expression::Regex(compile_regex(compiler, regex)?),
            ty: Type::Regex,
            span,
        }),
    };
    compiler.condition_depth -= 1;
    res
}

fn to_bool_expr(
    compiler: &mut RuleCompiler<'_>,
    expr: Expr,
) -> Result<Expression, CompilationError> {
    if expr.ty == Type::Bytes {
        compiler.add_warning(CompilationError::ImplicitBytesToBooleanCast {
            span: expr.span.clone(),
        })?;
    }
    Ok(expr.expr)
}

fn compile_primary_op<F>(
    compiler: &mut RuleCompiler<'_>,
    a: parser::Expression,
    b: parser::Expression,
    span: Range<usize>,
    constructor: F,
    string_allowed: bool,
    bool_allowed: bool,
) -> Result<Expr, CompilationError>
where
    F: Fn(Box<Expression>, Box<Expression>) -> Expression,
{
    let a = compile_expression(compiler, a)?;
    let b = compile_expression(compiler, b)?;

    let ty = match (a.ty, b.ty) {
        (Type::Integer, Type::Integer) => Type::Integer,
        (Type::Float | Type::Integer, Type::Integer | Type::Float) => Type::Float,
        (Type::Bytes, Type::Bytes) if string_allowed => Type::Bytes,
        (Type::Boolean, Type::Boolean) if bool_allowed => Type::Boolean,
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

    // A for expression on an empty set is not allowed by YARA.
    // The empty set (or "them") acts as a "($*)" element.
    if set.elements.is_empty() {
        if compiler.variables.is_empty() {
            return Err(CompilationError::UnknownVariable {
                variable_name: "*".to_string(),
                span,
            });
        }

        indexes.extend(0..compiler.variables.len());
        for var in &mut compiler.variables {
            var.used = true;
        }
    }

    for elem in set.elements {
        if elem.is_wildcard {
            let mut found = false;

            for (index, var) in compiler.variables.iter_mut().enumerate() {
                if var.name.starts_with(&elem.name) {
                    found = true;
                    var.used = true;
                    indexes.push(index);
                }
            }
            if !found {
                return Err(CompilationError::UnknownVariable {
                    variable_name: format!("{}*", elem.name),
                    span: elem.span,
                });
            }
        } else {
            let index = compiler.find_named_variable(&elem.name, &elem.span)?;
            indexes.push(index);
        }
    }

    Ok(VariableSet { elements: indexes })
}

fn compile_rule_set(
    compiler: &mut RuleCompiler<'_>,
    set: parser::RuleSet,
) -> Result<RuleSet, CompilationError> {
    // selected indexes.
    let mut indexes = Vec::new();
    let mut already_matched = 0;

    for elem in set.elements {
        if elem.is_wildcard {
            let mut found = false;

            for (name, index) in &compiler.namespace.rules_indexes {
                if name.starts_with(&elem.name) {
                    found = true;
                    match index {
                        // Normal rule, add it to the list of indexes to check
                        Some(index) => indexes.push(*index),
                        // Global rule: it is guaranteed to be matched, so add it to the already
                        // matched counter
                        None => already_matched += 1,
                    }
                }
            }
            if !found {
                return Err(CompilationError::UnknownIdentifier {
                    name: format!("{}*", elem.name),
                    span: elem.span,
                });
            }
            compiler.rule_wildcard_uses.push(elem.name);
        } else {
            match compiler.namespace.rules_indexes.get(&elem.name) {
                Some(Some(index)) => indexes.push(*index),
                Some(None) => already_matched += 1,
                None => {
                    return Err(CompilationError::UnknownIdentifier {
                        name: elem.name,
                        span: elem.span,
                    })
                }
            }
        }
    }

    Ok(RuleSet {
        elements: indexes,
        already_matched,
    })
}

/// Iterator for a 'for' expression over an identifier.
#[derive(Debug)]
pub enum ForIterator {
    ModuleIterator(ModuleExpression),
    Range {
        from: Box<Expression>,
        to: Box<Expression>,
    },
    List(Vec<Expression>),
}

fn compile_for_iterator(
    compiler: &mut RuleCompiler<'_>,
    iterator: parser::ForIterator,
    iterator_span: &Range<usize>,
    identifiers: &[String],
    identifiers_span: &Range<usize>,
) -> Result<ForIterator, CompilationError> {
    let invalid_binding = |expected_number| {
        Err(CompilationError::InvalidIdentifierBinding {
            actual_number: identifiers.len(),
            expected_number,
            identifiers_span: identifiers_span.clone(),
            iterator_span: iterator_span.clone(),
        })
    };

    match iterator {
        parser::ForIterator::Identifier(identifier) => {
            let (expr, iterator_type) =
                compile_identifier_as_iterator(compiler, identifier, iterator_span)?;

            match iterator_type {
                module::IteratorType::Array(value_type) => {
                    match &identifiers {
                        &[name] => {
                            compiler.add_bounded_identifier(name, value_type, identifiers_span)?;
                        }
                        _ => invalid_binding(1)?,
                    };
                }
                module::IteratorType::Dictionary(value_type) => match &identifiers {
                    &[key, value] => {
                        compiler.add_bounded_identifier(
                            key,
                            ModuleType::Bytes,
                            identifiers_span,
                        )?;
                        compiler.add_bounded_identifier(value, value_type, identifiers_span)?;
                    }
                    _ => invalid_binding(2)?,
                },
            };

            Ok(ForIterator::ModuleIterator(expr))
        }
        parser::ForIterator::Range { from, to } => {
            let from = compile_expression(compiler, *from)?;
            let to = compile_expression(compiler, *to)?;

            match &identifiers {
                &[name] => {
                    compiler.add_bounded_identifier(name, ModuleType::Integer, identifiers_span)?;
                }

                _ => invalid_binding(1)?,
            };

            Ok(ForIterator::Range {
                from: from.unwrap_expr(Type::Integer)?,
                to: to.unwrap_expr(Type::Integer)?,
            })
        }
        parser::ForIterator::List(exprs) => {
            let mut res = Vec::with_capacity(exprs.len());
            let mut bounded_type = None;
            for expr in exprs {
                let expr = compile_expression(compiler, expr)?;
                match (bounded_type, expr.ty) {
                    (None, Type::Integer) => bounded_type = Some(Type::Integer),
                    (None, Type::Bytes) => bounded_type = Some(Type::Bytes),
                    (None, ty) => {
                        return Err(CompilationError::ExpressionInvalidType {
                            ty: ty.to_string(),
                            expected_type: "integer or bytes".to_owned(),
                            span: expr.span,
                        });
                    }

                    (Some(ty), _) => expr.check_type(ty)?,
                }
                res.push(expr.expr);
            }

            let module_type = match bounded_type {
                Some(Type::Bytes) => ModuleType::Bytes,
                _ => ModuleType::Integer,
            };

            match &identifiers {
                &[name] => {
                    compiler.add_bounded_identifier(name, module_type, identifiers_span)?;
                }

                _ => invalid_binding(1)?,
            };

            Ok(ForIterator::List(res))
        }
    }
}

fn compile_regex(
    compiler: &mut RuleCompiler<'_>,
    regex: boreal_parser::regex::Regex,
) -> Result<Regex, CompilationError> {
    let boreal_parser::regex::Regex {
        ast,
        case_insensitive,
        dot_all,
        span,
    } = regex;

    let mut warnings = Vec::new();
    let hir = regex_ast_to_hir(ast, &mut warnings);
    for warn in warnings {
        compiler.add_warning(warn.into())?;
    }

    Regex::from_string(regex_hir_to_string(&hir), case_insensitive, dot_all)
        .map_err(|error| CompilationError::RegexError { error, span })
}

fn compile_identifier(
    compiler: &mut RuleCompiler<'_>,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(Expression, Type), CompilationError> {
    // First, try to resolve to a bound identifier.
    let res = compiler.bounded_identifiers.get(&identifier.name).cloned();
    if let Some((identifier_type, index)) = res.as_deref() {
        let module_use =
            module::compile_bounded_identifier_use(compiler, identifier_type, identifier, *index)?;

        module_use
            .into_expression()
            .ok_or_else(|| CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
    // Then, try to resolve to a module. This has precedence over rule names.
    } else if let Some(module) = compiler.namespace.imported_modules.get(&identifier.name) {
        let module_use = module::compile_identifier(compiler, module, identifier, identifier_span)?;

        module_use
            .into_expression()
            .ok_or_else(|| CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
    // Then, try to resolve to an existing rule in the namespace.
    } else if let Some(index) = compiler.namespace.rules_indexes.get(&identifier.name) {
        if identifier.operations.is_empty() {
            let expr = match index {
                Some(index) => Expression::Rule(*index),
                // The referenced rule is global. Since this rule can only be evaluated if all
                // global rules pass, then this can be just replaced by true.
                None => Expression::Boolean(true),
            };
            Ok((expr, Type::Boolean))
        } else {
            Err(CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
        }
    // Finally, try to resolve to an external symbol.
    } else if let Some((index, value)) =
        super::external_symbol::get_external_symbol(compiler, &identifier.name)
    {
        Ok((Expression::ExternalSymbol(index), value.get_type()))
    } else {
        Err(CompilationError::UnknownIdentifier {
            name: identifier.name,
            span: identifier.name_span,
        })
    }
}

fn compile_identifier_as_iterator(
    compiler: &mut RuleCompiler<'_>,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(ModuleExpression, module::IteratorType), CompilationError> {
    // First, try to resolve to a bound identifier.
    let res = compiler.bounded_identifiers.get(&identifier.name).cloned();
    let module_use = if let Some((identifier_type, index)) = res.as_deref() {
        module::compile_bounded_identifier_use(compiler, identifier_type, identifier, *index)?
    // Then, try to resolve to a module. This has precedence over rule names.
    } else if let Some(module) = compiler.namespace.imported_modules.get(&identifier.name) {
        module::compile_identifier(compiler, module, identifier, identifier_span)?
    // Finally, try to resolve to an existing rule in the namespace.
    } else if compiler
        .namespace
        .rules_indexes
        .get(&identifier.name)
        .is_some()
    {
        return Err(CompilationError::NonIterableIdentifier {
            span: identifier_span.clone(),
        });
    } else {
        return Err(CompilationError::UnknownIdentifier {
            name: identifier.name,
            span: identifier.name_span,
        });
    };

    module_use
        .into_iterator_expression()
        .ok_or_else(|| CompilationError::NonIterableIdentifier {
            span: identifier_span.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    #[test]
    fn test_types_traits() {
        test_type_traits(Type::Integer);
        test_type_traits(VariableIndex(None));
        test_type_traits(VariableSet {
            elements: Vec::new(),
        });
        test_type_traits(RuleSet {
            elements: Vec::new(),
            already_matched: 0,
        });
        test_type_traits_non_clonable(Expr {
            expr: Expression::Boolean(true),
            ty: Type::Boolean,
            span: 0..1,
        });
        test_type_traits_non_clonable(Expression::Boolean(true));
        test_type_traits_non_clonable(ForSelection::Any);
        test_type_traits_non_clonable(ForIterator::List(Vec::new()));
    }
}
