use std::{ops::Range, sync::Arc};

use boreal_parser as parser;

use super::{compile_expression, CompilationError, Expression, RuleCompiler, Type};
use crate::module::{self, Type as ValueType, Value};

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub value: Arc<Value>,
}

/// Operations on identifiers.
#[derive(Debug)]
pub enum ValueOperation {
    /// Object subfield, i.e. `value.subfield`.
    Subfield(String),
    /// Array/dict subscript, i.e. `value[subscript]`.
    Subscript(Box<Expression>),
    /// Function call, i.e. `value(arguments)`.
    FunctionCall(Vec<Expression>),
}

// XXX: I want to pass by value, as in the future, we might want to keep the owned module around.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn compile_module<M: module::Module>(module: M) -> Module {
    Module {
        name: module.get_name(),
        value: Arc::new(module.get_value()),
    }
}

pub(super) fn compile_module_identifier(
    compiler: &RuleCompiler<'_>,
    module_value: &Value,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(Expression, Type), CompilationError> {
    let mut module_use = ModuleUse {
        compiler,
        last_immediate_value: module_value,
        current_value: ValueOrType::Value(module_value),
        operations: Vec::with_capacity(identifier.operations.len()),
        current_span: identifier.name_span.clone(),
    };

    for op in identifier.operations {
        module_use.add_operation(op)?;
    }

    module_use
        .into_expression()
        .ok_or_else(|| CompilationError::InvalidIdentifierUse {
            span: identifier_span.clone(),
        })
}

struct ModuleUse<'a> {
    compiler: &'a RuleCompiler<'a>,

    // Last value to can be computed immediately (does not depend on a function to be called during
    // scanning).
    last_immediate_value: &'a Value,

    // Current value (or type).
    current_value: ValueOrType<'a>,

    // Operations that will need to be evaluated at scanning time.
    operations: Vec<ValueOperation>,

    // Current span of the module + added operations.
    current_span: Range<usize>,
}

impl ModuleUse<'_> {
    fn add_operation(&mut self, op: parser::IdentifierOperation) -> Result<(), CompilationError> {
        let res = match op.op {
            parser::IdentifierOperationType::Subfield(subfield) => {
                if self.current_value.coalesce_noarg_function() {
                    self.operations.push(ValueOperation::FunctionCall(vec![]));
                }

                let res = self.current_value.subfield(&subfield);
                match self.current_value {
                    ValueOrType::Value(v) => self.last_immediate_value = v,
                    ValueOrType::Type(_) => {
                        self.operations
                            .push(ValueOperation::Subfield(subfield.to_string()));
                    }
                }
                res
            }
            parser::IdentifierOperationType::Subscript(subscript) => {
                let subscript = compile_expression(self.compiler, *subscript)?;

                self.operations
                    .push(ValueOperation::Subscript(Box::new(subscript.expr)));
                self.current_value.subscript(subscript.ty, subscript.span)
            }
            parser::IdentifierOperationType::FunctionCall(arguments) => {
                let mut arguments_exprs = Vec::with_capacity(arguments.len());
                let mut arguments_types = Vec::with_capacity(arguments.len());
                for arg in arguments {
                    let res = compile_expression(self.compiler, arg)?;
                    arguments_exprs.push(res.expr);
                    arguments_types.push(res.ty);
                }
                self.operations
                    .push(ValueOperation::FunctionCall(arguments_exprs));
                self.current_value.function_call(&arguments_types)
            }
        };

        match res {
            Err(TypeError::UnknownSubfield(subfield)) => {
                Err(CompilationError::UnknownIdentifierField {
                    field_name: subfield,
                    span: op.span,
                })
            }
            Err(TypeError::WrongType {
                actual_type,
                expected_type,
            }) => Err(CompilationError::InvalidIdentifierType {
                actual_type,
                expected_type,
                span: self.current_span.clone(),
            }),
            Err(TypeError::WrongIndexType {
                actual_type,
                expected_type,
                span,
            }) => Err(CompilationError::InvalidIdentifierIndexType {
                ty: actual_type.to_string(),
                span,
                expected_type: expected_type.to_string(),
            }),
            Err(TypeError::WrongFunctionArguments { arguments_types }) => {
                Err(CompilationError::InvalidIdentifierCall {
                    arguments_types,
                    span: op.span,
                })
            }
            Ok(()) => {
                self.current_span.end = op.span.end;
                Ok(())
            }
        }
    }

    fn into_expression(mut self) -> Option<(Expression, Type)> {
        if self.current_value.coalesce_noarg_function() {
            self.operations.push(ValueOperation::FunctionCall(vec![]));
        }

        let ty = self.current_value.into_expression_type()?;

        let expr = match self.last_immediate_value {
            // Those are all primitive values. This means there are no operations applied, and
            // we can directly generate a primitive expression.
            Value::Integer(v) => Expression::Number(*v),
            Value::Float(v) => Expression::Double(*v),
            Value::String(v) => Expression::String(v.clone()),
            Value::Regex(v) => Expression::Regex(v.clone()),
            Value::Boolean(v) => Expression::Boolean(*v),

            // There is no legitimate situation where we can end up with an object
            // as the last immediate value.
            Value::Object(_) => return None,

            Value::Array { on_scan, .. } => {
                let mut ops = self.operations.into_iter();
                let subscript = if let Some(ValueOperation::Subscript(v)) = ops.next() {
                    v
                } else {
                    // This is unreachable code, but avoid a call to unreachable!() to prevent
                    // panic code.
                    debug_assert!(false);
                    return None;
                };
                Expression::ModuleArray {
                    fun: *on_scan,
                    subscript,
                    operations: ops.collect(),
                }
            }
            Value::Dictionary { on_scan, .. } => {
                let mut ops = self.operations.into_iter();
                let subscript = if let Some(ValueOperation::Subscript(v)) = ops.next() {
                    v
                } else {
                    // This is unreachable code, but avoid a call to unreachable!() to prevent
                    // panic code.
                    debug_assert!(false);
                    return None;
                };
                Expression::ModuleDictionary {
                    fun: *on_scan,
                    subscript,
                    operations: ops.collect(),
                }
            }
            Value::Function { fun, .. } => {
                let mut ops = self.operations.into_iter();
                let arguments = if let Some(ValueOperation::FunctionCall(v)) = ops.next() {
                    v
                } else {
                    // This is unreachable code, but avoid a call to unreachable!() to prevent
                    // panic code.
                    debug_assert!(false);
                    return None;
                };
                Expression::ModuleFunction {
                    fun: *fun,
                    arguments,
                    operations: ops.collect(),
                }
            }
        };

        Some((expr, ty))
    }
}

/// Used to type-check use of a module in a rule.
///
/// Tries to keep a proper [`Value`] for as long as possible, so that the compiled expression
/// can be optimized if possible (if the end value is a primitive of a function returning a
/// primitive for example).
#[derive(Debug)]
enum ValueOrType<'a> {
    /// Currently value, if available.
    Value(&'a Value),
    /// Otherwise, type the expression will have when evaluated.
    Type(&'a ValueType),
}

#[derive(Debug)]
enum TypeError {
    UnknownSubfield(String),
    WrongType {
        actual_type: String,
        expected_type: String,
    },
    WrongIndexType {
        actual_type: Type,
        expected_type: Type,
        span: Range<usize>,
    },
    WrongFunctionArguments {
        arguments_types: Vec<String>,
    },
}

impl ValueOrType<'_> {
    fn subfield(&mut self, subfield: &str) -> Result<(), TypeError> {
        match self {
            Self::Value(value) => {
                if let Value::Object(map) = value {
                    match map.get(&*subfield) {
                        Some(v) => {
                            *self = Self::Value(v);
                            return Ok(());
                        }
                        None => return Err(TypeError::UnknownSubfield(subfield.to_string())),
                    }
                }
            }
            Self::Type(ty) => {
                if let ValueType::Object(map) = ty {
                    match map.get(&*subfield) {
                        Some(v) => {
                            *self = Self::Type(v);
                            return Ok(());
                        }
                        None => return Err(TypeError::UnknownSubfield(subfield.to_string())),
                    }
                }
            }
        };

        Err(TypeError::WrongType {
            actual_type: self.type_to_string(),
            expected_type: "object".to_owned(),
        })
    }

    fn subscript(
        &mut self,
        subscript_type: Type,
        subscript_span: Range<usize>,
    ) -> Result<(), TypeError> {
        let check_subscript_type = |expected_type: Type| {
            if subscript_type == expected_type {
                Ok(())
            } else {
                Err(TypeError::WrongIndexType {
                    actual_type: subscript_type,
                    expected_type,
                    span: subscript_span,
                })
            }
        };

        match self {
            Self::Value(value) => match value {
                Value::Array { value_type, .. } => {
                    check_subscript_type(Type::Integer)?;
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                Value::Dictionary { value_type, .. } => {
                    check_subscript_type(Type::String)?;
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                _ => (),
            },
            Self::Type(ty) => match ty {
                ValueType::Array { value_type, .. } => {
                    check_subscript_type(Type::Integer)?;
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                ValueType::Dictionary { value_type, .. } => {
                    check_subscript_type(Type::String)?;
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                _ => (),
            },
        }

        Err(TypeError::WrongType {
            actual_type: self.type_to_string(),
            expected_type: "array or dictionary".to_string(),
        })
    }

    fn function_call(&mut self, actual_args_types: &[Type]) -> Result<(), TypeError> {
        match self {
            Self::Value(value) => {
                if let Value::Function {
                    arguments_types,
                    return_type,
                    ..
                } = value
                {
                    check_all_arguments_types(arguments_types, actual_args_types)?;
                    *self = Self::Type(return_type);
                    return Ok(());
                }
            }
            Self::Type(ty) => {
                if let ValueType::Function {
                    arguments_types,
                    return_type,
                } = ty
                {
                    check_all_arguments_types(arguments_types, actual_args_types)?;
                    *self = Self::Type(return_type);
                    return Ok(());
                }
            }
        }

        Err(TypeError::WrongType {
            actual_type: self.type_to_string(),
            expected_type: "function".to_owned(),
        })
    }

    // Coalesce function with no arguments to its return type.
    //
    // This allows using a function with no arguments without the `()` syntax, enabling
    // use of such functions transparently for properties that need to be computed
    // at scan time.
    fn coalesce_noarg_function(&mut self) -> bool {
        match self {
            Self::Value(value) => {
                if let Value::Function {
                    arguments_types,
                    return_type,
                    ..
                } = value
                {
                    if arguments_types.is_empty() {
                        *self = Self::Type(return_type);
                        return true;
                    }
                }
            }
            Self::Type(ty) => {
                if let ValueType::Function {
                    arguments_types,
                    return_type,
                } = ty
                {
                    if arguments_types.is_empty() {
                        *self = Self::Type(return_type);
                        return true;
                    }
                }
            }
        }
        false
    }

    fn type_to_string(&self) -> String {
        match self {
            Self::Value(value) => match value {
                Value::Integer(_) => "integer",
                Value::Float(_) => "float",
                Value::String(_) => "string",
                Value::Regex(_) => "regex",
                Value::Boolean(_) => "boolean",
                Value::Array { .. } => "array",
                Value::Dictionary { .. } => "dict",
                Value::Object(_) => "object",
                Value::Function { .. } => "function",
            },
            Self::Type(ty) => match ty {
                ValueType::Integer => "integer",
                ValueType::Float => "float",
                ValueType::String => "string",
                ValueType::Regex => "regex",
                ValueType::Boolean => "boolean",
                ValueType::Array { .. } => "array",
                ValueType::Dictionary { .. } => "dict",
                ValueType::Object(_) => "object",
                ValueType::Function { .. } => "function",
            },
        }
        .to_owned()
    }

    fn into_expression_type(self) -> Option<Type> {
        match self {
            Self::Value(value) => match value {
                Value::Integer(_) => Some(Type::Integer),
                Value::Float(_) => Some(Type::Float),
                Value::String(_) => Some(Type::String),
                Value::Regex(_) => Some(Type::Regex),
                Value::Boolean(_) => Some(Type::Boolean),
                _ => None,
            },
            Self::Type(ty) => match ty {
                ValueType::Integer => Some(Type::Integer),
                ValueType::Float => Some(Type::Float),
                ValueType::String => Some(Type::String),
                ValueType::Regex => Some(Type::Regex),
                ValueType::Boolean => Some(Type::Boolean),
                _ => None,
            },
        }
    }
}

fn check_all_arguments_types(
    valid_types_vec: &[Vec<ValueType>],
    actual_types: &[Type],
) -> Result<(), TypeError> {
    if valid_types_vec.is_empty() && actual_types.is_empty() {
        return Ok(());
    }

    for valid_types in valid_types_vec {
        if arguments_types_are_equal(valid_types, actual_types) {
            return Ok(());
        }
    }

    Err(TypeError::WrongFunctionArguments {
        arguments_types: actual_types.iter().map(ToString::to_string).collect(),
    })
}

fn arguments_types_are_equal(valid_types: &[ValueType], actual_types: &[Type]) -> bool {
    if valid_types.len() != actual_types.len() {
        return false;
    }
    for (expected, actual) in valid_types.iter().zip(actual_types.iter()) {
        let expected = module_type_to_expr_type(expected);
        if let Some(expected) = expected {
            if expected != *actual {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

fn module_type_to_expr_type(v: &ValueType) -> Option<Type> {
    match v {
        ValueType::Integer => Some(Type::Integer),
        ValueType::Float => Some(Type::Float),
        ValueType::String => Some(Type::String),
        ValueType::Regex => Some(Type::Regex),
        ValueType::Boolean => Some(Type::Boolean),
        _ => None,
    }
}
