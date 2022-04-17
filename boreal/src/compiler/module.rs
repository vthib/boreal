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
    /// Array subscript, i.e. `value[subscript]`.
    Subscript(Box<Expression>),
    /// Function call, i.e. `value(arguments)`.
    FunctionCall(Vec<Expression>),
}

pub(crate) fn compile_module<M: module::Module>(module: M) -> Module {
    Module {
        name: module.get_name(),
        value: Arc::new(module.get_value()),
    }
}

pub(super) fn compile_identifier(
    compiler: &RuleCompiler<'_>,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(Expression, Type), CompilationError> {
    let module_value = match compiler.file.symbols.get(&identifier.name) {
        Some(v) => Arc::clone(&v.value),
        None => {
            return Err(CompilationError::UnknownIdentifier {
                name: identifier.name,
                span: identifier.name_span,
            })
        }
    };

    let mut previous_span = identifier.name_span.clone();
    let mut checker = TypeChecker::new(&module_value);

    let mut operations = Vec::with_capacity(identifier.operations.len());
    for op in identifier.operations.into_iter() {
        let res = match op.op {
            parser::IdentifierOperationType::Subfield(subfield) => {
                let res = checker.subfield(&subfield);
                operations.push(ValueOperation::Subfield(subfield.to_string()));
                res
            }
            parser::IdentifierOperationType::Subscript(subscript) => {
                let subscript = compile_expression(compiler, *subscript)?;
                operations.push(ValueOperation::Subscript(Box::new(subscript.expr)));
                checker.subscript()
            }
            parser::IdentifierOperationType::FunctionCall(arguments) => {
                let arguments: Result<Vec<_>, _> = arguments
                    .into_iter()
                    .map(|expr| compile_expression(compiler, expr).map(|v| v.expr))
                    .collect();
                operations.push(ValueOperation::FunctionCall(arguments?));
                checker.function_call()
            }
        };

        match res {
            Err(TypeError::UnknownSubfield(subfield)) => {
                return Err(CompilationError::UnknownIdentifierField {
                    field_name: subfield.to_string(),
                    span: op.span,
                });
            }
            Err(TypeError::WrongType {
                actual_type,
                expected_type,
            }) => {
                return Err(CompilationError::InvalidIdentifierType {
                    actual_type,
                    expected_type,
                    span: Range {
                        start: identifier.name_span.start,
                        end: previous_span.end,
                    },
                });
            }
            Ok(()) => (),
        };
        previous_span = op.span.clone();
    }

    // TODO: if we resolved up to a primitive, returning directly the right expression would be
    // better.
    let expr_type = match checker.into_expression_type() {
        Some(ty) => ty,
        None => {
            return Err(CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
        }
    };

    Ok((
        Expression::ModuleValue {
            value: module_value,
            operations,
        },
        expr_type,
    ))
}

/// Used to type-check use of a module in a rule.
///
/// Tries to keep a proper [`Value`] for as long as possible, so that the compiled expression
/// can be optimized if possible (if the end value is a primitive of a function returning a
/// primitive for example).
enum TypeChecker<'a> {
    /// Currently value, if available.
    Value(&'a Value),
    /// Otherwise, type the expression will have when evaluated.
    Type(&'a ValueType),
}

enum TypeError {
    UnknownSubfield(String),
    WrongType {
        actual_type: String,
        expected_type: String,
    },
}

impl<'a> TypeChecker<'a> {
    fn new(value: &'a Value) -> Self {
        Self::Value(value)
    }

    fn subfield(&mut self, subfield: &str) -> Result<(), TypeError> {
        match self {
            Self::Value(value) => match value {
                Value::Dictionary(map) => match map.get(&*subfield) {
                    Some(v) => {
                        *self = Self::Value(v);
                        return Ok(());
                    }
                    None => return Err(TypeError::UnknownSubfield(subfield.to_string())),
                },
                _ => (),
            },
            Self::Type(ty) => match ty {
                ValueType::Dictionary(map) => match map.get(&*subfield) {
                    Some(v) => {
                        *self = Self::Type(v);
                        return Ok(());
                    }
                    None => return Err(TypeError::UnknownSubfield(subfield.to_string())),
                },
                _ => (),
            },
        };

        Err(TypeError::WrongType {
            actual_type: self.type_to_string(),
            expected_type: "dictionary".to_owned(),
        })
    }

    fn subscript(&mut self) -> Result<(), TypeError> {
        match self {
            Self::Value(value) => match value {
                Value::Array { value_type, .. } => {
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                _ => (),
            },
            Self::Type(ty) => match ty {
                ValueType::Array(value_type) => {
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                _ => (),
            },
        }

        Err(TypeError::WrongType {
            actual_type: self.type_to_string(),
            expected_type: "array".to_owned(),
        })
    }

    fn function_call(&mut self) -> Result<(), TypeError> {
        match self {
            Self::Value(value) => match value {
                Value::Function { return_type, .. } => {
                    *self = Self::Type(return_type);
                    return Ok(());
                }
                _ => (),
            },
            Self::Type(ty) => match ty {
                ValueType::Function { return_type } => {
                    *self = Self::Type(return_type);
                    return Ok(());
                }
                _ => (),
            },
        }

        Err(TypeError::WrongType {
            actual_type: self.type_to_string(),
            expected_type: "function".to_owned(),
        })
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
                Value::Dictionary(_) => "dictionary",
                Value::Function { .. } => "function",
            },
            Self::Type(ty) => match ty {
                ValueType::Integer => "integer",
                ValueType::Float => "float",
                ValueType::String => "string",
                ValueType::Regex => "regex",
                ValueType::Boolean => "boolean",
                ValueType::Array { .. } => "array",
                ValueType::Dictionary(_) => "dictionary",
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
