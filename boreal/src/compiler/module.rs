use std::{collections::HashMap, ops::Range};

use boreal_parser as parser;

use super::{compile_expression, CompilationError, Expression, RuleCompiler, Type};
use crate::module::{self, ScanContext, StaticValue, Type as ValueType, Value};

/// Module used during compilation
#[derive(Debug)]
pub struct Module {
    /// Name of the module
    pub name: String,
    /// Static values of the module, usable directly during compilation
    static_values: HashMap<&'static str, StaticValue>,
    /// Dynamic types for values computed during scanning.
    dynamic_types: ValueType,
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

/// Different type of expressions related to the use of a module.
pub enum ModuleExpression {
    /// Operations applied on a module value.
    ModuleUse {
        /// Name of the module to use
        // TODO: optimize this
        module_name: String,

        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },

    /// Operations on a bounded module value.
    BoundedModuleValueUse {
        /// Index on the stack of bounded identifiers that is populated during scanning.
        index: usize,

        /// List of operations to apply to the value to get the final value.
        operations: Vec<ValueOperation>,
    },

    /// A value coming from a function exposed by a module.
    Function {
        /// The function to call with the computed index
        fun: fn(&ScanContext, Vec<Value>) -> Option<Value>,
        /// The expressions that provides the arguments of the function.
        arguments: Vec<Expression>,
        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },
}

// XXX: custom Debug impl needed because derive does not work with the fn fields.
impl std::fmt::Debug for ModuleExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleUse {
                module_name,
                operations,
            } => f
                .debug_struct("ModuleUse")
                .field("module_name", module_name)
                .field("operations", operations)
                .finish(),
            Self::BoundedModuleValueUse { index, operations } => f
                .debug_struct("BoundedModuleValueUse")
                .field("index", index)
                .field("operations", operations)
                .finish(),
            Self::Function {
                fun,
                arguments,
                operations,
            } => f
                .debug_struct("Function")
                .field("fun", &(*fun as usize))
                .field("arguments", arguments)
                .field("operations", operations)
                .finish(),
        }
    }
}

/// Type describing an iterator generated by a module
#[derive(Debug)]
pub enum IteratorType {
    /// An array. This yields elements of the inner type
    Array(ValueType),
    /// A dictionary. This yields two elements: the key (a string), and the value, of the inner
    /// type.
    Dictionary(ValueType),
}

pub(crate) fn compile_module<M: module::Module>(module: &M) -> Module {
    Module {
        name: module.get_name(),
        static_values: module.get_static_values(),
        dynamic_types: ValueType::Object(module.get_dynamic_types()),
    }
}

/// Compile the use of an bounded identifier.
///
/// A for expression can generate an identifier that is referring to a partially resolved module
/// value. This identifier can then be used to compute the value in full, which this function is
/// for.
///
/// For example:
///
/// ```no_rust
/// for any section in pe.sections: (section.virtual_size == 0x00000224)
/// ```
///
/// `pe.sections` will be compiled by [`compile_identifier`], and
/// `section.virtual_size` will be compiled by this function.
pub(super) fn compile_bounded_identifier_use<'a, 'b>(
    compiler: &'b mut RuleCompiler<'a>,
    starting_type: &'b ValueType,
    identifier: parser::Identifier,
    identifier_stack_index: usize,
) -> Result<ModuleUse<'a, 'b>, CompilationError> {
    let mut module_use = ModuleUse {
        module_name: None,
        compiler,
        last_immediate_value: None,
        current_value: ValueOrType::Type(starting_type),
        operations: Vec::with_capacity(identifier.operations.len()),
        current_span: identifier.name_span.clone(),
        identifier_stack_index: Some(identifier_stack_index),
    };

    for op in identifier.operations {
        module_use.add_operation(op)?;
    }

    Ok(module_use)
}

/// Compile the use of an identifier referring to a module.
///
/// This returns an object that can generate either:
/// - an expression and a type, if the use is to be transformed into an expression
/// - a bounded value and an iterator type, if the use is for an iterable.
pub(super) fn compile_identifier<'a, 'b>(
    compiler: &'b mut RuleCompiler<'a>,
    module: &'b Module,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<ModuleUse<'a, 'b>, CompilationError> {
    let nb_ops = identifier.operations.len();

    // Extract first operation, it must be a subfielding.
    let mut ops = identifier.operations.into_iter();
    let first_op = match ops.next() {
        Some(v) => v,
        None => {
            return Err(CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
        }
    };
    let subfield = match &first_op.op {
        parser::IdentifierOperationType::Subfield(subfield) => &*subfield,
        parser::IdentifierOperationType::Subscript(_) => {
            return Err(CompilationError::InvalidIdentifierType {
                actual_type: "object".to_string(),
                expected_type: "array or dictionary".to_string(),
                span: identifier.name_span,
            });
        }
        parser::IdentifierOperationType::FunctionCall(_) => {
            return Err(CompilationError::InvalidIdentifierType {
                actual_type: "object".to_string(),
                expected_type: "function".to_string(),
                span: identifier.name_span,
            });
        }
    };

    // First try to get from the static values
    let mut module_use = match module.static_values.get(&**subfield) {
        Some(value) => ModuleUse {
            module_name: Some(&module.name),
            compiler,
            last_immediate_value: Some(value),
            current_value: ValueOrType::Value(value),
            operations: Vec::with_capacity(nb_ops),
            current_span: identifier.name_span,
            identifier_stack_index: None,
        },
        None => {
            // otherwise, use dynamic types, and apply the first operation (so that it will be
            // applied on scan).
            let mut module_use = ModuleUse {
                module_name: Some(&module.name),
                compiler,
                last_immediate_value: None,
                current_value: ValueOrType::Type(&module.dynamic_types),
                operations: Vec::with_capacity(nb_ops),
                current_span: identifier.name_span,
                identifier_stack_index: None,
            };
            module_use.add_operation(first_op)?;
            module_use
        }
    };

    for op in ops {
        module_use.add_operation(op)?;
    }
    Ok(module_use)
}

#[derive(Debug)]
pub(super) struct ModuleUse<'a, 'b> {
    compiler: &'b mut RuleCompiler<'a>,

    // Last value to can be computed immediately (does not depend on a function to be called during
    // scanning).
    last_immediate_value: Option<&'b StaticValue>,

    // Current value (or type).
    current_value: ValueOrType<'b>,

    // Operations that will need to be evaluated at scanning time.
    operations: Vec<ValueOperation>,

    // Current span of the module + added operations.
    current_span: Range<usize>,

    // stack index for the identifier being compiled. Only set when compiling the use of
    // a identifier bounded from a for expression.
    identifier_stack_index: Option<usize>,
    // TODO: this is WIP with the module rework
    module_name: Option<&'b str>,
}

impl ModuleUse<'_, '_> {
    fn add_operation(&mut self, op: parser::IdentifierOperation) -> Result<(), CompilationError> {
        let res = match op.op {
            parser::IdentifierOperationType::Subfield(subfield) => {
                let res = self.current_value.subfield(&subfield);
                match self.current_value {
                    ValueOrType::Value(v) => self.last_immediate_value = Some(v),
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

    fn into_module_expression(self) -> Option<(ModuleExpression, ValueType)> {
        let ty = self.current_value.into_type()?;
        let expr = match self.identifier_stack_index {
            Some(index) => ModuleExpression::BoundedModuleValueUse {
                index,
                operations: self.operations,
            },
            None => ModuleExpression::ModuleUse {
                module_name: self.module_name.unwrap().to_string(),
                operations: self.operations,
            },
        };
        Some((expr, ty))
    }

    pub(super) fn into_expression(self) -> Option<(Expression, Type)> {
        let (expr, ty) = match self.last_immediate_value {
            Some(value) => {
                let expr = match value {
                    // Those are all primitive values. This means there are no operations applied, and
                    // we can directly generate a primitive expression.
                    StaticValue::Integer(v) => Expression::Number(*v),
                    StaticValue::Float(v) => Expression::Double(*v),
                    StaticValue::Bytes(v) => Expression::Bytes(v.clone()),
                    StaticValue::Regex(v) => Expression::Regex(v.clone()),
                    StaticValue::Boolean(v) => Expression::Boolean(*v),

                    StaticValue::Object(_) => return None,

                    StaticValue::Function { fun, .. } => {
                        let mut ops = self.operations.into_iter();
                        let arguments = if let Some(ValueOperation::FunctionCall(v)) = ops.next() {
                            v
                        } else {
                            return None;
                        };
                        Expression::Module(ModuleExpression::Function {
                            fun: *fun,
                            arguments,
                            operations: ops.collect(),
                        })
                    }
                };
                let ty = self.current_value.into_type()?;

                (expr, ty)
            }
            None => {
                let (module_expr, ty) = self.into_module_expression()?;
                (Expression::Module(module_expr), ty)
            }
        };

        let ty = match ty {
            ValueType::Integer => Type::Integer,
            ValueType::Float => Type::Float,
            ValueType::Bytes => Type::Bytes,
            ValueType::Regex => Type::Regex,
            ValueType::Boolean => Type::Boolean,
            _ => return None,
        };
        Some((expr, ty))
    }

    pub(super) fn into_iterator_expression(self) -> Option<(ModuleExpression, IteratorType)> {
        let (expr, ty) = self.into_module_expression()?;
        let ty = match ty {
            ValueType::Array { value_type, .. } => IteratorType::Array(*value_type),
            ValueType::Dictionary { value_type, .. } => IteratorType::Dictionary(*value_type),
            _ => return None,
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
    Value(&'a StaticValue),
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
                if let StaticValue::Object(map) = value {
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
            Self::Value(_) => (),
            Self::Type(ty) => match ty {
                ValueType::Array { value_type, .. } => {
                    check_subscript_type(Type::Integer)?;
                    *self = Self::Type(value_type);
                    return Ok(());
                }
                ValueType::Dictionary { value_type, .. } => {
                    check_subscript_type(Type::Bytes)?;
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
                if let StaticValue::Function {
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

    fn type_to_string(&self) -> String {
        match self {
            Self::Value(value) => match value {
                StaticValue::Integer(_) => "integer",
                StaticValue::Float(_) => "float",
                StaticValue::Bytes(_) => "bytes",
                StaticValue::Regex(_) => "regex",
                StaticValue::Boolean(_) => "boolean",
                StaticValue::Object(_) => "object",
                StaticValue::Function { .. } => "function",
            },
            Self::Type(ty) => match ty {
                ValueType::Integer => "integer",
                ValueType::Float => "float",
                ValueType::Bytes => "bytes",
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

    fn into_type(self) -> Option<ValueType> {
        match self {
            Self::Value(value) => match value {
                StaticValue::Integer(_) => Some(ValueType::Integer),
                StaticValue::Float(_) => Some(ValueType::Float),
                StaticValue::Bytes(_) => Some(ValueType::Bytes),
                StaticValue::Regex(_) => Some(ValueType::Regex),
                StaticValue::Boolean(_) => Some(ValueType::Boolean),
                _ => None,
            },
            Self::Type(ty) => Some(ty.clone()),
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
        ValueType::Bytes => Some(Type::Bytes),
        ValueType::Regex => Some(Type::Regex),
        ValueType::Boolean => Some(Type::Boolean),
        _ => None,
    }
}
