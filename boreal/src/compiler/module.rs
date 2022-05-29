use std::{collections::HashMap, ops::Range};

use boreal_parser as parser;

use super::{compile_expression, CompilationError, Expression, RuleCompiler, Type};
use crate::module::{self, ScanContext, Type as ValueType, Value};

/// Module used during compilation
#[derive(Debug)]
pub struct Module {
    /// Name of the module
    pub name: String,
    /// Static values of the module, usable directly during compilation
    static_values: HashMap<&'static str, Value>,
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
    /// Operations applied on a dynamic value.
    DynamicValue {
        /// Name of the module to use
        // TODO: optimize this
        module_name: String,

        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },

    /// A value coming from an array exposed by a module.
    Array {
        /// The function to call to get the array
        fun: fn(&ScanContext) -> Option<Vec<Value>>,
        /// The expression giving the index to use with the function.
        subscript: Box<Expression>,
        /// List of operations to apply on the value returned by the function.
        operations: Vec<ValueOperation>,
    },

    /// A value coming from a dictionary exposed by a module.
    Dictionary {
        /// The function to call to get the dictionary
        fun: fn(&ScanContext) -> Option<HashMap<String, Value>>,
        /// The expression giving the index to use with the function.
        subscript: Box<Expression>,
        /// List of operations to apply on the value returned by the function.
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
            Self::DynamicValue {
                module_name,
                operations,
            } => f
                .debug_struct("DynamicValue")
                .field("module_name", module_name)
                .field("operations", operations)
                .finish(),
            Self::Array {
                fun,
                subscript,
                operations,
            } => f
                .debug_struct("Array")
                .field("fun", &(*fun as usize))
                .field("subscript", subscript)
                .field("operations", operations)
                .finish(),
            Self::Dictionary {
                fun,
                subscript,
                operations,
            } => f
                .debug_struct("Dictionary")
                .field("fun", &(*fun as usize))
                .field("subscript", subscript)
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

/// Compile the use of an identifier referring to a module.
///
/// This only accepts uses that yield valid expressions in the end. Therefore, the end value must
/// not be a compound value, but one of integer, floating-point number, string, regex or boolean.
pub(super) fn compile_module_identifier(
    compiler: &mut RuleCompiler<'_>,
    module: &Module,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(Expression, Type), CompilationError> {
    let module_use = compile_identifier(compiler, module, identifier, identifier_span)?;

    module_use
        .into_expression()
        .ok_or_else(|| CompilationError::InvalidIdentifierUse {
            span: identifier_span.clone(),
        })
}

/// Compile the use of an identifier referring to a module, used as an iterator.
///
/// This only accepts uses that can acts as iterators, so arrays or dictionaries.
pub(super) fn compile_module_identifier_as_iterator(
    compiler: &mut RuleCompiler<'_>,
    module: &Module,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(ModuleExpression, IteratorType), CompilationError> {
    let module_use = compile_identifier(compiler, module, identifier, identifier_span)?;

    module_use
        .into_iterator_expression()
        .ok_or_else(|| CompilationError::NonIterableIdentifier {
            span: identifier_span.clone(),
        })
}

/// Compile the use of an identifier that is referring to an iteration value
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
/// `pe.sections` will be compiled by [`compile_module_identifier_as_iterator`], and
/// `section.virtual_size` will be compiled by this function.
pub(super) fn compile_module_identifier_used_in_iteration(
    compiler: &mut RuleCompiler<'_>,
    starting_type: &ValueType,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
    identifier_stack_index: usize,
) -> Result<(Expression, Type), CompilationError> {
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

    module_use
        .into_expression()
        .ok_or_else(|| CompilationError::InvalidIdentifierUse {
            span: identifier_span.clone(),
        })
}

fn compile_identifier<'a, 'b>(
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
struct ModuleUse<'a, 'b> {
    compiler: &'b mut RuleCompiler<'a>,

    // Last value to can be computed immediately (does not depend on a function to be called during
    // scanning).
    last_immediate_value: Option<&'b Value>,

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
                if self.current_value.coalesce_noarg_function() {
                    self.operations.push(ValueOperation::FunctionCall(vec![]));
                }

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

    fn into_expression(mut self) -> Option<(Expression, Type)> {
        if self.current_value.coalesce_noarg_function() {
            self.operations.push(ValueOperation::FunctionCall(vec![]));
        }

        let ty = self.current_value.into_expression_type()?;
        let expr = match self.last_immediate_value {
            // Those are all primitive values. This means there are no operations applied, and
            // we can directly generate a primitive expression.
            Some(Value::Integer(v)) => Expression::Number(*v),
            Some(Value::Float(v)) => Expression::Double(*v),
            Some(Value::String(v)) => Expression::String(v.clone()),
            Some(Value::Regex(v)) => Expression::Regex(v.clone()),
            Some(Value::Boolean(v)) => Expression::Boolean(*v),

            // There is no legitimate situation where we can end up with an object
            // as the last immediate value.
            Some(Value::Object(_)) => return None,

            Some(Value::Array { on_scan, .. }) => {
                let mut ops = self.operations.into_iter();
                let subscript = if let Some(ValueOperation::Subscript(v)) = ops.next() {
                    v
                } else {
                    return None;
                };
                Expression::Module(ModuleExpression::Array {
                    fun: *on_scan,
                    subscript,
                    operations: ops.collect(),
                })
            }
            Some(Value::Dictionary { on_scan, .. }) => {
                let mut ops = self.operations.into_iter();
                let subscript = if let Some(ValueOperation::Subscript(v)) = ops.next() {
                    v
                } else {
                    return None;
                };
                Expression::Module(ModuleExpression::Dictionary {
                    fun: *on_scan,
                    subscript,
                    operations: ops.collect(),
                })
            }
            Some(Value::Function { fun, .. }) => {
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

            // This is a two-step evaluation:
            // - first one is during an iteration: a `Value` will be pushed in the identifier
            //   stack.
            // - second one is when the identifier is used: we need to apply the operations to
            //   the Value retrieved from the stack.
            // Here, we are compiling the second one.
            None => match self.identifier_stack_index {
                Some(index) => Expression::BoundedModuleIdentifier {
                    index,
                    operations: self.operations,
                },
                None => Expression::Module(ModuleExpression::DynamicValue {
                    module_name: self.module_name.unwrap().to_string(),
                    operations: self.operations,
                }),
            },
        };

        Some((expr, ty))
    }

    fn into_iterator_expression(mut self) -> Option<(ModuleExpression, IteratorType)> {
        if self.current_value.coalesce_noarg_function() {
            self.operations.push(ValueOperation::FunctionCall(vec![]));
        }

        let ty = self.current_value.into_iterator_type()?;
        let expr = ModuleExpression::DynamicValue {
            module_name: self.module_name.unwrap().to_string(),
            operations: self.operations,
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

    fn into_iterator_type(self) -> Option<IteratorType> {
        match self {
            Self::Value(value) => match value {
                // TODO: is there a way to avoid those clones?
                Value::Array { value_type, .. } => Some(IteratorType::Array(value_type.clone())),
                Value::Dictionary { value_type, .. } => {
                    Some(IteratorType::Dictionary(value_type.clone()))
                }
                _ => None,
            },
            Self::Type(ty) => match ty {
                ValueType::Array { value_type, .. } => {
                    Some(IteratorType::Array((**value_type).clone()))
                }
                ValueType::Dictionary { value_type, .. } => {
                    Some(IteratorType::Dictionary((**value_type).clone()))
                }
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
