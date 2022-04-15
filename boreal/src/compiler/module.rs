use std::ops::Range;

use boreal_parser as parser;

use super::{compile_expression, CompilationError, Expression, RuleCompiler, Type};
use crate::module::{self, Type as ValueType, Value};

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub value: Value,
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
        value: module.get_value(),
    }
}

pub(super) fn compile_identifier(
    compiler: &RuleCompiler<'_>,
    identifier: parser::Identifier,
    identifier_span: &Range<usize>,
) -> Result<(Expression, Type), CompilationError> {
    let mut value = match compiler.file.symbols.get(&identifier.name) {
        Some(v) => &v.value,
        None => {
            return Err(CompilationError::UnknownIdentifier {
                name: identifier.name,
                span: identifier.name_span,
            })
        }
    };

    let ops = identifier.operations;

    let mut previous_span = identifier.name_span.clone();
    // Resolve the value as deep as possible, until reaching either the final value, or a lazy
    // evaluated value.
    let mut i = 0;
    while i < ops.len() {
        match &ops[i].op {
            parser::IdentifierOperationType::Subfield(subfield) => {
                match value {
                    Value::Dictionary(map) => match map.get(&**subfield) {
                        Some(v) => value = v,
                        None => {
                            return Err(CompilationError::UnknownIdentifierField {
                                field_name: subfield.to_string(),
                                span: ops[i].span.clone(),
                            })
                        }
                    },
                    _ => {
                        return Err(CompilationError::InvalidIdentifierType {
                            actual_type: value.get_type().to_string(),
                            expected_type: "dictionary".to_string(),
                            span: Range {
                                start: identifier.name_span.start,
                                end: previous_span.end,
                            },
                        })
                    }
                };
            }
            _ => break,
        }
        i += 1;
    }

    let value_type = value.get_type();
    let mut ty = &value_type;

    // Compile the rest of the operations, and store them to evaluate them when scanning.
    let mut operations = Vec::with_capacity(ops.len() - i);
    for op in ops.into_iter().skip(i) {
        match op.op {
            parser::IdentifierOperationType::Subfield(subfield) => {
                // Type-check the operation
                match ty {
                    ValueType::Dictionary(map) => match map.get(&*subfield) {
                        Some(v) => ty = v,
                        None => {
                            return Err(CompilationError::UnknownIdentifierField {
                                field_name: subfield,
                                span: op.span,
                            })
                        }
                    },
                    _ => {
                        return Err(CompilationError::InvalidIdentifierType {
                            actual_type: ty.to_string(),
                            expected_type: "dictionary".to_string(),
                            span: Range {
                                start: identifier.name_span.start,
                                end: previous_span.end,
                            },
                        })
                    }
                };

                operations.push(ValueOperation::Subfield(subfield));
            }

            parser::IdentifierOperationType::Subscript(subscript) => {
                // Type-check the operation
                match ty {
                    ValueType::Array(value_type) => ty = value_type,
                    _ => {
                        return Err(CompilationError::InvalidIdentifierType {
                            actual_type: ty.to_string(),
                            expected_type: "array".to_string(),
                            span: Range {
                                start: identifier.name_span.start,
                                end: previous_span.end,
                            },
                        })
                    }
                };

                let subscript = compile_expression(compiler, *subscript)?;
                operations.push(ValueOperation::Subscript(Box::new(subscript.expr)));
            }
            parser::IdentifierOperationType::FunctionCall(arguments) => {
                // Type-check the operation
                match ty {
                    ValueType::Function { return_type } => ty = return_type,
                    _ => {
                        return Err(CompilationError::InvalidIdentifierType {
                            actual_type: ty.to_string(),
                            expected_type: "function".to_string(),
                            span: Range {
                                start: identifier.name_span.start,
                                end: previous_span.end,
                            },
                        })
                    }
                };

                let arguments: Result<Vec<_>, _> = arguments
                    .into_iter()
                    .map(|expr| compile_expression(compiler, expr).map(|v| v.expr))
                    .collect();
                operations.push(ValueOperation::FunctionCall(arguments?));
            }
        }
        previous_span = op.span.clone();
    }

    let expr_type = match ty {
        ValueType::Integer => Type::Integer,
        ValueType::Float => Type::Float,
        ValueType::String => Type::String,
        ValueType::Regex => Type::Regex,
        ValueType::Boolean => Type::Boolean,

        _ => {
            return Err(CompilationError::InvalidIdentifierUse {
                span: identifier_span.clone(),
            })
        }
    };

    // FIXME: value should not be cloned
    Ok((
        Expression::ModuleValue {
            value: value.clone(),
            operations,
        },
        expr_type,
    ))
}
