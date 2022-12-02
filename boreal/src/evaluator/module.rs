//! Provides methods to evaluate module values during scanning.
use std::collections::HashMap;
use std::sync::Arc;

use crate::compiler::expression::Expression;
use crate::compiler::module::{BoundedValueIndex, ModuleExpression, ValueOperation};
use crate::module::Value as ModuleValue;

use super::{Evaluator, PoisonKind, Value};

pub(super) fn evaluate_expr(
    evaluator: &mut Evaluator,
    expr: &ModuleExpression,
) -> Result<ModuleValue, PoisonKind> {
    match expr {
        ModuleExpression::BoundedModuleValueUse { index, operations } => {
            let value = match index {
                BoundedValueIndex::Module(index) => {
                    &evaluator
                        .scan_data
                        .module_values
                        .get(*index)
                        .ok_or(PoisonKind::Undefined)?
                        .1
                }
                BoundedValueIndex::BoundedStack(index) => evaluator
                    .bounded_identifiers_stack
                    .get(*index)
                    .ok_or(PoisonKind::Undefined)?,
            };
            let value = Arc::clone(value);
            evaluate_ops(evaluator, &value, operations, 0)
        }
        ModuleExpression::Function {
            fun,
            arguments,
            operations,
        } => {
            let arguments = eval_function_args(evaluator, arguments)?;
            let value =
                fun(&evaluator.scan_data.module_ctx, arguments).ok_or(PoisonKind::Undefined)?;
            evaluate_ops(evaluator, &value, operations, 0)
        }
    }
}

fn evaluate_ops(
    evaluator: &mut Evaluator,
    mut value: &ModuleValue,
    operations: &[ValueOperation],
    mut index: usize,
) -> Result<ModuleValue, PoisonKind> {
    while index < operations.len() {
        match &operations[index] {
            ValueOperation::Subfield(subfield) => match value {
                ModuleValue::Object(map) => {
                    value = map.get(&**subfield).ok_or(PoisonKind::Undefined)?;
                }
                _ => return Err(PoisonKind::Undefined),
            },
            ValueOperation::Subscript(subscript) => match value {
                ModuleValue::Array(array) => {
                    value = eval_array_op(evaluator, subscript, array)?;
                }
                ModuleValue::Dictionary(dict) => {
                    value = eval_dict_op(evaluator, subscript, dict)?;
                }
                _ => return Err(PoisonKind::Undefined),
            },
            ValueOperation::FunctionCall(arguments) => match value {
                ModuleValue::Function(fun) => {
                    let arguments = eval_function_args(evaluator, arguments)?;
                    let new_value = fun(&evaluator.scan_data.module_ctx, arguments)
                        .ok_or(PoisonKind::Undefined)?;
                    // Avoid cloning the value if possible
                    return if index + 1 >= operations.len() {
                        Ok(new_value)
                    } else {
                        evaluate_ops(evaluator, &new_value, operations, index + 1)
                    };
                }
                _ => return Err(PoisonKind::Undefined),
            },
        }

        index += 1;
    }

    Ok(value.clone())
}

pub(super) fn module_value_to_expr_value(value: ModuleValue) -> Result<Value, PoisonKind> {
    match value {
        ModuleValue::Integer(v) => Ok(Value::Integer(v)),
        ModuleValue::Float(v) => {
            if v.is_nan() {
                Err(PoisonKind::Undefined)
            } else {
                Ok(Value::Float(v))
            }
        }
        ModuleValue::Bytes(v) => Ok(Value::Bytes(v)),
        ModuleValue::Regex(v) => Ok(Value::Regex(v)),
        ModuleValue::Boolean(v) => Ok(Value::Boolean(v)),

        _ => Err(PoisonKind::Undefined),
    }
}

fn eval_array_op<'a>(
    evaluator: &mut Evaluator,
    subscript: &Expression,
    array: &'a [ModuleValue],
) -> Result<&'a ModuleValue, PoisonKind> {
    let index = evaluator.evaluate_expr(subscript)?.unwrap_number()?;

    usize::try_from(index)
        .ok()
        .and_then(|i| array.get(i))
        .ok_or(PoisonKind::Undefined)
}

fn eval_dict_op<'a>(
    evaluator: &mut Evaluator,
    subscript: &Expression,
    dict: &'a HashMap<Vec<u8>, ModuleValue>,
) -> Result<&'a ModuleValue, PoisonKind> {
    let val = evaluator.evaluate_expr(subscript)?.unwrap_bytes()?;

    dict.get(&val).ok_or(PoisonKind::Undefined)
}

fn eval_function_args(
    evaluator: &mut Evaluator,
    arguments: &[Expression],
) -> Result<Vec<ModuleValue>, PoisonKind> {
    arguments
        .iter()
        .map(|expr| {
            evaluator
                .evaluate_expr(expr)
                .map(expr_value_to_module_value)
        })
        .collect()
}

fn expr_value_to_module_value(v: Value) -> ModuleValue {
    match v {
        Value::Integer(v) => ModuleValue::Integer(v),
        Value::Float(v) => ModuleValue::Float(v),
        Value::Bytes(v) => ModuleValue::Bytes(v),
        Value::Regex(v) => ModuleValue::Regex(v),
        Value::Boolean(v) => ModuleValue::Boolean(v),
    }
}
