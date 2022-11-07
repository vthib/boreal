//! Provides methods to evaluate module values during scanning.
use std::{collections::HashMap, sync::Arc};

use crate::{
    compiler::{BoundedValueIndex, Expression, ModuleExpression, ValueOperation},
    module::{ScanContext, Value as ModuleValue},
};

use super::{Evaluator, Value};

pub(super) fn evaluate_expr(
    evaluator: &mut Evaluator,
    expr: &ModuleExpression,
) -> Option<ModuleValue> {
    match expr {
        ModuleExpression::BoundedModuleValueUse { index, operations } => {
            let value = match index {
                BoundedValueIndex::Module(index) => {
                    &evaluator.scan_data.module_values.get(*index)?.1
                }
                BoundedValueIndex::BoundedStack(index) => {
                    evaluator.bounded_identifiers_stack.get(*index)?
                }
            };
            let value = Arc::clone(value);
            evaluate_ops(evaluator, &value, operations.iter())
        }
        ModuleExpression::Function {
            fun,
            arguments,
            operations,
        } => {
            let value = eval_function_op(evaluator, *fun, arguments)?;
            evaluate_ops(evaluator, &value, operations.iter())
        }
    }
}

pub(super) fn evaluate_ops<'a, I>(
    evaluator: &mut Evaluator,
    mut value: &ModuleValue,
    mut operations: I,
) -> Option<ModuleValue>
where
    I: Iterator<Item = &'a ValueOperation> + 'a,
{
    while let Some(op) = operations.next() {
        match op {
            ValueOperation::Subfield(subfield) => match value {
                ModuleValue::Object(map) => {
                    value = map.get(&**subfield)?;
                }
                _ => None?,
            },
            ValueOperation::Subscript(subscript) => match value {
                ModuleValue::Array(array) => {
                    value = eval_array_op(evaluator, subscript, array)?;
                }
                ModuleValue::Dictionary(dict) => {
                    value = eval_dict_op(evaluator, subscript, dict)?;
                }
                _ => None?,
            },
            ValueOperation::FunctionCall(arguments) => match value {
                ModuleValue::Function(fun) => {
                    let arguments: Option<Vec<_>> = arguments
                        .iter()
                        .map(|expr| {
                            evaluator
                                .evaluate_expr(expr)
                                .map(expr_value_to_module_value)
                        })
                        .collect();

                    let new_value = fun(&evaluator.scan_data.module_ctx, arguments?)?;
                    return evaluate_ops(evaluator, &new_value, operations);
                }
                _ => None?,
            },
        }
    }

    Some(value.clone())
}

pub(super) fn module_value_to_expr_value(value: ModuleValue) -> Option<Value> {
    match value {
        ModuleValue::Integer(v) => Some(Value::Integer(v)),
        ModuleValue::Float(v) => {
            if v.is_nan() {
                None
            } else {
                Some(Value::Float(v))
            }
        }
        ModuleValue::Bytes(v) => Some(Value::Bytes(v)),
        ModuleValue::Regex(v) => Some(Value::Regex(v)),
        ModuleValue::Boolean(v) => Some(Value::Boolean(v)),

        _ => None,
    }
}

fn eval_array_op<'a>(
    evaluator: &mut Evaluator,
    subscript: &Expression,
    array: &'a [ModuleValue],
) -> Option<&'a ModuleValue> {
    let index = evaluator.evaluate_expr(subscript)?.unwrap_number()?;

    if let Ok(i) = usize::try_from(index) {
        array.get(i)
    } else {
        None
    }
}

fn eval_dict_op<'a>(
    evaluator: &mut Evaluator,
    subscript: &Expression,
    dict: &'a HashMap<Vec<u8>, ModuleValue>,
) -> Option<&'a ModuleValue> {
    let val = evaluator.evaluate_expr(subscript)?.unwrap_bytes()?;

    dict.get(&val)
}

fn eval_function_op(
    evaluator: &mut Evaluator,
    fun: fn(&ScanContext, Vec<ModuleValue>) -> Option<ModuleValue>,
    arguments: &[Expression],
) -> Option<ModuleValue> {
    let arguments: Option<Vec<_>> = arguments
        .iter()
        .map(|expr| {
            evaluator
                .evaluate_expr(expr)
                .map(expr_value_to_module_value)
        })
        .collect();

    fun(&evaluator.scan_data.module_ctx, arguments?)
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
