//! Provides methods to evaluate module values during scanning.
use std::collections::HashMap;

use crate::{
    compiler::{Expression, ModuleExpression, ValueOperation},
    module::{ScanContext, Value as ModuleValue},
};

use super::{BoundedIdentifierValue, Evaluator, Value};

pub(super) fn evaluate_expr(
    evaluator: &mut Evaluator,
    expr: &ModuleExpression,
) -> Option<ModuleValue> {
    match expr {
        ModuleExpression::ModuleUse {
            module_name,
            operations,
        } => {
            // FIXME: avoid this clone
            let value = evaluator.scan_data.module_values.get(module_name)?.clone();
            evaluate_ops(evaluator, value, operations)
        }
        ModuleExpression::BoundedModuleValueUse { index, operations } => {
            let value = evaluator
                .bounded_identifiers_stack
                .get(*index)
                .and_then(|v| match v {
                    BoundedIdentifierValue::RawValue(_) => None,
                    // TODO: find a way to avoid the clone
                    BoundedIdentifierValue::ModuleValue(v) => Some((*v).clone()),
                })?;
            evaluate_ops(evaluator, value, operations)
        }
        ModuleExpression::Function {
            fun,
            arguments,
            operations,
        } => {
            let value = eval_function_op(evaluator, *fun, arguments)?;
            evaluate_ops(evaluator, value, operations)
        }
    }
}

pub(super) fn evaluate_ops(
    evaluator: &mut Evaluator,
    mut value: ModuleValue,
    operations: &[ValueOperation],
) -> Option<ModuleValue> {
    for op in operations {
        value = evaluate_value_operation(evaluator, value, op)?;
    }
    Some(value)
}

pub(super) fn module_value_to_expr_value(value: ModuleValue) -> Option<Value> {
    match value {
        ModuleValue::Integer(v) => Some(Value::Number(v)),
        ModuleValue::Float(v) => Some(Value::Float(v)),
        ModuleValue::Bytes(v) => Some(Value::Bytes(v)),
        ModuleValue::Regex(v) => Some(Value::Regex(v)),
        ModuleValue::Boolean(v) => Some(Value::Boolean(v)),

        _ => None,
    }
}

fn eval_array_op(
    evaluator: &mut Evaluator,
    subscript: &Expression,
    mut array: Vec<ModuleValue>,
) -> Option<ModuleValue> {
    let index = evaluator.evaluate_expr(subscript)?.unwrap_number()?;

    if let Ok(i) = usize::try_from(index) {
        if i < array.len() {
            Some(array.remove(i))
        } else {
            None
        }
    } else {
        None
    }
}

fn eval_dict_op(
    evaluator: &mut Evaluator,
    subscript: &Expression,
    mut dict: HashMap<Vec<u8>, ModuleValue>,
) -> Option<ModuleValue> {
    let val = evaluator.evaluate_expr(subscript)?.unwrap_bytes()?;

    dict.remove(&val)
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

fn evaluate_value_operation(
    evaluator: &mut Evaluator,
    value: ModuleValue,
    op: &ValueOperation,
) -> Option<ModuleValue> {
    match op {
        ValueOperation::Subfield(subfield) => match value {
            ModuleValue::Object(mut map) => map.remove(&**subfield),
            _ => None,
        },
        ValueOperation::Subscript(subscript) => match value {
            ModuleValue::Array(array) => eval_array_op(evaluator, subscript, array),
            ModuleValue::Dictionary(dict) => eval_dict_op(evaluator, subscript, dict),
            _ => None,
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

                Some(fun(&evaluator.scan_data.module_ctx, arguments?)?)
            }
            _ => None,
        },
    }
}

fn expr_value_to_module_value(v: Value) -> ModuleValue {
    match v {
        Value::Number(v) => ModuleValue::Integer(v),
        Value::Float(v) => ModuleValue::Float(v),
        Value::Bytes(v) => ModuleValue::Bytes(v),
        Value::Regex(v) => ModuleValue::Regex(v),
        Value::Boolean(v) => ModuleValue::Boolean(v),
    }
}
