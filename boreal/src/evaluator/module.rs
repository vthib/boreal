//! Provides methods to evaluate module values during scanning.
use std::collections::HashMap;

use crate::{
    compiler::{Expression, ModuleExpression, ValueOperation},
    module::{ScanContext, Value as ModuleValue},
};

use super::{Evaluator, Value};

pub(super) fn evaluate_expr(
    evaluator: &mut Evaluator,
    expr: &ModuleExpression,
) -> Option<ModuleValue> {
    match expr {
        ModuleExpression::Array {
            fun,
            subscript,
            operations,
        } => {
            let value = eval_array_op(evaluator, *fun, subscript)?;
            evaluate_ops(evaluator, value, operations)
        }
        ModuleExpression::Dictionary {
            fun,
            subscript,
            operations,
        } => {
            let value = eval_dict_op(evaluator, *fun, subscript)?;
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
        ModuleValue::String(v) => Some(Value::String(v)),
        ModuleValue::Regex(v) => Some(Value::Regex(v)),
        ModuleValue::Boolean(v) => Some(Value::Boolean(v)),

        _ => None,
    }
}

fn eval_array_op(
    evaluator: &mut Evaluator,
    fun: fn(&ScanContext) -> Option<Vec<ModuleValue>>,
    subscript: &Expression,
) -> Option<ModuleValue> {
    let mut array = fun(&evaluator.module_ctx)?;
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
    fun: fn(&ScanContext) -> Option<HashMap<String, ModuleValue>>,
    subscript: &Expression,
) -> Option<ModuleValue> {
    let mut dict = fun(&evaluator.module_ctx)?;
    let val = evaluator.evaluate_expr(subscript)?.unwrap_string()?;

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

    fun(&evaluator.module_ctx, arguments?)
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
            ModuleValue::Array { on_scan, .. } => eval_array_op(evaluator, on_scan, subscript),
            ModuleValue::Dictionary { on_scan, .. } => eval_dict_op(evaluator, on_scan, subscript),
            _ => None,
        },
        ValueOperation::FunctionCall(arguments) => match value {
            ModuleValue::Function { fun, .. } => {
                let arguments: Option<Vec<_>> = arguments
                    .iter()
                    .map(|expr| {
                        evaluator
                            .evaluate_expr(expr)
                            .map(expr_value_to_module_value)
                    })
                    .collect();

                Some(fun(&evaluator.module_ctx, arguments?)?)
            }
            _ => None,
        },
    }
}

fn expr_value_to_module_value(v: Value) -> ModuleValue {
    match v {
        Value::Number(v) => ModuleValue::Integer(v),
        Value::Float(v) => ModuleValue::Float(v),
        Value::String(v) => ModuleValue::String(v),
        Value::Regex(v) => ModuleValue::Regex(v),
        Value::Boolean(v) => ModuleValue::Boolean(v),
    }
}
