//! Provides methods to evaluate module values during scanning.
use crate::{
    compiler::{Expression, ValueOperation},
    module::Value as ModuleValue,
};

use super::{Evaluator, Value};

pub(super) fn evaluate_module_array(
    evaluator: &mut Evaluator<'_>,
    fun: fn(u64) -> Option<ModuleValue>,
    subscript: &Expression,
    operations: &[ValueOperation],
) -> Option<Value> {
    let mut value = eval_array_op(evaluator, fun, subscript)?;

    for op in operations {
        value = evaluate_value_operation(evaluator, value, op)?;
    }

    module_value_to_expr_value(value)
}

pub(super) fn evaluate_module_function(
    evaluator: &mut Evaluator<'_>,
    fun: fn(Vec<ModuleValue>) -> Option<ModuleValue>,
    arguments: &[Expression],
    operations: &[ValueOperation],
) -> Option<Value> {
    let mut value = eval_function_op(evaluator, fun, arguments)?;

    for op in operations {
        value = evaluate_value_operation(evaluator, value, op)?;
    }

    module_value_to_expr_value(value)
}

fn eval_array_op(
    evaluator: &mut Evaluator<'_>,
    fun: fn(u64) -> Option<ModuleValue>,
    subscript: &Expression,
) -> Option<ModuleValue> {
    let index = evaluator.evaluate_expr(subscript)?;

    match index {
        Value::Number(i) => {
            if let Ok(u) = u64::try_from(i) {
                fun(u)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn eval_function_op(
    evaluator: &mut Evaluator<'_>,
    fun: fn(Vec<ModuleValue>) -> Option<ModuleValue>,
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

    fun(arguments?)
}

fn evaluate_value_operation(
    evaluator: &mut Evaluator<'_>,
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

                Some(fun(arguments?)?)
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

fn module_value_to_expr_value(value: ModuleValue) -> Option<Value> {
    match value {
        ModuleValue::Integer(v) => Some(Value::Number(v)),
        ModuleValue::Float(v) => Some(Value::Float(v)),
        ModuleValue::String(v) => Some(Value::String(v)),
        ModuleValue::Regex(v) => Some(Value::Regex(v)),
        ModuleValue::Boolean(v) => Some(Value::Boolean(v)),

        _ => None,
    }
}
