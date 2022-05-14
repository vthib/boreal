//! Provides methods to evaluate module values during scanning.
use std::collections::HashMap;

use crate::{
    compiler::{Expression, ModuleExpression, ValueOperation},
    module::Value as ModuleValue,
};

use super::{Evaluator, Value};

pub(super) fn evaluate_expr(
    evaluator: &mut Evaluator<'_>,
    expr: &ModuleExpression,
) -> Option<Value> {
    match expr {
        ModuleExpression::Array {
            fun,
            subscript,
            operations,
        } => {
            let mut value = eval_array_op(evaluator, *fun, subscript)?;

            for op in operations {
                value = evaluate_value_operation(evaluator, value, op)?;
            }

            module_value_to_expr_value(value)
        }
        ModuleExpression::Dictionary {
            fun,
            subscript,
            operations,
        } => {
            let mut value = eval_dict_op(evaluator, *fun, subscript)?;

            for op in operations {
                value = evaluate_value_operation(evaluator, value, op)?;
            }

            module_value_to_expr_value(value)
        }
        ModuleExpression::Function {
            fun,
            arguments,
            operations,
        } => {
            let mut value = eval_function_op(evaluator, *fun, arguments)?;

            for op in operations {
                value = evaluate_value_operation(evaluator, value, op)?;
            }

            module_value_to_expr_value(value)
        }
    }
}

fn eval_array_op(
    evaluator: &mut Evaluator<'_>,
    fun: fn() -> Option<Vec<ModuleValue>>,
    subscript: &Expression,
) -> Option<ModuleValue> {
    let mut array = fun()?;
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
    evaluator: &mut Evaluator<'_>,
    fun: fn() -> Option<HashMap<String, ModuleValue>>,
    subscript: &Expression,
) -> Option<ModuleValue> {
    let mut dict = fun()?;
    let val = evaluator.evaluate_expr(subscript)?.unwrap_string()?;

    dict.remove(&val)
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
