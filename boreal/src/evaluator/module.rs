//! Provides methods to evaluate module values during scanning.
use std::collections::HashMap;
use std::iter::Peekable;
use std::slice::Iter;

use crate::compiler::module::{
    BoundedValueIndex, ModuleExpression, ModuleExpressionKind, ModuleOperations, ValueOperation,
};
use crate::memory::MemoryRegion;
use crate::module::{EvalContext, Module, ModuleDataMap, ScanContext, Value as ModuleValue};

use super::{Evaluator, PoisonKind, Value};

#[derive(Debug)]
pub struct EvalData {
    pub values: Vec<(&'static str, ModuleValue)>,
    pub data_map: ModuleDataMap,
}

impl EvalData {
    pub fn new(modules: &[Box<dyn Module>]) -> Self {
        let mut data_map = ModuleDataMap::default();

        let values = modules
            .iter()
            .map(|module| {
                module.setup_new_scan(&mut data_map);

                (module.get_name(), ModuleValue::Object(HashMap::new()))
            })
            .collect();

        Self { values, data_map }
    }

    pub fn scan_region(&mut self, region: &MemoryRegion, modules: &[Box<dyn Module>]) {
        let mut scan_ctx = ScanContext {
            region,
            module_data: &mut self.data_map,
        };

        for (module, values) in modules.iter().zip(self.values.iter_mut()) {
            let ModuleValue::Object(values) = &mut values.1 else {
                // Safety: this value is built in the new method of this object and guaranteed
                // to be of this type.
                unreachable!();
            };
            module.get_dynamic_values(&mut scan_ctx, values);
        }
    }
}

pub(super) fn evaluate_expr(
    evaluator: &mut Evaluator,
    expr: &ModuleExpression,
) -> Result<ModuleValue, PoisonKind> {
    let ModuleOperations {
        expressions,
        operations,
    } = &expr.operations;

    let expressions = expressions
        .iter()
        .map(|expr| evaluator.evaluate_expr(expr))
        .collect::<Result<Vec<Value>, PoisonKind>>()?;
    let mut expressions = expressions.into_iter();

    let mut ops = operations.iter().peekable();

    match &expr.kind {
        ModuleExpressionKind::BoundedModuleValueUse { index } => {
            let value = match index {
                BoundedValueIndex::Module(index) => {
                    &evaluator
                        .scan_data
                        .module_values
                        .values
                        .get(*index)
                        .ok_or(PoisonKind::Undefined)?
                        .1
                }
                BoundedValueIndex::BoundedStack(index) => evaluator
                    .bounded_identifiers_stack
                    .get(*index)
                    .ok_or(PoisonKind::Undefined)?,
            };

            evaluate_ops(evaluator, value, ops, expressions)
        }
        ModuleExpressionKind::StaticFunction { fun } => {
            let Some(ValueOperation::FunctionCall(nb_arguments)) = ops.next() else {
                return Err(PoisonKind::Undefined);
            };

            let arguments: Vec<ModuleValue> = (&mut expressions)
                .take(*nb_arguments)
                .map(expr_value_to_module_value)
                .collect();
            let eval_ctx = EvalContext {
                mem: &evaluator.scan_data.mem,
                module_data: &evaluator.scan_data.module_values.data_map,
            };
            let value = fun(&eval_ctx, arguments).ok_or(PoisonKind::Undefined)?;
            evaluate_ops(evaluator, &value, ops, expressions)
        }
    }
}

fn evaluate_ops(
    evaluator: &Evaluator,
    mut value: &ModuleValue,
    mut operations: Peekable<Iter<ValueOperation>>,
    mut expressions: std::vec::IntoIter<Value>,
) -> Result<ModuleValue, PoisonKind> {
    while let Some(op) = operations.next() {
        match op {
            ValueOperation::Subfield(subfield) => match value {
                ModuleValue::Object(map) => {
                    value = map.get(&**subfield).ok_or(PoisonKind::Undefined)?;
                }
                _ => return Err(PoisonKind::Undefined),
            },
            ValueOperation::Subscript => {
                let subscript = expressions.next().ok_or(PoisonKind::Undefined)?;

                value = match value {
                    ModuleValue::Array(array) => {
                        let index = subscript.unwrap_number()?;

                        usize::try_from(index)
                            .ok()
                            .and_then(|i| array.get(i))
                            .ok_or(PoisonKind::Undefined)?
                    }
                    ModuleValue::Dictionary(dict) => {
                        let val = subscript.unwrap_bytes()?;

                        dict.get(&val).ok_or(PoisonKind::Undefined)?
                    }
                    _ => return Err(PoisonKind::Undefined),
                };
            }
            ValueOperation::FunctionCall(nb_arguments) => match value {
                ModuleValue::Function(fun) => {
                    let arguments: Vec<ModuleValue> = (&mut expressions)
                        .take(*nb_arguments)
                        .map(expr_value_to_module_value)
                        .collect();
                    let eval_ctx = EvalContext {
                        mem: &evaluator.scan_data.mem,
                        module_data: &evaluator.scan_data.module_values.data_map,
                    };
                    let new_value = fun(&eval_ctx, arguments).ok_or(PoisonKind::Undefined)?;
                    // Avoid cloning the value if possible
                    return if operations.peek().is_none() {
                        Ok(new_value)
                    } else {
                        evaluate_ops(evaluator, &new_value, operations, expressions)
                    };
                }
                _ => return Err(PoisonKind::Undefined),
            },
        }
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

        ModuleValue::Object(_)
        | ModuleValue::Array(_)
        | ModuleValue::Dictionary(_)
        | ModuleValue::Function(_)
        | ModuleValue::Undefined => Err(PoisonKind::Undefined),
    }
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

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(EvalData {
            values: Vec::new(),
            data_map: ModuleDataMap::default(),
        });
    }
}
