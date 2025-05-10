//! Provides methods to evaluate module values during scanning.
use std::collections::HashMap;
use std::iter::Peekable;
use std::slice::Iter;

use crate::compiler::module::{
    BoundedValueIndex, ModuleExpression, ModuleExpressionKind, ModuleOperations, ValueOperation,
};
use crate::memory::Region;
use crate::module::{
    EvalContext, Module, ModuleDataMap, ModuleUserData, ScanContext, Value as ModuleValue,
};

use super::{Evaluator, PoisonKind, Value};

/// Result of a module evaluation during a scan.
#[non_exhaustive]
pub struct EvaluatedModule<'scanner> {
    /// The evaluated module.
    pub module: &'scanner dyn Module,

    /// Dynamic values produced by this module.
    pub dynamic_values: crate::module::Value,
}

impl std::fmt::Debug for EvaluatedModule<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvaluatedModule")
            .field("module", &self.module.get_name())
            .field("dynamic_values", &self.dynamic_values)
            .finish()
    }
}

#[derive(Debug)]
pub struct EvalData<'scanner> {
    pub evaluated_modules: Vec<EvaluatedModule<'scanner>>,
    pub data_map: ModuleDataMap<'scanner>,
}

impl<'scanner> EvalData<'scanner> {
    pub fn new(modules: &'scanner [Box<dyn Module>], user_data: &'scanner ModuleUserData) -> Self {
        let mut data_map = ModuleDataMap::new(user_data);

        let evaluated_modules = modules
            .iter()
            .map(|module| {
                module.setup_new_scan(&mut data_map);

                EvaluatedModule {
                    module: &**module,
                    dynamic_values: ModuleValue::Object(HashMap::new()),
                }
            })
            .collect();

        Self {
            evaluated_modules,
            data_map,
        }
    }

    pub fn scan_region(&mut self, region: &Region, process_memory: bool) {
        let mut scan_ctx = ScanContext {
            region,
            module_data: &mut self.data_map,
            process_memory,
        };

        for evaluated_module in &mut self.evaluated_modules {
            let ModuleValue::Object(values) = &mut evaluated_module.dynamic_values else {
                // Safety: this value is built in the new method of this object and guaranteed
                // to be of this type.
                unreachable!();
            };
            evaluated_module
                .module
                .get_dynamic_values(&mut scan_ctx, values);
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
                        .evaluated_modules
                        .get(*index)
                        .ok_or(PoisonKind::Undefined)?
                        .dynamic_values
                }
                BoundedValueIndex::BoundedStack(index) => evaluator
                    .bounded_identifiers_stack
                    .get(*index)
                    .ok_or(PoisonKind::Undefined)?,
            };

            let mut eval_ctx = EvalContext {
                mem: evaluator.mem,
                module_data: &evaluator.scan_data.module_values.data_map,
                process_memory: evaluator.scan_data.params.process_memory,
            };
            evaluate_ops(&mut eval_ctx, value, ops, expressions)
        }
        ModuleExpressionKind::StaticFunction { fun, .. } => {
            let Some(ValueOperation::FunctionCall(nb_arguments)) = ops.next() else {
                return Err(PoisonKind::Undefined);
            };

            let arguments: Vec<ModuleValue> = (&mut expressions)
                .take(*nb_arguments)
                .map(expr_value_to_module_value)
                .collect();
            let mut eval_ctx = EvalContext {
                mem: evaluator.mem,
                module_data: &evaluator.scan_data.module_values.data_map,
                process_memory: evaluator.scan_data.params.process_memory,
            };
            let value = fun(&mut eval_ctx, arguments).ok_or(PoisonKind::Undefined)?;
            evaluate_ops(&mut eval_ctx, &value, ops, expressions)
        }
    }
}

fn evaluate_ops(
    eval_ctx: &mut EvalContext,
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
                    let new_value = fun(eval_ctx, arguments).ok_or(PoisonKind::Undefined)?;
                    // Avoid cloning the value if possible
                    return if operations.peek().is_none() {
                        Ok(new_value)
                    } else {
                        evaluate_ops(eval_ctx, &new_value, operations, expressions)
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
            evaluated_modules: Vec::new(),
            data_map: ModuleDataMap::new(&ModuleUserData::default()),
        });
        test_type_traits_non_clonable(EvaluatedModule {
            module: &crate::module::Math,
            dynamic_values: ModuleValue::Object(HashMap::new()),
        });
    }
}
