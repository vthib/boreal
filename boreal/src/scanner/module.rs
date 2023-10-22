use std::collections::HashMap;

use crate::{
    evaluator::ModulesData,
    module::{Module, ModuleDataMap, ScanContext, Value},
};

#[derive(Debug)]
pub struct ScanData {
    pub values: Vec<(&'static str, Value)>,
    pub data_map: ModuleDataMap,
}

impl ScanData {
    pub fn new(modules: &[Box<dyn Module>]) -> Self {
        let mut data_map = ModuleDataMap::default();

        let values = modules
            .iter()
            .map(|module| {
                module.setup_new_scan(&mut data_map);

                (module.get_name(), Value::Object(HashMap::new()))
            })
            .collect();

        Self { values, data_map }
    }

    pub fn scan_mem(&mut self, mem: &[u8], modules: &[Box<dyn Module>]) {
        let mut scan_ctx = ScanContext {
            mem,
            module_data: &mut self.data_map,
        };

        for (module, values) in modules.iter().zip(self.values.iter_mut()) {
            let Value::Object(values) = &mut values.1 else {
                // Safety: this value is built in the new method of this object and guaranteed
                // to be of this type.
                unreachable!();
            };
            module.get_dynamic_values(&mut scan_ctx, values);
        }
    }

    pub fn to_eval_data(&self) -> ModulesData {
        ModulesData {
            dynamic_values: &self.values,
            data_map: &self.data_map,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(ScanData {
            values: Vec::new(),
            data_map: ModuleDataMap::default(),
        });
    }
}
