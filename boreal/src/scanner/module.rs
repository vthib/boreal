use std::collections::HashMap;

use crate::{
    evaluator::ModulesData,
    module::{Module, ModuleDataMap, ScanContext, Value},
};

#[derive(Debug)]
pub struct ScanData<'a> {
    modules: &'a [Box<dyn Module>],
    values: Vec<HashMap<&'static str, Value>>,
    data_map: ModuleDataMap,
}

impl<'a> ScanData<'a> {
    pub fn new(modules: &'a [Box<dyn Module>]) -> Self {
        let mut data_map = ModuleDataMap::default();

        let values = modules
            .iter()
            .map(|module| {
                module.setup_new_scan(&mut data_map);

                HashMap::new()
            })
            .collect();

        Self {
            modules,
            values,
            data_map,
        }
    }

    pub fn scan_mem(&mut self, mem: &[u8]) {
        let mut scan_ctx = ScanContext {
            mem,
            module_data: &mut self.data_map,
        };

        for (module, values) in self.modules.iter().zip(self.values.iter_mut()) {
            module.get_dynamic_values(&mut scan_ctx, values);
        }
    }

    pub fn finalize(self) -> ModulesData {
        ModulesData {
            dynamic_values: self
                .modules
                .iter()
                .zip(self.values)
                .map(|(module, values)| (module.get_name(), Value::Object(values)))
                .collect(),
            data_map: self.data_map,
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
            modules: &[],
            values: Vec::new(),
            data_map: ModuleDataMap::default(),
        });
    }
}
