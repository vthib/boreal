use crate::module::{self, Value};

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub value: Value,
}

pub(crate) fn compile_module<M: module::Module>(module: M) -> Module {
    Module {
        name: module.get_name(),
        value: module.get_value(),
    }
}
