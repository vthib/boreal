use crate::module::{self, Symbol};

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub symbol: Symbol,
}

pub(crate) fn compile_module<M: module::Module>(module: M) -> Module {
    Module {
        name: module.get_name(),
        symbol: module.get_symbol(),
    }
}
