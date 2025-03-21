use std::{collections::HashMap, sync::Arc};

use super::{AvailableModule, ModuleLocation};

/// Configurable builder for the [`crate::Compiler`] object.
#[derive(Debug, Default)]
pub struct CompilerBuilder {
    /// Modules that can be imported when compiling rules.
    modules: HashMap<&'static str, AvailableModule>,

    /// Profile to use when compiling rules.
    profile: super::CompilerProfile,
}

impl CompilerBuilder {
    /// Create a new builder with sane default values.
    ///
    /// Modules enabled by default:
    /// - `time`
    /// - `math`
    /// - `string`
    /// - `hash` if the `hash` feature is enabled
    /// - `elf`, `macho`, `pe`, `dotnet` and `dex` if the `object` feature is enabled
    /// - `magic` if the `magic` feature is enabled
    /// - `cuckoo` if the `cuckoo` feature is enabled
    ///
    /// Modules disabled by default:
    /// - `console`
    ///
    /// To create a builder without any modules, use [`CompilerBuilder::default`] to
    /// create a [`CompilerBuilder`] without any modules, then add back only the desired modules.
    #[must_use]
    pub fn new() -> Self {
        let mut this = Self::default();

        crate::module::add_default_modules(|module| {
            this.add_module_inner(module);
        });

        this
    }

    /// Add a module that will be importable in rules.
    ///
    /// If the same module has already been added, it will be replaced by this one.
    /// This can be useful to change the parameters of a module.
    #[must_use]
    pub fn add_module<M: crate::module::Module + 'static>(mut self, module: M) -> Self {
        self.add_module_inner(Box::new(module));
        self
    }

    fn add_module_inner(&mut self, module: Box<dyn crate::module::Module>) {
        let compiled_module = Arc::new(super::module::compile_module(&*module));

        let _r = self.modules.insert(
            compiled_module.name,
            AvailableModule {
                compiled_module,
                location: ModuleLocation::Module(module),
            },
        );
    }

    /// Set the profile to use when compiling rules.
    ///
    /// By default, [`crate::compiler::CompilerProfile::Speed`] is used.
    #[must_use]
    pub fn profile(mut self, profile: super::CompilerProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Build a [`crate::Compiler`] object with the configuration set on this builder.
    #[must_use]
    pub fn build(self) -> super::Compiler {
        super::Compiler::build(self.modules, self.profile)
    }

    /// Get the profile to use when compiling rules.
    #[must_use]
    pub fn get_profile(&self) -> super::CompilerProfile {
        self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::CompilerProfile;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(CompilerBuilder::default());
    }

    #[test]
    fn test_getters() {
        let builder = CompilerBuilder::default();

        let builder = builder.profile(CompilerProfile::Memory);
        assert_eq!(builder.get_profile(), CompilerProfile::Memory);
    }
}
