//! Compilation of a parsed expression into an optimized one.
use std::collections::HashMap;
use std::sync::Arc;

use codespan_reporting::diagnostic::Diagnostic;
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;

use boreal_parser as parser;

mod base64;
mod error;
pub use error::CompilationError;
mod expression;
pub use expression::*;
mod variable;
pub use variable::*;
mod module;
pub use module::*;
mod rule;
pub use rule::*;

use crate::scanner::ScannerModule;
use crate::Scanner;

/// Object used to compile rules.
#[derive(Debug, Default)]
pub struct Compiler {
    /// List of compiled rules.
    rules: Vec<Rule>,

    /// Default namespace, see [`Namespace`]
    default_namespace: Namespace,

    /// Other namespaces, accessible by their names.
    namespaces: HashMap<String, Namespace>,

    /// Modules declared in the scanner, added with [`Compiler::add_module`].
    ///
    /// These are modules that can be imported and used in the namespaces.
    available_modules: HashMap<String, Arc<Module>>,

    /// List of modules passed to the scanner.
    // TODO rework this
    modules: HashMap<String, ScannerModule>,
}

impl Compiler {
    /// Create a new object to compile YARA rules.
    ///
    /// All available modules are enabled by default:
    /// - `time`
    /// - `hash` if the `hash` feature is enabled
    #[must_use]
    pub fn new() -> Self {
        let mut this = Self::default();
        this.add_module(crate::module::Time);
        #[cfg(feature = "hash")]
        this.add_module(crate::module::Hash);
        #[cfg(feature = "object")]
        this.add_module(crate::module::Elf);
        this
    }

    /// Add a module
    pub fn add_module<M: crate::module::Module + 'static>(&mut self, module: M) {
        let m = compile_module(&module);
        let _res = self
            .modules
            .insert(m.name.clone(), ScannerModule::new(Box::new(module)));
        // Ignore the result: that would mean the same module is already registered.
        // FIXME: this is done to allow the double "import" in a rule, but this can be improved.
        let _res = self.available_modules.insert(m.name.clone(), Arc::new(m));
    }

    /// Add rules to the scanner from a string.
    ///
    /// The default namespace will be used.
    ///
    /// # Errors
    ///
    /// If parsing of the rules fails, an error is returned.
    pub fn add_rules_str(&mut self, s: &str) -> Result<(), AddRuleError> {
        let file = parser::parse_str(s).map_err(AddRuleError::ParseError)?;
        self.add_file(file, None)
            .map_err(AddRuleError::CompilationError)?;
        Ok(())
    }

    /// Add rules to the scanner from a string into a specific namespace.
    ///
    /// # Errors
    ///
    /// If parsing of the rules fails, an error is returned.
    pub fn add_rules_str_in_namespace<S: Into<String>>(
        &mut self,
        s: &str,
        namespace: S,
    ) -> Result<(), AddRuleError> {
        let file = parser::parse_str(s).map_err(AddRuleError::ParseError)?;
        self.add_file(file, Some(namespace.into()))
            .map_err(AddRuleError::CompilationError)?;
        Ok(())
    }

    fn add_file(
        &mut self,
        file: parser::YaraFile,
        namespace: Option<String>,
    ) -> Result<(), CompilationError> {
        let namespace = match namespace {
            Some(name) => self
                .namespaces
                .entry(name.clone())
                .or_insert_with(|| Namespace {
                    name: Some(name),
                    ..Namespace::default()
                }),
            None => &mut self.default_namespace,
        };

        for component in file.components {
            match component {
                parser::YaraFileComponent::Include(_) => todo!(),
                parser::YaraFileComponent::Import(import) => {
                    match self.available_modules.get(&import) {
                        Some(module) => {
                            // Ignore result: if the import was already done, it's fine.
                            let _r = namespace
                                .imported_modules
                                .insert(import.clone(), Arc::clone(module));
                        }
                        None => return Err(CompilationError::UnknownImport(import.clone())),
                    };
                }
                parser::YaraFileComponent::Rule(rule) => {
                    for prefix in &namespace.forbidden_rule_prefixes {
                        if rule.name.starts_with(prefix) {
                            return Err(CompilationError::MatchOnWildcardRuleSet {
                                rule_name: rule.name,
                                rule_set: format!("{}*", prefix),
                            });
                        }
                    }

                    let rule_name = rule.name.clone();
                    let rule = compile_rule(*rule, namespace)?;

                    // Check then insert, to avoid a double clone on the rule name. Maybe
                    // someday we'll get the raw entry API.
                    if namespace.rules_names.contains_key(&rule_name) {
                        return Err(CompilationError::DuplicatedRuleName(rule_name));
                    }
                    let _r = namespace.rules_names.insert(rule_name, self.rules.len());

                    self.rules.push(rule);
                }
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn into_scanner(self) -> Scanner {
        Scanner::new(self.rules, self.modules)
    }
}

/// Contains rules and modules that belong to the same shared namespace.
///
/// In a namespace:
/// - all rules must have unique names
/// - new rules can reference already existing rules
/// - new rules can either import new modules, or directly use already imported modules
#[derive(Debug, Default)]
struct Namespace {
    /// Name of the namespace, `None` if default.
    name: Option<String>,

    /// Map of a rule name to its index in the `rules` vector in [`Compiler`].
    rules_names: HashMap<String, usize>,

    /// Modules imported in the namespace.
    ///
    /// Those modules have precedence in the namespace over rules. If a module `foo` is imported,
    /// and a rule named `foo` is added, this is not an error, but the identifier `foo` will refer
    /// to the module.
    imported_modules: HashMap<String, Arc<Module>>,

    /// List of names prefixes that cannot be used anymore in this namespace.
    ///
    /// This is a list of rule wildcards that have already been used by rules in
    /// this namespace.
    pub forbidden_rule_prefixes: Vec<String>,
}

#[derive(Debug)]
pub enum AddRuleError {
    /// Error while parsing a rule.
    ParseError(boreal_parser::Error),
    /// Error while compiling a rule.
    CompilationError(CompilationError),
}

impl AddRuleError {
    /// Convert to a displayable, single-lined description.
    ///
    /// # Arguments
    ///
    /// * `input_name`: a name for the input, used at the beginning of the
    ///   description: `<filename>:<line>:<column>: <description>`.
    /// * `input`: the input given to [`parse_str`] that generated the error.
    #[must_use]
    pub fn to_short_description(&self, input_name: &str, input: &str) -> String {
        // Generate a small report using codespan_reporting
        let mut writer = term::termcolor::Buffer::no_color();
        let config = term::Config {
            display_style: term::DisplayStyle::Short,
            ..term::Config::default()
        };

        let files = SimpleFile::new(&input_name, &input);
        // TODO: handle error better here?
        let _res = term::emit(&mut writer, &config, &files, &self.to_diagnostic());
        String::from_utf8_lossy(writer.as_slice()).to_string()
    }

    /// Convert to a [`Diagnostic`].
    ///
    /// This can be used to display the error in a more user-friendly manner
    /// than the simple `to_short_description`. It does require depending
    /// on the `codespan_reporting` crate to make use of this diagnostic
    /// however.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic<()> {
        match self {
            Self::ParseError(err) => err.to_diagnostic(),
            Self::CompilationError(err) => err.to_diagnostic(),
        }
    }
}

#[cfg(test)]
mod tests;
