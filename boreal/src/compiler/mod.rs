//! Provides the [`Compiler`] object used to compile YARA rules.
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;

use boreal_parser as parser;

mod base64;
mod error;
pub use error::CompilationError;
pub(crate) mod expression;
pub(crate) mod external_symbol;
pub use external_symbol::ExternalValue;
pub(crate) mod module;
pub mod params;
pub(crate) mod rule;
pub(crate) mod variable;

use crate::Scanner;

/// Object used to compile rules.
#[derive(Debug, Default)]
pub struct Compiler {
    /// List of compiled rules.
    rules: Vec<rule::Rule>,

    /// List of compiled, global rules.
    global_rules: Vec<rule::Rule>,

    /// List of compiled variables.
    variables: Vec<variable::Variable>,

    /// Default namespace, see [`Namespace`]
    default_namespace: Namespace,

    /// Other namespaces, accessible by their names.
    namespaces: HashMap<String, Namespace>,

    /// Modules declared in the compiler, added with [`Compiler::add_module`].
    ///
    /// These are modules that can be imported and used in the namespaces.
    available_modules: HashMap<String, AvailableModule>,

    /// List of imported modules, passed to the scanner.
    imported_modules: Vec<Box<dyn crate::module::Module>>,

    /// Externally defined symbols.
    external_symbols: Vec<external_symbol::ExternalSymbol>,

    /// Compilation parameters
    params: params::Parameters,
}

#[derive(Debug)]
struct AvailableModule {
    /// The compiled module.
    compiled_module: Arc<module::Module>,

    /// The location of the module object
    location: ModuleLocation,
}

#[derive(Debug)]
enum ModuleLocation {
    /// The module object.
    Module(Box<dyn crate::module::Module>),
    /// Index in the imported modules vec.
    ImportedIndex(usize),
}

#[derive(Debug)]
struct ImportedModule {
    /// The imported module.
    module: Arc<module::Module>,

    /// Index of the module in the imported vec, used to access the module dynamic values during
    /// scanning.
    module_index: usize,
}

impl Compiler {
    /// Create a new object to compile YARA rules.
    ///
    /// All available modules are enabled by default:
    /// - `time`
    /// - `math`
    /// - `hash` if the `hash` feature is enabled
    /// - `elf`, `macho` and `pe` if the `object` feature is enabled
    ///
    /// To create a compiler without some or all of those modules, use [`Compiler::default`] to
    /// create a [`Compiler`] without any modules, then add back only the desired modules.
    #[must_use]
    pub fn new() -> Self {
        let mut this = Self::default();

        let _r = this.add_module(crate::module::Time);
        let _r = this.add_module(crate::module::Math);

        #[cfg(feature = "hash")]
        let _r = this.add_module(crate::module::Hash);

        #[cfg(feature = "object")]
        let _r = this.add_module(crate::module::Elf);
        #[cfg(feature = "object")]
        let _r = this.add_module(crate::module::MachO);
        #[cfg(feature = "object")]
        let _r = this.add_module(crate::module::Pe);

        this
    }

    /// Add a module.
    ///
    /// Returns false if a module with the same name is already registered, and the module
    /// was not added.
    pub fn add_module<M: crate::module::Module + 'static>(&mut self, module: M) -> bool {
        let m = module::compile_module(&module);

        match self.available_modules.entry(m.name.to_owned()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                let _r = v.insert(AvailableModule {
                    compiled_module: Arc::new(m),
                    location: ModuleLocation::Module(Box::new(module)),
                });
                true
            }
        }
    }

    /// Add rules to compile from a file.
    ///
    /// The default namespace will be used.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error (when trying
    /// to open and read the file, or any following includes).
    pub fn add_rules_file<T: AsRef<Path>>(&mut self, path: T) -> Result<(), AddRuleError> {
        self.add_rules_file_inner(path.as_ref(), None)
    }

    /// Add rules to compile from a file into a specific namespace.
    ///
    /// The default namespace will be used.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error (when trying
    /// to open and read the file, or any following includes).
    pub fn add_rules_file_in_namespace<T: AsRef<Path>, S: AsRef<str>>(
        &mut self,
        path: T,
        namespace: S,
    ) -> Result<(), AddRuleError> {
        self.add_rules_file_inner(path.as_ref(), Some(namespace.as_ref()))
    }

    fn add_rules_file_inner(
        &mut self,
        path: &Path,
        namespace: Option<&str>,
    ) -> Result<(), AddRuleError> {
        let contents = std::fs::read_to_string(path).map_err(|error| AddRuleError {
            path: Some(path.to_path_buf()),
            kind: AddRuleErrorKind::IO(error),
        })?;
        self.add_rules_str_inner(&contents, namespace, Some(path))
    }

    /// Add rules to compile from a string.
    ///
    /// The default namespace will be used.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error on includes.
    pub fn add_rules_str<T: AsRef<str>>(&mut self, rules: T) -> Result<(), AddRuleError> {
        self.add_rules_str_inner(rules.as_ref(), None, None)
    }

    /// Add rules to compile from a string into a specific namespace.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error on includes.
    pub fn add_rules_str_in_namespace<T: AsRef<str>, S: AsRef<str>>(
        &mut self,
        rules: T,
        namespace: S,
    ) -> Result<(), AddRuleError> {
        self.add_rules_str_inner(rules.as_ref(), Some(namespace.as_ref()), None)
    }

    fn add_rules_str_inner(
        &mut self,
        s: &str,
        namespace: Option<&str>,
        current_filepath: Option<&Path>,
    ) -> Result<(), AddRuleError> {
        let file = parser::parse(s).map_err(|error| AddRuleError {
            path: current_filepath.map(Path::to_path_buf),
            kind: AddRuleErrorKind::Parse(error),
        })?;
        for component in file.components {
            self.add_component(component, namespace, current_filepath)?;
        }
        Ok(())
    }

    fn add_component(
        &mut self,
        component: parser::YaraFileComponent,
        namespace_name: Option<&str>,
        current_filepath: Option<&Path>,
    ) -> Result<(), AddRuleError> {
        let namespace = match namespace_name {
            Some(name) => self
                .namespaces
                .entry(name.to_string())
                .or_insert_with(|| Namespace {
                    name: Some(name.to_string()),
                    ..Namespace::default()
                }),
            None => &mut self.default_namespace,
        };

        match component {
            parser::YaraFileComponent::Include(include) => {
                // Resolve the given path relative to the current one
                let path = match current_filepath {
                    None => PathBuf::from(include.path),
                    Some(current_path) => current_path
                        .parent()
                        .unwrap_or(current_path)
                        .join(include.path),
                };
                let path = path.canonicalize().map_err(|error| AddRuleError {
                    path: current_filepath.map(Path::to_path_buf),
                    kind: AddRuleErrorKind::InvalidInclude {
                        path,
                        span: include.span,
                        error,
                    },
                })?;
                self.add_rules_file_inner(&path, namespace_name)?;
            }
            parser::YaraFileComponent::Import(import) => {
                match self.available_modules.get_mut(&import.name) {
                    Some(module) => {
                        // XXX: this is a bit ugly, but i haven't found a better way to get
                        // ownership of the module.
                        let loc = std::mem::replace(
                            &mut module.location,
                            ModuleLocation::ImportedIndex(0),
                        );
                        let module_index = match loc {
                            ModuleLocation::ImportedIndex(i) => i,
                            ModuleLocation::Module(m) => {
                                // Move the module into the imported modules vec, and keep
                                // the index.
                                let i = self.imported_modules.len();
                                self.imported_modules.push(m);
                                i
                            }
                        };
                        module.location = ModuleLocation::ImportedIndex(module_index);

                        // Ignore result: if the import was already done, it's fine.
                        let _r = namespace.imported_modules.insert(
                            import.name.clone(),
                            ImportedModule {
                                module: Arc::clone(&module.compiled_module),
                                module_index,
                            },
                        );
                    }
                    None => {
                        return Err(AddRuleError {
                            path: current_filepath.map(Path::to_path_buf),
                            kind: AddRuleErrorKind::Compilation(CompilationError::UnknownImport {
                                name: import.name,
                                span: import.span,
                            }),
                        })
                    }
                };
            }
            parser::YaraFileComponent::Rule(rule) => {
                for prefix in &namespace.forbidden_rule_prefixes {
                    if rule.name.starts_with(prefix) {
                        return Err(AddRuleError {
                            path: current_filepath.map(Path::to_path_buf),
                            kind: AddRuleErrorKind::Compilation(
                                CompilationError::MatchOnWildcardRuleSet {
                                    rule_name: rule.name,
                                    name_span: rule.name_span,
                                    rule_set: format!("{prefix}*"),
                                },
                            ),
                        });
                    }
                }

                let rule_name = rule.name.clone();
                let is_global = rule.is_global;
                let name_span = rule.name_span.clone();
                let (rule, vars) =
                    rule::compile_rule(*rule, namespace, &self.external_symbols, &self.params)
                        .map_err(|error| AddRuleError {
                            path: current_filepath.map(Path::to_path_buf),
                            kind: AddRuleErrorKind::Compilation(error),
                        })?;

                // Check then insert, to avoid a double clone on the rule name. Maybe
                // someday we'll get the raw entry API.
                if namespace.rules_indexes.contains_key(&rule_name) {
                    return Err(AddRuleError {
                        path: current_filepath.map(Path::to_path_buf),
                        kind: AddRuleErrorKind::Compilation(CompilationError::DuplicatedRuleName {
                            name: rule_name,
                            span: name_span,
                        }),
                    });
                }

                if is_global {
                    let _r = namespace.rules_indexes.insert(rule_name, None);
                    self.global_rules.push(rule);
                } else {
                    let _r = namespace
                        .rules_indexes
                        .insert(rule_name, Some(self.rules.len()));
                    self.rules.push(rule);
                }
                self.variables.extend(vars);
            }
        }

        Ok(())
    }

    /// Define a symbol that can be used in compiled rules.
    ///
    /// Any rules compiled after the addition can use the symbol name, which will be replaced
    /// during scanning by either:
    /// - the last value set in the [`Scanner`] value for this symbol (see
    /// [`Scanner::define_symbol`]).
    /// - the default value provided here otherwise.
    ///
    /// Returns false if a symbol of the same name is already defined.
    pub fn define_symbol<S, T>(&mut self, name: S, value: T) -> bool
    where
        S: AsRef<str>,
        T: Into<ExternalValue>,
    {
        self.define_symbol_inner(name.as_ref(), value.into())
    }

    fn define_symbol_inner(&mut self, name: &str, default_value: ExternalValue) -> bool {
        for sym in &self.external_symbols {
            if sym.name == name {
                return false;
            }
        }

        self.external_symbols.push(external_symbol::ExternalSymbol {
            name: name.to_owned(),
            default_value,
        });
        true
    }

    /// Set compilation parameters.
    pub fn set_params(&mut self, params: params::Parameters) {
        self.params = params;
    }

    /// Finalize the compiler and generate a [`Scanner`].
    ///
    /// # Errors
    ///
    /// Can fail if generating a set of all rules variables is not possible.
    #[must_use]
    pub fn into_scanner(self) -> Scanner {
        Scanner::new(
            self.rules,
            self.global_rules,
            self.variables,
            self.imported_modules,
            self.external_symbols,
        )
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
    ///
    /// If the value is None, this means the rule is global.
    rules_indexes: HashMap<String, Option<usize>>,

    /// Modules imported in the namespace.
    ///
    /// Those modules have precedence in the namespace over rules. If a module `foo` is imported,
    /// and a rule named `foo` is added, this is not an error, but the identifier `foo` will refer
    /// to the module.
    ///
    imported_modules: HashMap<String, ImportedModule>,

    /// List of names prefixes that cannot be used anymore in this namespace.
    ///
    /// This is a list of rule wildcards that have already been used by rules in
    /// this namespace.
    pub forbidden_rule_prefixes: Vec<String>,
}

/// Error when adding a rule to a [`Compiler`].
#[derive(Debug)]
pub struct AddRuleError {
    /// The path to the file containing the error.
    ///
    /// None if the error happens on a raw string ([`Compiler::add_rules_str`]).
    pub path: Option<PathBuf>,

    /// The kind of error.
    kind: AddRuleErrorKind,
}

/// Kind of error when adding a rule to a [`Compiler`].
#[derive(Debug)]
enum AddRuleErrorKind {
    /// Error while trying to read a file.
    ///
    /// This can happen either:
    /// - when using the [`Compiler::add_rules_file`] or [`Compiler::add_rules_file_in_namespace`]
    ///   and failing to read from the provided path.
    /// - On `include` clauses.
    IO(std::io::Error),

    InvalidInclude {
        /// Path in the include clause that is invalid.
        path: PathBuf,

        /// Span of the include.
        span: Range<usize>,

        /// IO error on this path.
        error: std::io::Error,
    },

    /// Error while parsing a rule.
    Parse(boreal_parser::Error),

    /// Error while compiling a rule.
    Compilation(CompilationError),
}

impl AddRuleError {
    /// Convert to a displayable, single-lined description.
    ///
    /// # Arguments
    ///
    /// * `input_name`: a name for the input, used at the beginning of the
    ///   description: `<filename>:<line>:<column>: <description>`.
    /// * `input`: the input given to [`boreal_parser::parse`] that generated the error.
    #[must_use]
    pub fn to_short_description(&self, input_name: &str, input: &str) -> String {
        // Generate a small report using codespan_reporting
        let mut writer = term::termcolor::Buffer::no_color();
        let config = term::Config {
            display_style: term::DisplayStyle::Short,
            ..term::Config::default()
        };

        let files = SimpleFile::new(&input_name, &input);
        let _res = term::emit(&mut writer, &config, &files, &self.kind.to_diagnostic());
        String::from_utf8_lossy(writer.as_slice()).to_string()
    }

    /// Convert to a [`Diagnostic`].
    ///
    /// This can be used to display the error in a more user-friendly manner than the
    /// simple `Self::to_short_description`.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic<()> {
        self.kind.to_diagnostic()
    }
}

impl AddRuleErrorKind {
    fn to_diagnostic(&self) -> Diagnostic<()> {
        match self {
            Self::IO(error) => Diagnostic::error().with_message(format!("IO error: {error}")),
            Self::InvalidInclude { path, span, error } => Diagnostic::error()
                .with_message(format!("cannot include `{}`: {error}", path.display()))
                .with_labels(vec![Label::primary((), span.clone())]),
            Self::Parse(err) => err.to_diagnostic(),
            Self::Compilation(err) => err.to_diagnostic(),
        }
    }
}

#[cfg(test)]
mod tests;
