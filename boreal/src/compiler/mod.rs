//! Provides the [`Compiler`] object used to compile YARA rules.
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use boreal_parser::file::YaraFileComponent;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;

mod builder;
pub use builder::CompilerBuilder;
mod error;
pub use error::CompilationError;
pub(crate) mod expression;
pub(crate) mod external_symbol;
pub use external_symbol::ExternalValue;
pub(crate) mod module;
mod params;
pub use params::CompilerParams;
pub(crate) mod rule;
pub(crate) mod variable;

use crate::bytes_pool::BytesPoolBuilder;
use crate::{statistics, Scanner};

/// Object used to compile rules.
#[derive(Debug)]
pub struct Compiler {
    /// List of compiled rules.
    pub(crate) rules: Vec<rule::Rule>,

    /// List of compiled, global rules.
    pub(crate) global_rules: Vec<rule::Rule>,

    /// List of compiled variables.
    pub(crate) variables: Vec<variable::Variable>,

    /// Number of variables used by global rules.
    nb_global_rules_variables: usize,

    /// List of namespaces, see [`Namespace`].
    ///
    /// This list always contains at least one namespace: the default one,
    /// at index 0. Other namespaces are added when rules are added in the
    /// non default namespace.
    pub(crate) namespaces: Vec<Namespace>,

    /// Map from the namespace name to its index in the `namespaces` list.
    namespaces_indexes: HashMap<String, usize>,

    /// Modules declared in the compiler, added with [`Compiler::add_module`].
    ///
    /// These are modules that can be imported and used in the namespaces.
    available_modules: HashMap<&'static str, AvailableModule>,

    /// List of imported modules, passed to the scanner.
    pub(crate) imported_modules: Vec<Box<dyn crate::module::Module>>,

    /// Externally defined symbols.
    pub(crate) external_symbols: Vec<external_symbol::ExternalSymbol>,

    /// Bytes intern pool.
    ///
    /// This is used to reduce memory footprint and share byte strings.
    pub(crate) bytes_pool: BytesPoolBuilder,

    /// Compilation parameters
    params: CompilerParams,

    /// Profile to use when compiling rules.
    pub(crate) profile: CompilerProfile,

    /// Callback to use to resolve includes.
    include_callback: Option<IncludeCallback>,
}

#[allow(clippy::type_complexity)]
struct IncludeCallback(
    Box<dyn FnMut(&str, Option<&Path>, &str) -> Result<String, std::io::Error> + Send + Sync>,
);

impl std::fmt::Debug for IncludeCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncludeCallback").finish()
    }
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

/// Profile to use when compiling rules.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompilerProfile {
    /// Prioritize scan speed.
    ///
    /// This profile will strive to get the best possible scan speed by using more memory
    /// when possible.
    Speed,
    /// Prioritize memory usage
    ///
    /// This profile will strive to reduce memory usage as much as possible, even if it means
    /// a slower scan speed overall.
    Memory,
}

impl Default for CompilerProfile {
    fn default() -> Self {
        Self::Speed
    }
}

#[allow(clippy::new_without_default)]
impl Compiler {
    /// Create a new object to compile YARA rules.
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
    /// To create a compiler without some or all of those modules, use the [`CompilerBuilder`]
    /// object.
    /// create a [`Compiler`] without any modules, then add back only the desired modules.
    #[must_use]
    pub fn new() -> Self {
        CompilerBuilder::new().build()
    }

    /// Build a compiler with the given parameters.
    fn build(
        available_modules: HashMap<&'static str, AvailableModule>,
        profile: CompilerProfile,
    ) -> Self {
        Self {
            available_modules,
            profile,

            namespaces: Vec::new(),
            rules: Vec::new(),
            global_rules: Vec::new(),
            variables: Vec::new(),
            nb_global_rules_variables: 0,
            namespaces_indexes: HashMap::new(),
            imported_modules: Vec::new(),
            external_symbols: Vec::new(),
            bytes_pool: BytesPoolBuilder::default(),
            params: CompilerParams::default(),
            include_callback: None,
        }
    }

    /// Add rules to compile from a file.
    ///
    /// The namespace named "default" will be used.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error (when trying
    /// to open and read the file, or any following includes).
    pub fn add_rules_file<T: AsRef<Path>>(
        &mut self,
        path: T,
    ) -> Result<AddRuleStatus, AddRuleError> {
        let mut status = AddRuleStatus::default();
        self.add_rules_file_inner(path.as_ref(), "default", &mut status)?;
        Ok(status)
    }

    /// Add rules to compile from a file into a specific namespace.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error (when trying
    /// to open and read the file, or any following includes).
    pub fn add_rules_file_in_namespace<T: AsRef<Path>, S: AsRef<str>>(
        &mut self,
        path: T,
        namespace: S,
    ) -> Result<AddRuleStatus, AddRuleError> {
        let mut status = AddRuleStatus::default();
        self.add_rules_file_inner(path.as_ref(), namespace.as_ref(), &mut status)?;
        Ok(status)
    }

    fn add_rules_file_inner(
        &mut self,
        path: &Path,
        namespace: &str,
        status: &mut AddRuleStatus,
    ) -> Result<(), AddRuleError> {
        let contents = std::fs::read_to_string(path).map_err(|error| {
            AddRuleError::new(
                AddRuleErrorKind::IO {
                    path: path.to_path_buf(),
                    error,
                },
                Some(path),
                "",
            )
        })?;
        self.add_rules_str_inner(&contents, namespace, Some(path), status)
    }

    /// Add rules to compile from a string.
    ///
    /// The namespace named "default" will be used.
    ///
    /// # Errors
    ///
    /// An error is returned if failing to parse the rules, or on any I/O error on includes.
    pub fn add_rules_str<T: AsRef<str>>(
        &mut self,
        rules: T,
    ) -> Result<AddRuleStatus, AddRuleError> {
        let mut status = AddRuleStatus::default();
        self.add_rules_str_inner(rules.as_ref(), "default", None, &mut status)?;
        Ok(status)
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
    ) -> Result<AddRuleStatus, AddRuleError> {
        let mut status = AddRuleStatus::default();
        self.add_rules_str_inner(rules.as_ref(), namespace.as_ref(), None, &mut status)?;
        Ok(status)
    }

    fn add_rules_str_inner(
        &mut self,
        s: &str,
        namespace: &str,
        current_filepath: Option<&Path>,
        status: &mut AddRuleStatus,
    ) -> Result<(), AddRuleError> {
        let file = boreal_parser::parse(s).map_err(|error| {
            AddRuleError::new(AddRuleErrorKind::Parse(error), current_filepath, s)
        })?;
        for component in file.components {
            self.add_component(component, namespace, current_filepath, s, status)?;
        }
        Ok(())
    }

    fn add_component(
        &mut self,
        component: YaraFileComponent,
        namespace_name: &str,
        current_filepath: Option<&Path>,
        parsed_contents: &str,
        status: &mut AddRuleStatus,
    ) -> Result<(), AddRuleError> {
        let ns_index = match self.namespaces_indexes.entry(namespace_name.to_string()) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(v) => {
                // New namespace: insert it and save its index in the namespaces_indexes
                // map.
                let idx = self.namespaces.len();
                let _r = v.insert(idx);
                self.namespaces.push(Namespace {
                    name: namespace_name.to_string(),
                    ..Namespace::default()
                });
                idx
            }
        };
        let namespace = &mut self.namespaces[ns_index];

        match component {
            YaraFileComponent::Include(include) => {
                if self.params.disable_includes {
                    return Err(AddRuleError::new(
                        AddRuleErrorKind::UnauthorizedInclude { span: include.span },
                        current_filepath,
                        parsed_contents,
                    ));
                }
                match &mut self.include_callback {
                    Some(cb) => {
                        // With an include callback, we do not attempt to resolve the path
                        // through the local filesystem, and just pass to the callback the
                        // include path as is.
                        let contents = (cb.0)(&include.path, current_filepath, namespace_name)
                            .map_err(|error| {
                                AddRuleError::new(
                                    AddRuleErrorKind::InvalidInclude {
                                        path: PathBuf::from(&include.path),
                                        span: include.span,
                                        error,
                                    },
                                    current_filepath,
                                    parsed_contents,
                                )
                            })?;
                        self.add_rules_str_inner(
                            &contents,
                            namespace_name,
                            Some(Path::new(&include.path)),
                            status,
                        )?;
                    }
                    None => {
                        // Resolve the given path relative to the current one
                        let path = match current_filepath {
                            None => PathBuf::from(include.path),
                            Some(current_path) => current_path
                                .parent()
                                .unwrap_or(current_path)
                                .join(include.path),
                        };
                        let path = path.canonicalize().map_err(|error| {
                            AddRuleError::new(
                                AddRuleErrorKind::InvalidInclude {
                                    path,
                                    span: include.span,
                                    error,
                                },
                                current_filepath,
                                parsed_contents,
                            )
                        })?;
                        self.add_rules_file_inner(&path, namespace_name, status)?;
                    }
                }
            }
            YaraFileComponent::Import(import) => {
                match self.available_modules.get_mut(&*import.name) {
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
                        return Err(AddRuleError::new(
                            AddRuleErrorKind::Compilation(CompilationError::UnknownImport {
                                name: import.name,
                                span: import.span,
                            }),
                            current_filepath,
                            parsed_contents,
                        ))
                    }
                }
            }
            YaraFileComponent::Rule(rule) => {
                for prefix in &namespace.forbidden_rule_prefixes {
                    if rule.name.starts_with(prefix) {
                        return Err(AddRuleError::new(
                            AddRuleErrorKind::Compilation(
                                CompilationError::MatchOnWildcardRuleSet {
                                    rule_name: rule.name,
                                    name_span: rule.name_span,
                                    rule_set: format!("{prefix}*"),
                                },
                            ),
                            current_filepath,
                            parsed_contents,
                        ));
                    }
                }

                let rule_name = rule.name.clone();
                let is_global = rule.is_global;
                let name_span = rule.name_span.clone();

                let rule::CompiledRule {
                    rule,
                    variables,
                    variables_statistics,
                    warnings,
                    rule_wildcard_uses,
                } = rule::compile_rule(
                    *rule,
                    namespace,
                    ns_index,
                    &self.external_symbols,
                    &self.params,
                    parsed_contents,
                    &mut self.bytes_pool,
                )
                .map_err(|error| {
                    AddRuleError::new(
                        AddRuleErrorKind::Compilation(error),
                        current_filepath,
                        parsed_contents,
                    )
                })?;

                // Check the rule has no name conflict.
                if namespace.rules_indexes.contains_key(&rule_name) {
                    return Err(AddRuleError::new(
                        AddRuleErrorKind::Compilation(CompilationError::DuplicatedRuleName {
                            name: rule_name,
                            span: name_span,
                        }),
                        current_filepath,
                        parsed_contents,
                    ));
                }

                // From this point onward, the rule is valid. We can add all data related
                // to the rule.
                if self.params.compute_statistics {
                    status.statistics.push(statistics::CompiledRule {
                        filepath: current_filepath.map(ToOwned::to_owned),
                        namespace: namespace.name.clone(),
                        name: rule.name.clone(),
                        strings: variables_statistics,
                    });
                }

                // Append warnings for this rule to the warnings of all the currently added
                // string or file.
                status.warnings.extend(warnings.into_iter().map(|error| {
                    AddRuleError::new(
                        AddRuleErrorKind::Compilation(error),
                        current_filepath,
                        parsed_contents,
                    )
                }));

                namespace.forbidden_rule_prefixes.extend(rule_wildcard_uses);

                if is_global {
                    let _r = namespace.rules_indexes.insert(rule_name, None);
                    self.global_rules.push(rule);

                    // Insert the variables at the right place in the vector: after the already
                    // compiled global rules, but before the normal rules.
                    // This is ok to do since there is no reference to variable indexes anywhere in
                    // compiled rules.
                    let nb_vars = variables.len();
                    let index = self.nb_global_rules_variables;

                    let _r = self.variables.splice(index..index, variables);
                    self.nb_global_rules_variables += nb_vars;
                } else {
                    let _r = namespace
                        .rules_indexes
                        .insert(rule_name, Some(self.rules.len()));
                    self.rules.push(rule);
                    self.variables.extend(variables);
                }
            }
        }

        Ok(())
    }

    /// Define a symbol that can be used in compiled rules.
    ///
    /// Any rules compiled after the addition can use the symbol name, which will be replaced
    /// during scanning by either:
    /// - the last value set in the [`Scanner`] value for this symbol (see
    ///   [`Scanner::define_symbol`]).
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
    pub fn set_params(&mut self, params: CompilerParams) {
        self.params = params;
    }

    /// Get compilation parameters.
    #[must_use]
    pub fn params(&self) -> &CompilerParams {
        &self.params
    }

    /// Names of modules that are available for use in rules.
    pub fn available_modules(&self) -> impl Iterator<Item = &str> {
        self.available_modules.keys().map(|v| &**v)
    }

    /// Set a callback to use to resolve includes.
    ///
    /// This can be used to implement custom handling of includes.
    /// The callback receives as arguments:
    ///
    /// - The include name (the literal string used in the include directive).
    ///
    /// - The path of the current document. This is either:
    ///
    ///   - `None` if the current document comes from a string, i.e. from
    ///     [`Compiler::add_rules_str`] or its namespaced variant.
    ///   - The path to the current document if the current document
    ///     comes [`Compiler::add_rules_file`] or its namespaced variant.
    ///   - The last include name if the current document is from an include.
    ///
    /// - The current namespace.
    ///
    /// For example, lets consider three documents:
    /// - `first.yar` that includes `../second.yar`
    /// - `../second.yar` that includes `subdir/third.yar`.
    /// - `third.yar` that does not contains includes.
    ///
    /// Then:
    ///
    /// ```no_run
    /// # let mut compiler = boreal::Compiler::new();
    /// // This will call the include callback with:
    /// //
    /// // - first:   ("first.yar",        None,                  None)
    /// // - then:    ("../second.yar",    Some("first.yar"),     None)
    /// // - finally: ("subdir/third.yar", Some("../second.yar"), None)
    /// compiler.add_rules_str(r#"
    /// include "first.yar"
    /// ...
    /// "#);
    ///
    /// // This will call the include callback with:
    /// //
    /// // - first: ("../second.yar",    Some("path/to/first.yar"), Some("ns"))
    /// // - then:  ("subdir/third.yar", Some("../second.yar"),     Some("ns"))
    /// compiler.add_rules_file_in_namespace("path/to/first.yar", "ns");
    /// ```
    pub fn set_include_callback<F>(&mut self, callback: F)
    where
        F: FnMut(&str, Option<&Path>, &str) -> Result<String, std::io::Error>
            + Send
            + Sync
            + 'static,
    {
        self.include_callback = Some(IncludeCallback(Box::new(callback)));
    }

    /// Finalize the compiler and generate a [`Scanner`].
    #[must_use]
    pub fn finalize(self) -> Scanner {
        Scanner::new(self)
    }
}

/// Contains rules and modules that belong to the same shared namespace.
///
/// In a namespace:
/// - all rules must have unique names
/// - new rules can reference already existing rules
/// - new rules can either import new modules, or directly use already imported modules
#[derive(Debug, Default)]
pub(crate) struct Namespace {
    /// Name of the namespace.
    pub(crate) name: String,

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

/// Result status of adding a rule to a [`Compiler`].
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct AddRuleStatus {
    warnings: Vec<AddRuleError>,

    statistics: Vec<statistics::CompiledRule>,
}

impl AddRuleStatus {
    /// Return the list of warnings generated when adding the rule.
    pub fn warnings(&self) -> impl Iterator<Item = &AddRuleError> {
        self.warnings.iter()
    }

    /// Returns statistics on compiled rules.
    ///
    /// Statistics are only computed if [`CompilerParams::compute_statistics`] has been set.
    /// Otherwise, this will just return an empty iterator.
    pub fn statistics(&self) -> impl Iterator<Item = &statistics::CompiledRule> {
        self.statistics.iter()
    }
}

/// Error when adding a rule to a [`Compiler`].
#[derive(Debug)]
pub struct AddRuleError {
    /// The path to the file containing the error.
    ///
    /// None if the error happens on a raw string ([`Compiler::add_rules_str`]).
    pub path: Option<PathBuf>,

    /// The kind of error.
    ///
    /// Boxed because big.
    kind: Box<AddRuleErrorKind>,

    /// Description of the error.
    desc: String,
}

impl Display for AddRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.desc)
    }
}
impl std::error::Error for AddRuleError {}

/// Kind of error when adding a rule to a [`Compiler`].
#[derive(Debug)]
enum AddRuleErrorKind {
    /// Error while trying to read a file.
    ///
    /// This can happen either:
    /// - when using the [`Compiler::add_rules_file`] or [`Compiler::add_rules_file_in_namespace`]
    ///   and failing to read from the provided path.
    /// - On `include` clauses.
    IO {
        /// Path to the file.
        path: PathBuf,

        /// IO error on this path.
        error: std::io::Error,
    },

    /// An include directive could not be resolved.
    InvalidInclude {
        /// Path in the include clause that is invalid.
        path: PathBuf,

        /// Span of the include.
        span: Range<usize>,

        /// IO error on this path.
        error: std::io::Error,
    },

    /// An include directive was found, but includes are disabled.
    UnauthorizedInclude {
        /// Span of the include.
        span: Range<usize>,
    },

    /// Error while parsing a rule.
    Parse(boreal_parser::error::Error),

    /// Error while compiling a rule.
    Compilation(CompilationError),
}

impl AddRuleError {
    fn new(kind: AddRuleErrorKind, input_path: Option<&Path>, input: &str) -> Self {
        let path_display = input_path.map(|v| v.display().to_string());

        Self {
            desc: generate_description(
                &kind.to_diagnostic(),
                path_display.as_deref().unwrap_or("mem"),
                input,
            ),
            path: input_path.map(Path::to_path_buf),
            kind: Box::new(kind),
        }
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

/// Convert to a displayable, single-lined description.
///
/// # Arguments
///
/// * `input_name`: a name for the input, used at the beginning of the
///   description: `<filename>:<line>:<column>: <description>`.
/// * `input`: the input given to [`boreal_parser::parse`] that generated the error.
#[must_use]
pub fn generate_description(diag: &Diagnostic<()>, input_name: &str, input: &str) -> String {
    // Generate a small report using codespan_reporting
    let mut writer = term::termcolor::Buffer::no_color();
    let config = term::Config {
        display_style: term::DisplayStyle::Short,
        ..term::Config::default()
    };

    let files = SimpleFile::new(input_name, &input);
    let _res = term::emit(&mut writer, &config, &files, diag);
    let mut res = writer.as_slice();
    // remove the trailing \n that codespan reporting adds.
    if res.ends_with(b"\n") {
        res = &res[..(res.len() - 1)];
    }
    String::from_utf8_lossy(res).to_string()
}

impl AddRuleErrorKind {
    fn to_diagnostic(&self) -> Diagnostic<()> {
        match self {
            Self::IO { path, error } => Diagnostic::error().with_message(format!(
                "Cannot read rules file {}: {}",
                path.display(),
                error
            )),
            Self::InvalidInclude { path, span, error } => Diagnostic::error()
                .with_message(format!("cannot include `{}`: {error}", path.display()))
                .with_labels(vec![Label::primary((), span.clone())]),
            Self::UnauthorizedInclude { span } => Diagnostic::error()
                .with_message("includes are not allowed")
                .with_labels(vec![Label::primary((), span.clone())]),
            Self::Parse(err) => err.to_diagnostic(),
            Self::Compilation(err) => err.to_diagnostic(),
        }
    }
}

#[cfg(test)]
mod tests;
