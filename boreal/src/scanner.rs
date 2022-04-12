//! Provides the [`Scanner`] object which provides methods to scan
//! files or memory on a set of rules.
use std::collections::HashMap;

use codespan_reporting::diagnostic::Diagnostic;
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;

use boreal_parser as parser;

use crate::compiler::{compile_file, compile_module, CompilationError, Module, Rule};
use crate::evaluator;

/// Holds a list of rules, and provides methods to
/// run them on files or bytes.
#[derive(Default)]
pub struct Scanner {
    rules: Vec<Rule>,

    modules: HashMap<String, Module>,
}

impl Scanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a module
    pub fn add_module<M: crate::module::Module>(&mut self, module: M) {
        let m = compile_module(module);
        let _ = self.modules.insert(m.name.clone(), m);
    }

    /// Add rules to the scanner from a string.
    ///
    /// # Errors
    ///
    /// If parsing of the rules fails, an error is returned.
    pub fn add_rules_from_str(&mut self, s: &str) -> Result<(), AddRuleError> {
        let file = parser::parse_str(s).map_err(AddRuleError::ParseError)?;
        self.add_file(file)
            .map_err(AddRuleError::CompilationError)?;
        Ok(())
    }

    /// Add rules in the scanner.
    fn add_file(&mut self, file: parser::YaraFile) -> Result<(), CompilationError> {
        let rules = compile_file(file, &self.modules)?;
        self.rules.extend(rules);
        Ok(())
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given
    /// byte slice.
    #[must_use]
    pub fn scan_mem(&self, mem: &[u8]) -> ScanResults {
        // FIXME: this is pretty bad performance wise
        let mut results = ScanResults::default();
        for rule in &self.rules {
            if evaluator::evaluate_rule(rule, mem) {
                results.matching_rules.push(rule);
            }
        }
        results
    }
}

#[derive(Default)]
pub struct ScanResults<'a> {
    pub matching_rules: Vec<&'a Rule>,
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
