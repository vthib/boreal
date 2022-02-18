//! Provides the [`Scanner`] object which provides methods to scan
//! files or memory on a set of rules.
use boreal_parser::Rule;

use crate::evaluator;

/// Holds a list of rules, and provides methods to
/// run them on files or bytes.
#[derive(Default)]
pub struct Scanner {
    rules: Vec<Rule>,
}

impl Scanner {
    /// Add rules in the scanner.
    pub fn add_rules(&mut self, mut rules: Vec<Rule>) {
        self.rules.append(&mut rules);
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given
    /// byte slice.
    #[must_use]
    pub fn scan_mem(&self, mem: &[u8]) -> Vec<&Rule> {
        // FIXME: this is pretty bad performance wise
        self.rules
            .iter()
            .filter(|rule| {
                // TODO: handle errors
                evaluator::evaluate_rule(rule, mem).unwrap_or(false)
            })
            .collect()
    }
}
