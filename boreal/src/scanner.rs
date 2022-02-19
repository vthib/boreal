//! Provides the [`Scanner`] object which provides methods to scan
//! files or memory on a set of rules.
use boreal_parser::Rule;

use crate::{evaluator, ScanError};

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
    pub fn scan_mem(&self, mem: &[u8]) -> ScanResults {
        // FIXME: this is pretty bad performance wise
        let mut results = ScanResults::default();
        for rule in &self.rules {
            // TODO: handle errors
            match evaluator::evaluate_rule(rule, mem) {
                Ok(true) => results.matching_rules.push(rule),
                Ok(false) => (),
                Err(error) => results.scan_errors.push(RuleScanError { rule, error }),
            }
        }
        results
    }
}

#[derive(Default)]
pub struct ScanResults<'a> {
    pub matching_rules: Vec<&'a Rule>,

    pub scan_errors: Vec<RuleScanError<'a>>,
}

pub struct RuleScanError<'a> {
    pub rule: &'a Rule,
    pub error: ScanError,
}
