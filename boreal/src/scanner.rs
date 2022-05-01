//! Provides the [`Scanner`] object which provides methods to scan
//! files or memory on a set of rules.
use crate::{compiler::Rule, evaluator};

/// Holds a list of rules, and provides methods to run them on files or bytes.
#[derive(Debug)]
pub struct Scanner {
    rules: Vec<Rule>,
}

impl Scanner {
    #[must_use]
    pub(crate) fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
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
