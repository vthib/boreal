//! Provides the [`Scanner`] object which provides methods to scan
//! files or memory on a set of rules.
use std::collections::HashMap;

use crate::{compiler::Rule, evaluator};

/// Holds a list of rules, and provides methods to run them on files or bytes.
#[derive(Debug)]
pub struct Scanner {
    rules: Vec<Rule>,

    // List of modules used during scanning.
    modules: HashMap<String, ScannerModule>,
}

impl Scanner {
    #[must_use]
    pub(crate) fn new(rules: Vec<Rule>, modules: HashMap<String, ScannerModule>) -> Self {
        Self { rules, modules }
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given
    /// byte slice.
    #[must_use]
    pub fn scan_mem<'scanner>(&'scanner self, mem: &'scanner [u8]) -> Vec<MatchedRule<'scanner>> {
        // FIXME: this is pretty bad performance wise
        let mut results = Vec::new();
        let mut previous_results = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let res = {
                // TODO: only get dynamic values for modules once for the mem, not once per rule.
                let (res, var_evals) =
                    evaluator::evaluate_rule(rule, &self.modules, mem, &previous_results);
                if res {
                    results.push(MatchedRule {
                        namespace: rule.namespace.as_deref(),
                        name: &rule.name,
                        matches: var_evals
                            .into_iter()
                            .map(|eval| StringMatches {
                                name: &eval.var.name,
                                matches: eval
                                    .matches
                                    .iter()
                                    .map(|mat| StringMatch {
                                        offset: mat.start,
                                        value: mem[mat.start..mat.end].to_vec(),
                                    })
                                    .collect(),
                            })
                            .collect(),
                    });
                }
                res
            };
            previous_results.push(res);
        }
        results
    }
}

/// Module to use during scan.
///
/// Cheap to clone, as it is cloned on every scan.
pub struct ScannerModule {
    // TODO: keep only the get_dynamic_values function?
    module: Box<dyn crate::module::Module>,
}

impl std::fmt::Debug for ScannerModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScannerModule")
            .field("module", &self.module.get_name())
            .finish()
    }
}

impl ScannerModule {
    pub fn new(module: Box<dyn crate::module::Module>) -> Self {
        Self { module }
    }

    pub fn on_scan(&self, ctx: &crate::module::ScanContext) -> crate::module::Value {
        crate::module::Value::Object(self.module.get_dynamic_values(ctx))
    }
}

// TODO: add tests on those results

/// Description of a rule that matched during a scan.
#[derive(Debug)]
pub struct MatchedRule<'scanner> {
    /// Namespace containing the rule. None if in the default namespace.
    pub namespace: Option<&'scanner str>,

    /// Name of the rule.
    pub name: &'scanner str,

    /// List of matched strings, with details on their matches.
    pub matches: Vec<StringMatches<'scanner>>,
}

/// Details on matches for a string.
#[derive(Debug)]
pub struct StringMatches<'scanner> {
    /// Name of the string
    pub name: &'scanner str,

    /// List of matches found for this string.
    ///
    /// This is not guaranteed to be complete! If the rule
    /// could be resolved without scanning entirely the input
    /// for this variable, some potential matches will not
    /// be reported.
    pub matches: Vec<StringMatch>,
}

/// Details on a match on a string during a scan.
#[derive(Debug)]
pub struct StringMatch {
    /// Offset of the match
    pub offset: usize,

    /// The matched data.
    // TODO: implement a max bound for this
    pub value: Vec<u8>,
}
