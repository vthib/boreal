//! Provides the [`Scanner`] object which provides methods to sca
//! files or memory on a set of rules.
use std::sync::Arc;

use crate::{
    compiler::{CompilationError, Rule},
    evaluator::{self, ScanData},
    module::Module,
    variable_set::VariableSet,
};

/// Holds a list of rules, and provides methods to run them on files or bytes.
#[derive(Debug)]
pub struct Scanner {
    /// List of compiled rules.
    ///
    /// Order is important, as rules can depend on other rules, and uses indexes into this array
    /// to retrieve the truth value of rules it depends upon.
    rules: Vec<Rule>,

    /// Compiled global rules.
    ///
    /// Those rules are interpreted first. If any of them is false, the other rules are not
    /// evaluated.
    global_rules: Vec<Rule>,

    /// Regex set of all variables used in the rules.
    ///
    /// This is used to scan the memory in one go, and find which variables are found. This
    /// is usually sufficient for most rules. Other rules that depend on the number or length of
    /// matches will scan the memory during their evaluation.
    variable_set: VariableSet,

    /// List of modules used during scanning.
    modules: Vec<Box<dyn Module>>,
}

impl Scanner {
    pub(crate) fn new(
        rules: Vec<Rule>,
        global_rules: Vec<Rule>,
        modules: Vec<Box<dyn Module>>,
    ) -> Result<Self, CompilationError> {
        let exprs: Vec<_> = global_rules
            .iter()
            .chain(rules.iter())
            .flat_map(|rule| rule.variables.iter().map(|v| &v.expr))
            .collect();

        let variable_set = VariableSet::new(&exprs)?;

        Ok(Self {
            rules,
            global_rules,
            variable_set,
            modules,
        })
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given
    /// byte slice.
    #[must_use]
    pub fn scan_mem<'scanner>(&'scanner self, mem: &'scanner [u8]) -> ScanResult<'scanner> {
        // First, run the regex set on the memory. This does a single pass on it, finding out
        // which variables have no miss at all.
        //
        // TODO: this is not optimal w.r.t. global rules. I imagine people can use global rules
        // that do not have variables, and attempt to avoid the cost of scanning if those rules do
        // not match.
        // A better solution would be:
        // - evaluate global rules that have no variables first
        // - then scan the set
        // - then evaluate rest of global rules first, then rules
        let variable_set_matches = self.variable_set.matches(mem);

        let mut matched_rules = Vec::new();
        let mut previous_results = Vec::with_capacity(self.rules.len());

        let scan_data = ScanData::new(mem, variable_set_matches, &self.modules);

        // First, check global rules
        let mut set_index_offset = 0;
        for rule in &self.global_rules {
            let (res, var_evals) =
                evaluator::evaluate_rule(rule, &scan_data, set_index_offset, &previous_results);
            set_index_offset += rule.variables.len();

            if !res {
                matched_rules.clear();
                return ScanResult {
                    matched_rules,
                    module_values: scan_data.module_values,
                };
            }
            if !rule.is_private {
                matched_rules.push(build_matched_rule(rule, var_evals, mem));
            }
        }

        // Then, if all global rules matched, the normal rules
        for rule in &self.rules {
            let res = {
                let (res, var_evals) =
                    evaluator::evaluate_rule(rule, &scan_data, set_index_offset, &previous_results);

                set_index_offset += rule.variables.len();

                if res && !rule.is_private {
                    matched_rules.push(build_matched_rule(rule, var_evals, mem));
                }
                res
            };
            previous_results.push(res);
        }

        ScanResult {
            matched_rules,
            module_values: scan_data.module_values,
        }
    }
}

fn build_matched_rule<'a>(
    rule: &'a Rule,
    var_evals: Vec<evaluator::VariableEvaluation<'a>>,
    mem: &[u8],
) -> MatchedRule<'a> {
    MatchedRule {
        namespace: rule.namespace.as_deref(),
        name: &rule.name,
        matches: var_evals
            .into_iter()
            .filter(|eval| !eval.var.is_private())
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
    }
}

// TODO: add tests on those results

/// Result of a scan
#[derive(Debug)]
pub struct ScanResult<'scanner> {
    /// List of rules that matched.
    pub matched_rules: Vec<MatchedRule<'scanner>>,

    /// On-scan values of all modules used in the scanner.
    ///
    /// First element is the module name, second one is the dynamic values produced by the module.
    pub module_values: Vec<(&'static str, Arc<crate::module::Value>)>,
}

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
