//! Provides the [`Scanner`] object which provides methods to sca
//! files or memory on a set of rules.
use std::{collections::HashMap, sync::Arc};

use crate::{
    compiler::{ExternalSymbol, ExternalValue, Rule, Variable},
    evaluator::{self, ScanData, Value},
    module::Module,
    scan_params::{ScanParams, ScanParamsBuilder},
    variable_set::VariableSet,
};

/// Holds a list of rules, and provides methods to run them on files or bytes.
#[derive(Clone, Debug)]
pub struct Scanner {
    /// Inner value containing all compiled data.
    ///
    /// Put all compiled data into an inner struct behind an Arc: this allows cloning the Scanner
    /// cheaply, in order to use it in parallel or modify external variables without impacting
    /// other scans.
    inner: Arc<Inner>,

    /// Parameters to use during scanning.
    ///
    /// See documentation of [`ScanParamsBuilder`] for details on those parameters.
    scan_params: ScanParams,

    /// Default value of external symbols.
    ///
    /// Compiled rules uses indexing into this vec to retrieve the symbols values.
    external_symbols_values: Vec<Value>,
}

impl Scanner {
    pub(crate) fn new(
        rules: Vec<Rule>,
        global_rules: Vec<Rule>,
        variables: Vec<Variable>,
        modules: Vec<Box<dyn Module>>,
        external_symbols: Vec<ExternalSymbol>,
    ) -> Self {
        let variable_set = VariableSet::new(&variables);

        let mut external_symbols_values = Vec::new();
        let mut external_symbols_map = HashMap::new();
        for (index, sym) in external_symbols.into_iter().enumerate() {
            let ExternalSymbol {
                name,
                default_value,
            } = sym;
            external_symbols_values.push(default_value.into());
            let _ = external_symbols_map.insert(name, index);
        }

        Self {
            inner: Arc::new(Inner {
                rules,
                global_rules,
                variables,
                variable_set,
                modules,
                external_symbols_map,
            }),
            scan_params: ScanParamsBuilder::default().build(),
            external_symbols_values,
        }
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given byte slice.
    #[must_use]
    pub fn scan_mem<'scanner>(&'scanner self, mem: &'scanner [u8]) -> ScanResult<'scanner> {
        self.inner
            .scan(mem, &self.scan_params, &self.external_symbols_values)
    }

    /// Define a value for a symbol defined and used in compiled rules.
    ///
    /// This symbol must have been defined when compiling rules using
    /// [`crate::Compiler::define_symbol`]. The provided value must have the same type as
    /// the value provided to this function.
    ///
    /// # Errors
    ///
    /// Fails if a symbol of the given name has never been defined, or if the type of the value
    /// is invalid.
    pub fn define_symbol<S, T>(&mut self, name: S, value: T) -> Result<(), DefineSymbolError>
    where
        S: AsRef<str>,
        T: Into<ExternalValue>,
    {
        self.define_symbol_inner(name.as_ref(), value.into())
    }

    fn define_symbol_inner(
        &mut self,
        name: &str,
        value: ExternalValue,
    ) -> Result<(), DefineSymbolError> {
        let index = match self.inner.external_symbols_map.get(name) {
            Some(v) => *v,
            None => return Err(DefineSymbolError::UnknownName),
        };

        if let Some(v) = self.external_symbols_values.get_mut(index) {
            match (v, value) {
                (Value::Boolean(a), ExternalValue::Boolean(b)) => *a = b,
                (Value::Integer(a), ExternalValue::Integer(b)) => *a = b,
                (Value::Float(a), ExternalValue::Float(b)) => *a = b,
                (Value::Bytes(a), ExternalValue::Bytes(b)) => *a = b,
                _ => return Err(DefineSymbolError::InvalidType),
            }
        }

        Ok(())
    }

    /// Set scan parameters on this scanner.
    pub fn set_scan_params(&mut self, params: ScanParams) {
        self.scan_params = params;
    }
}

#[derive(Debug)]
struct Inner {
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

    /// Compiled variables.
    ///
    /// Those are stored in the order the rules have been compiled in.
    variables: Vec<Variable>,

    /// Regex set of all variables used in the rules.
    ///
    /// This is used to scan the memory in one go, and find which variables are found. This
    /// is usually sufficient for most rules. Other rules that depend on the number or length of
    /// matches will scan the memory during their evaluation.
    variable_set: VariableSet,

    /// List of modules used during scanning.
    modules: Vec<Box<dyn Module>>,

    /// Mapping from names to index for external symbols.
    external_symbols_map: HashMap<String, usize>,
}

impl Inner {
    fn scan<'scanner>(
        &'scanner self,
        mem: &[u8],
        params: &ScanParams,
        external_symbols_values: &[Value],
    ) -> ScanResult<'scanner> {
        let ScanParams {
            compute_full_matches,
        } = params;

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
        let variable_set_matches = self.variable_set.matches(mem, &self.variables);

        let mut matched_rules = Vec::new();
        let mut previous_results = Vec::with_capacity(self.rules.len());

        let scan_data = ScanData::new(
            mem,
            variable_set_matches,
            &self.modules,
            external_symbols_values,
        );

        // First, check global rules
        let mut var_index = 0;
        for rule in &self.global_rules {
            let (res, var_evals) = evaluator::evaluate_rule(
                rule,
                &self.variables[var_index..(var_index + rule.nb_variables)],
                &scan_data,
                var_index,
                &previous_results,
            );
            var_index += rule.nb_variables;

            if !res {
                matched_rules.clear();
                return ScanResult {
                    matched_rules,
                    module_values: scan_data.module_values,
                };
            }
            if !rule.is_private {
                matched_rules.push(build_matched_rule(
                    rule,
                    var_evals,
                    mem,
                    *compute_full_matches,
                ));
            }
        }

        // Then, if all global rules matched, the normal rules
        for rule in &self.rules {
            let res = {
                let (res, var_evals) = evaluator::evaluate_rule(
                    rule,
                    &self.variables[var_index..(var_index + rule.nb_variables)],
                    &scan_data,
                    var_index,
                    &previous_results,
                );

                var_index += rule.nb_variables;

                if res && !rule.is_private {
                    matched_rules.push(build_matched_rule(
                        rule,
                        var_evals,
                        mem,
                        *compute_full_matches,
                    ));
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
    mut var_evals: Vec<evaluator::VariableEvaluation<'a>>,
    mem: &[u8],
    compute_full_matches: bool,
) -> MatchedRule<'a> {
    if compute_full_matches {
        for var_eval in &mut var_evals {
            var_eval.compute_all_matches(mem);
        }
    }

    MatchedRule {
        namespace: rule.namespace.as_deref(),
        name: &rule.name,
        matches: var_evals
            .into_iter()
            .filter(|eval| !eval.var.is_private())
            .filter(|eval| !eval.matches.is_empty())
            .map(|eval| StringMatches {
                name: &eval.var.name,
                matches: eval
                    .matches
                    .iter()
                    .map(|mat| StringMatch {
                        offset: mat.start,
                        data: mem[mat.start..mat.end].to_vec(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

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
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum DefineSymbolError {
    /// No symbol with this name exists.
    UnknownName,
    /// The defined symbol has a different value type than the provided one.
    InvalidType,
}

impl std::error::Error for DefineSymbolError {}

impl std::fmt::Display for DefineSymbolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownName => write!(f, "unknown symbol name"),
            Self::InvalidType => write!(f, "invalid value type"),
        }
    }
}
