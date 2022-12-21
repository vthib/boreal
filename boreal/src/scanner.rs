//! Provides the [`Scanner`] object used to scan bytes against a set of compiled rules.
use std::collections::HashMap;
use std::sync::Arc;

use crate::compiler::external_symbol::{ExternalSymbol, ExternalValue};
use crate::compiler::rule::Rule;
use crate::compiler::variable::Variable;
use crate::evaluator::ac_scan::AcScan;
use crate::evaluator::{evaluate_rule, Params as EvalParams, ScanData, Value, VariableEvaluation};
use crate::module::Module;

mod params;
pub use params::ScanParams;

/// Holds a list of rules, and provides methods to run them on files or bytes.
///
/// A [`Scanner`] can be created with a [`crate::Compiler`] object when all rules have been
/// added to it.
///
/// ```
/// let mut compiler = boreal::Compiler::new();
///
/// // Add as many rules as desired.
/// compiler.add_rules_str("rule a { strings: $a = \"abc\" condition: $a }")?;
///
/// // Compile all the rules and generate a scanner.
/// let scanner = compiler.into_scanner();
///
/// // Use the scanner to run the rules against byte strings or files.
/// let scan_result = scanner.scan_mem(b"abc");
/// assert_eq!(scan_result.matched_rules.len(), 1);
/// # Ok::<(), boreal::compiler::AddRuleError>(())
/// ```
///
/// If you need to use the scanner in a multi-thread context, and need to define symbols or
/// modify scan parameters for each scan, you can clone the object, which is guaranteed to be
/// cheap.
///
/// ```
/// let mut compiler = boreal::Compiler::new();
/// compiler.define_symbol("extension", "");
/// compiler.add_rules_str("rule a { condition: extension endswith \"pdf\" }")?;
/// let scanner = compiler.into_scanner();
///
/// let thread1 = {
///     let mut scanner = scanner.clone();
///     std::thread::spawn(move || {
///         scanner.define_symbol("extension", "exe");
///         let res = scanner.scan_mem(b"");
///         assert!(res.matched_rules.is_empty());
///     })
/// };
/// let thread2 = {
///     let mut scanner = scanner.clone();
///     std::thread::spawn(move || {
///          scanner.define_symbol("extension", "pdf");
///          let res = scanner.scan_mem(b"");
///          assert_eq!(res.matched_rules.len(), 1);
///     })
/// };
///
/// thread1.join();
/// thread2.join();
/// # Ok::<(), boreal::compiler::AddRuleError>(())
/// ```
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
    /// See documentation of [`ScanParams`] for details on those parameters.
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
        let ac_scan = AcScan::new(&variables);

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
                ac_scan,
                modules,
                external_symbols_map,
            }),
            scan_params: ScanParams::default(),
            external_symbols_values,
        }
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given byte slice.
    #[must_use]
    pub fn scan_mem<'scanner>(&'scanner self, mem: &[u8]) -> ScanResult<'scanner> {
        self.inner
            .scan(mem, &self.scan_params, &self.external_symbols_values)
    }

    /// Scan a file.
    ///
    /// Returns a list of rules that matched the given file.
    ///
    /// # Errors
    ///
    /// Fails if the file at the given path cannot be read.
    pub fn scan_file<P: AsRef<std::path::Path>>(&self, path: P) -> std::io::Result<ScanResult> {
        let contents = std::fs::read(path.as_ref())?;
        Ok(self.scan_mem(&contents))
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

    /// Get the current scan parameters on this scanner.
    #[must_use]
    pub fn scan_params(&self) -> &ScanParams {
        &self.scan_params
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
    ac_scan: AcScan,

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
        let scan_data = ScanData::new(mem, &self.modules, external_symbols_values);

        if !params.compute_full_matches {
            if let Some(matched_rules) = self.evaluate_without_matches(&scan_data, params) {
                return ScanResult {
                    matched_rules,
                    module_values: scan_data.module_values,
                };
            }
        }

        // First, run the regex set on the memory. This does a single pass on it, finding out
        // which variables have no miss at all.
        let eval_params = EvalParams {
            string_max_nb_matches: params.string_max_nb_matches,
        };
        let ac_matches = self.ac_scan.matches(mem, &self.variables, eval_params);

        let mut matched_rules = Vec::new();
        let mut previous_results = Vec::with_capacity(self.rules.len());

        // First, check global rules
        let mut var_evals_iterator = self
            .variables
            .iter()
            .zip(ac_matches.into_iter())
            .map(|(var, ac_result)| VariableEvaluation::new(var, eval_params, ac_result));

        for rule in &self.global_rules {
            let mut var_evals = collect_nb_elems(&mut var_evals_iterator, rule.nb_variables);
            let res = evaluate_rule(rule, Some(&mut var_evals), &scan_data, &previous_results)
                .unwrap_or(false);

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
                    params.compute_full_matches,
                    params.match_max_length,
                ));
            }
        }

        // Then, if all global rules matched, the normal rules
        for rule in &self.rules {
            let res = {
                let mut var_evals = collect_nb_elems(&mut var_evals_iterator, rule.nb_variables);
                let res = evaluate_rule(rule, Some(&mut var_evals), &scan_data, &previous_results)
                    .unwrap_or(false);

                if res && !rule.is_private {
                    matched_rules.push(build_matched_rule(
                        rule,
                        var_evals,
                        mem,
                        params.compute_full_matches,
                        params.match_max_length,
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

    /// Evaluate all rules without availability of the variables' matches.
    ///
    /// This returns None if variables' matches must be computed, otherwise it returns the
    /// final result of the scan.
    fn evaluate_without_matches<'scanner>(
        &'scanner self,
        scan_data: &ScanData<'_>,
        params: &ScanParams,
    ) -> Option<Vec<MatchedRule<'scanner>>> {
        let mut matched_rules = Vec::new();
        let mut previous_results = Vec::with_capacity(self.rules.len());

        // First, check global rules
        let mut has_unknown_globals = false;
        for rule in &self.global_rules {
            match evaluate_rule(rule, None, scan_data, &previous_results) {
                Some(true) => {
                    if !rule.is_private {
                        matched_rules.push(build_matched_rule(
                            rule,
                            Vec::new(),
                            scan_data.mem,
                            false,
                            params.match_max_length,
                        ));
                    }
                }
                Some(false) => return Some(Vec::new()),
                // Do not rethrow immediately, so that if one of the globals is false, it is
                // detected.
                None => has_unknown_globals = true,
            }
        }
        if has_unknown_globals {
            return None;
        }

        // Then, if all global rules matched, the normal rules
        for rule in &self.rules {
            let matched = evaluate_rule(rule, None, scan_data, &previous_results)?;

            if matched && !rule.is_private {
                matched_rules.push(build_matched_rule(
                    rule,
                    Vec::new(),
                    scan_data.mem,
                    false,
                    params.match_max_length,
                ));
            }
            previous_results.push(matched);
        }

        Some(matched_rules)
    }
}

fn collect_nb_elems<I: Iterator<Item = T>, T>(iter: &mut I, nb: usize) -> Vec<T> {
    let mut res = Vec::with_capacity(nb);
    loop {
        if res.len() >= nb {
            return res;
        }
        // TODO: do not unwrap, bubble up inconsistency error
        res.push(iter.next().unwrap());
    }
}

fn build_matched_rule<'a>(
    rule: &'a Rule,
    mut var_evals: Vec<VariableEvaluation<'a>>,
    mem: &[u8],
    compute_full_matches: bool,
    match_max_length: usize,
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
            .filter(|eval| !eval.var.is_private)
            .filter(|eval| !eval.matches.is_empty())
            .map(|eval| StringMatches {
                name: &eval.var.name,
                matches: eval
                    .matches
                    .iter()
                    .map(|mat| {
                        let length = mat.end - mat.start;
                        let capped_length = std::cmp::min(length, match_max_length);
                        StringMatch {
                            offset: mat.start,
                            length: mat.end - mat.start,
                            data: mem[mat.start..]
                                .iter()
                                .take(capped_length)
                                .copied()
                                .collect(),
                        }
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

    /// Actual length of the match.
    ///
    /// This is the real length of the match, which might be bigger than the length of `data`.
    pub length: usize,

    /// The matched data.
    ///
    /// The length of this field is capped.
    pub data: Vec<u8>,
}

/// Error when defining a symbol's value in a [`Scanner`].
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::module::{ScanContext, StaticValue, Type, Value as ModuleValue};
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};
    use crate::Compiler;

    use super::*;

    struct Test;

    impl Module for Test {
        fn get_name(&self) -> &'static str {
            "test"
        }

        fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
            [(
                "to_bytes",
                StaticValue::function(Self::to_bytes, vec![vec![Type::Integer]], Type::Bytes),
            )]
            .into()
        }

        fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
            [
                ("array", Type::array(Type::Integer)),
                ("dict", Type::dict(Type::Integer)),
            ]
            .into()
        }

        fn get_dynamic_values(&self, _: &mut ScanContext) -> HashMap<&'static str, ModuleValue> {
            [
                ("array", ModuleValue::Array(vec![ModuleValue::Integer(3)])),
                (
                    "dict",
                    ModuleValue::Dictionary([(b"a".to_vec(), ModuleValue::Integer(3))].into()),
                ),
            ]
            .into()
        }
    }

    impl Test {
        fn to_bytes(_ctx: &ScanContext, args: Vec<ModuleValue>) -> Option<ModuleValue> {
            let mut args = args.into_iter();
            let v: i64 = args.next()?.try_into().ok()?;
            Some(ModuleValue::Bytes(format!("{v}").into_bytes()))
        }
    }

    fn empty_rule(cond: &str) -> String {
        format!(
            r#"
            import "test"

            rule yes {{ condition: true }}
            rule no {{ condition: false }}

            rule a {{
                condition: {}
            }}
        "#,
            cond
        )
    }

    fn single_var_rule(cond: &str) -> String {
        format!(
            r#"
            import "test"

            rule yes {{ condition: true }}
            rule no {{ condition: false }}

            rule a {{
                strings:
                    $a = /abc/
                condition:
                    {}
            }}
        "#,
            cond
        )
    }

    #[track_caller]
    fn test_eval_with_poison(rule_str: &str, mem: &[u8], expected: Option<bool>) {
        let mut compiler = Compiler::default();
        let _ = compiler.add_module(Test);
        compiler.add_rules_str(rule_str).unwrap();
        let scanner = compiler.into_scanner();

        let scan_data = ScanData::new(
            mem,
            &scanner.inner.modules,
            &scanner.external_symbols_values,
        );
        let mut previous_results = Vec::new();
        let rules = &scanner.inner.rules;
        for rule in &rules[..(rules.len() - 1)] {
            previous_results
                .push(evaluate_rule(rule, None, &scan_data, &previous_results).unwrap());
        }
        let last_res = evaluate_rule(&rules[rules.len() - 1], None, &scan_data, &previous_results);

        assert_eq!(last_res, expected);
    }

    #[test]
    fn test_poison_filesize() {
        test_eval_with_poison(&empty_rule("filesize"), b"", Some(false));
        test_eval_with_poison(&empty_rule("filesize"), b"a", Some(true));
    }

    #[test]
    fn test_poison_entrypoint() {
        test_eval_with_poison(&empty_rule("entrypoint"), b"", Some(false));
    }

    #[test]
    fn test_poison_read_integer() {
        test_eval_with_poison(&empty_rule("uint16(0)"), b"", Some(false));
        test_eval_with_poison(&empty_rule("uint16(0)"), b"abc", Some(true));
        test_eval_with_poison(&single_var_rule("uint16(#a)"), b"abc", None);
    }

    #[test]
    fn test_poison_count_in_range() {
        test_eval_with_poison(&empty_rule("# in (0..3)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a in (0..3)"), b"", None);
        test_eval_with_poison(&single_var_rule("#a in (0..#a)"), b"", None);
        test_eval_with_poison(&single_var_rule("#a in (#a..1)"), b"", None);
        test_eval_with_poison(&single_var_rule("#a in (0..entrypoint)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a in (entrypoint..5)"), b"", Some(false));
    }

    #[test]
    fn test_poison_count() {
        test_eval_with_poison(&single_var_rule("#a"), b"", None);
        test_eval_with_poison(&empty_rule("#"), b"", Some(false));
    }

    #[test]
    fn test_poison_offset() {
        test_eval_with_poison(&single_var_rule("@a"), b"", None);
        test_eval_with_poison(&empty_rule("@"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("@a[2]"), b"", None);
        test_eval_with_poison(&single_var_rule("@a[entrypoint]"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("@a[#a]"), b"", None);
    }

    #[test]
    fn test_poison_length() {
        test_eval_with_poison(&single_var_rule("!a"), b"", None);
        test_eval_with_poison(&empty_rule("!"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("!a[2]"), b"", None);
        test_eval_with_poison(&single_var_rule("!a[entrypoint]"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("!a[#a]"), b"", None);
    }

    #[test]
    fn test_poison_neg() {
        test_eval_with_poison(&empty_rule("-1"), b"", Some(true));
        test_eval_with_poison(&single_var_rule("-#a"), b"", None);
    }

    #[test]
    fn test_poison_add() {
        test_eval_with_poison(&empty_rule("1 + 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 + entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint + 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 + #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a + 1"), b"", None);
    }

    #[test]
    fn test_poison_mul() {
        test_eval_with_poison(&empty_rule("1 * 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 * entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint * 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 * #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a * 1"), b"", None);
    }

    #[test]
    fn test_poison_sub() {
        test_eval_with_poison(&empty_rule("1 - 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 - entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint - 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 - #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a - 1"), b"", None);
    }

    #[test]
    fn test_poison_div() {
        test_eval_with_poison(&empty_rule("4 \\ 3"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 \\ uint8(0)"), b"\0", Some(false));
        test_eval_with_poison(&empty_rule("1 \\ entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint \\ 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 \\ #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a \\ 1"), b"", None);
    }

    #[test]
    fn test_poison_mod() {
        test_eval_with_poison(&empty_rule("4 % 3"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 % uint8(0)"), b"\0", Some(false));
        test_eval_with_poison(&empty_rule("1 % entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint % 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 % #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a % 1"), b"", None);
    }

    #[test]
    fn test_poison_bitwise_xor() {
        test_eval_with_poison(&empty_rule("1 ^ 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 ^ entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint ^ 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 ^ #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a ^ 1"), b"", None);
    }

    #[test]
    fn test_poison_bitwise_and() {
        test_eval_with_poison(&empty_rule("1 & 2"), b"", Some(false));
        test_eval_with_poison(&empty_rule("1 & entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint & 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 & #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a & 1"), b"", None);
    }

    #[test]
    fn test_poison_bitwise_or() {
        test_eval_with_poison(&empty_rule("1 | 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 | entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint | 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 | #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a | 1"), b"", None);
    }

    #[test]
    fn test_poison_bitwise_not() {
        test_eval_with_poison(&empty_rule("~1"), b"", Some(true));
        test_eval_with_poison(&empty_rule("~entrypoint"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("~#a"), b"", None);
    }

    #[test]
    fn test_poison_shift_left() {
        test_eval_with_poison(&empty_rule("1 << 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 << -2"), b"", Some(false));
        test_eval_with_poison(&empty_rule("1 << entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint << 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 << #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a << 1"), b"", None);
    }

    #[test]
    fn test_poison_shift_right() {
        test_eval_with_poison(&empty_rule("2 >> 1"), b"", Some(true));
        test_eval_with_poison(&empty_rule("2 >> -1"), b"", Some(false));
        test_eval_with_poison(&empty_rule("1 >> entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint >> 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 >> #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a >> 1"), b"", None);
    }

    #[test]
    fn test_poison_and() {
        test_eval_with_poison(&empty_rule("true and true"), b"", Some(true));
        test_eval_with_poison(&empty_rule("true and entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint and true"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a and true"), b"", None);
        test_eval_with_poison(&single_var_rule("true and #a"), b"", None);
        test_eval_with_poison(&single_var_rule("#a and false"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("false and #a"), b"", Some(false));
    }

    #[test]
    fn test_poison_or() {
        test_eval_with_poison(&empty_rule("true or false"), b"", Some(true));
        test_eval_with_poison(&empty_rule("true or entrypoint"), b"", Some(true));
        test_eval_with_poison(&empty_rule("entrypoint or true"), b"", Some(true));
        test_eval_with_poison(&single_var_rule("#a or true"), b"", Some(true));
        test_eval_with_poison(&single_var_rule("true or #a"), b"", Some(true));
        test_eval_with_poison(&single_var_rule("#a or false"), b"", None);
        test_eval_with_poison(&single_var_rule("false or #a"), b"", None);
    }

    #[test]
    fn test_poison_cmp() {
        test_eval_with_poison(&empty_rule("1 <= 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 < entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint >= 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a <= 2"), b"", None);
        test_eval_with_poison(&single_var_rule("1 > #a"), b"", None);
    }

    #[test]
    fn test_poison_eq() {
        test_eval_with_poison(&empty_rule("1 == 2"), b"", Some(false));
        test_eval_with_poison(&empty_rule("1 == entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint == 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a == 2"), b"", None);
        test_eval_with_poison(&single_var_rule("1 == #a"), b"", None);
    }

    #[test]
    fn test_poison_not_eq() {
        test_eval_with_poison(&empty_rule("1 != 2"), b"", Some(true));
        test_eval_with_poison(&empty_rule("1 != entrypoint"), b"", Some(false));
        test_eval_with_poison(&empty_rule("entrypoint != 1"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a != 2"), b"", None);
        test_eval_with_poison(&single_var_rule("1 != #a"), b"", None);
    }

    #[test]
    fn test_poison_contains() {
        test_eval_with_poison(&empty_rule(r#""abc" contains "b""#), b"", Some(true));
        test_eval_with_poison(
            &empty_rule(r#""a" icontains test.to_bytes(entrypoint)"#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &empty_rule(r#"test.to_bytes(entrypoint) contains "a""#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule(r#""a" icontains test.to_bytes(#a)"#),
            b"",
            None,
        );
        test_eval_with_poison(
            &single_var_rule(r#"test.to_bytes(#a) contains "a""#),
            b"",
            None,
        );
    }

    #[test]
    fn test_poison_startswith() {
        test_eval_with_poison(&empty_rule(r#""ab" startswith "a""#), b"", Some(true));
        test_eval_with_poison(
            &empty_rule(r#""a" istartswith test.to_bytes(entrypoint)"#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &empty_rule(r#"test.to_bytes(entrypoint) startswith "a""#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule(r#""a" istartswith test.to_bytes(#a)"#),
            b"",
            None,
        );
        test_eval_with_poison(
            &single_var_rule(r#"test.to_bytes(#a) startswith "a""#),
            b"",
            None,
        );
    }

    #[test]
    fn test_poison_endswith() {
        test_eval_with_poison(&empty_rule(r#""ab" endswith "b""#), b"", Some(true));
        test_eval_with_poison(
            &empty_rule(r#""a" iendswith test.to_bytes(entrypoint)"#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &empty_rule(r#"test.to_bytes(entrypoint) endswith "a""#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule(r#""a" iendswith test.to_bytes(#a)"#),
            b"",
            None,
        );
        test_eval_with_poison(
            &single_var_rule(r#"test.to_bytes(#a) endswith "a""#),
            b"",
            None,
        );
    }

    #[test]
    fn test_poison_iequals() {
        test_eval_with_poison(&empty_rule(r#""ab" iequals "Ab""#), b"", Some(true));
        test_eval_with_poison(
            &empty_rule(r#""a" iequals test.to_bytes(entrypoint)"#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &empty_rule(r#"test.to_bytes(entrypoint) iequals "a""#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule(r#""a" iequals test.to_bytes(#a)"#),
            b"",
            None,
        );
        test_eval_with_poison(
            &single_var_rule(r#"test.to_bytes(#a) iequals "a""#),
            b"",
            None,
        );
    }

    #[test]
    fn test_poison_matches() {
        test_eval_with_poison(&empty_rule(r#""ab" matches /a/"#), b"", Some(true));
        test_eval_with_poison(
            &empty_rule(r#"test.to_bytes(entrypoint) matches /a/"#),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule(r#"test.to_bytes(#a) matches /a/"#),
            b"",
            None,
        );
    }

    #[test]
    fn test_poison_defined() {
        test_eval_with_poison(&empty_rule("defined 0"), b"", Some(true));
        test_eval_with_poison(&empty_rule("defined entrypoint"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("defined #a"), b"", None);
    }

    #[test]
    fn test_poison_not() {
        test_eval_with_poison(&empty_rule("not 0"), b"", Some(true));
        test_eval_with_poison(&empty_rule("not entrypoint"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("not #a"), b"", None);
    }

    #[test]
    fn test_poison_variable() {
        test_eval_with_poison(&single_var_rule("$a"), b"", None);
        test_eval_with_poison(&empty_rule("$"), b"", Some(false));
    }

    #[test]
    fn test_poison_variable_at() {
        test_eval_with_poison(&single_var_rule("$a at 0"), b"", None);
        test_eval_with_poison(&empty_rule("$ at 0"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("$a at entrypoint"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("$a at #a"), b"", None);
    }

    #[test]
    fn test_poison_variable_in() {
        test_eval_with_poison(&single_var_rule("$a in (0..5)"), b"", None);
        test_eval_with_poison(&empty_rule("$ in (0..5)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("$a in (0..entrypoint)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("$a in (entrypoint..5)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("$a in (0..#a)"), b"", None);
        test_eval_with_poison(&single_var_rule("$a in (#a..5)"), b"", None);
    }

    #[test]
    fn test_poison_for() {
        test_eval_with_poison(&single_var_rule("any of them"), b"", None);
        test_eval_with_poison(&single_var_rule("all of them"), b"", None);
        test_eval_with_poison(&single_var_rule("none of them"), b"", None);
        test_eval_with_poison(&single_var_rule("5 of them"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("1 of them"), b"", None);
        test_eval_with_poison(&single_var_rule("5% of them"), b"", None);
        test_eval_with_poison(&single_var_rule("#a of them"), b"", None);
        test_eval_with_poison(&single_var_rule("#a% of them"), b"", None);

        test_eval_with_poison(&single_var_rule("any of them in (0..2)"), b"", None);
        test_eval_with_poison(
            &single_var_rule("any of them in (0..entrypoint)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule("any of them in (entrypoint..5)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("any of them in (0..#a)"), b"", None);
        test_eval_with_poison(&single_var_rule("any of them in (#a..5)"), b"", None);

        test_eval_with_poison(&single_var_rule("any of ($a)"), b"", None);
        test_eval_with_poison(
            &single_var_rule("for any of ($a): (false)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("for any of ($a): (true)"), b"", Some(true));
        test_eval_with_poison(
            &single_var_rule("for any of them: (false)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("for any of them: (true)"), b"", Some(true));
    }

    #[test]
    fn test_poison_for_identifiers() {
        test_eval_with_poison(&empty_rule("for any i in (1): (true)"), b"", Some(true));
        test_eval_with_poison(
            &empty_rule("for any i in (1): (entrypoint)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("for any i in (1): (!a[i])"), b"", None);

        test_eval_with_poison(&empty_rule("for any i in (1..2): (true)"), b"", Some(true));
        test_eval_with_poison(
            &empty_rule("for any i in (1..2): (entrypoint)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("for any i in (1..2): (!a[i])"), b"", None);

        test_eval_with_poison(
            &empty_rule("for all i in (entrypoint): (true)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("for all i in (#a): (true)"), b"", None);

        test_eval_with_poison(
            &empty_rule("for all i in (0..entrypoint): (true)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &empty_rule("for all i in (entrypoint..1): (true)"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("for all i in (0..#a): (true)"), b"", None);
        test_eval_with_poison(&single_var_rule("for all i in (#a..1): (true)"), b"", None);

        test_eval_with_poison(&single_var_rule("for #a i in (1): (true)"), b"", None);

        test_eval_with_poison(
            &empty_rule("for any i in test.array: (true)"),
            b"",
            Some(true),
        );
        test_eval_with_poison(
            &single_var_rule("for any i in test.array: (!a[i])"),
            b"",
            None,
        );

        test_eval_with_poison(
            &empty_rule("for any k,v in test.dict: (true)"),
            b"",
            Some(true),
        );
        test_eval_with_poison(
            &single_var_rule("for any k,v in test.dict: (@a[v])"),
            b"",
            None,
        );
    }

    #[test]
    fn test_poison_for_rules() {
        test_eval_with_poison(&empty_rule("2 of (no, yes)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("#a of (yes, no)"), b"", None);
        test_eval_with_poison(&single_var_rule("#a% of (yes, no)"), b"", None);
    }

    #[test]
    fn test_poison_module() {
        test_eval_with_poison(&empty_rule("test.to_bytes(5)"), b"", Some(true));
        test_eval_with_poison(&empty_rule("test.to_bytes(entrypoint)"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("test.to_bytes(#a)"), b"", None);

        test_eval_with_poison(&empty_rule("test.array[0]"), b"", Some(true));
        test_eval_with_poison(&empty_rule("test.array[entrypoint]"), b"", Some(false));
        test_eval_with_poison(&single_var_rule("test.array[#a]"), b"", None);

        test_eval_with_poison(&empty_rule("test.dict[\"a\"]"), b"", Some(true));
        test_eval_with_poison(
            &empty_rule("test.dict[test.to_bytes(entrypoint)]"),
            b"",
            Some(false),
        );
        test_eval_with_poison(&single_var_rule("test.dict[test.to_bytes(#a)]"), b"", None);
    }

    #[test]
    fn test_types_traits() {
        test_type_traits(Scanner::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
        test_type_traits_non_clonable(ScanResult {
            matched_rules: Vec::new(),
            module_values: Vec::new(),
        });
        test_type_traits_non_clonable(MatchedRule {
            namespace: None,
            name: "a",
            matches: Vec::new(),
        });
        test_type_traits_non_clonable(StringMatches {
            name: "a",
            matches: Vec::new(),
        });
        test_type_traits_non_clonable(StringMatch {
            offset: 0,
            length: 0,
            data: Vec::new(),
        });
        test_type_traits_non_clonable(DefineSymbolError::UnknownName);
    }
}
