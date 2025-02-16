//! Provides the [`Scanner`] object used to scan bytes against a set of compiled rules.
use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

use crate::bytes_pool::{BytesPool, BytesSymbol, StringSymbol};
use crate::compiler::external_symbol::{ExternalSymbol, ExternalValue};
use crate::compiler::rule::Rule;
use crate::compiler::variable::Variable;
use crate::evaluator::{self, evaluate_rule, EvalError};
use crate::memory::{FragmentedMemory, Memory, Region};
use crate::module::{Module, ModuleData, ModuleUserData};
use crate::timeout::TimeoutChecker;
use crate::{statistics, Compiler, Metadata};

pub use crate::evaluator::variable::StringMatch;

mod ac_scan;
mod error;
pub use error::ScanError;
mod params;
pub use params::{FragmentedScanMode, ScanParams};

#[cfg(feature = "process")]
mod process;

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
/// let scan_result = scanner.scan_mem(b"abc").unwrap();
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
///         let res = scanner.scan_mem(b"").unwrap();
///         assert!(res.matched_rules.is_empty());
///     })
/// };
/// let thread2 = {
///     let mut scanner = scanner.clone();
///     std::thread::spawn(move || {
///          scanner.define_symbol("extension", "pdf");
///          let res = scanner.scan_mem(b"").unwrap();
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
    external_symbols_values: Vec<ExternalValue>,

    /// User data associated to specific modules.
    ///
    /// See [`crate::module::ModuleData`] for more details on how this parameter is used.
    module_user_data: ModuleUserData,
}

impl Scanner {
    pub(crate) fn new(compiler: Compiler) -> Self {
        let Compiler {
            rules,
            global_rules,
            variables,
            namespaces,
            imported_modules,
            external_symbols,
            bytes_pool,
            profile,
            ..
        } = compiler;
        let namespaces = namespaces.into_iter().map(|v| v.name).collect();

        let ac_scan = ac_scan::AcScan::new(&variables, profile);

        let mut external_symbols_values = Vec::new();
        let mut external_symbols_map = HashMap::new();
        for (index, sym) in external_symbols.into_iter().enumerate() {
            let ExternalSymbol {
                name,
                default_value,
            } = sym;
            external_symbols_values.push(default_value);
            _ = external_symbols_map.insert(name, index);
        }

        Self {
            inner: Arc::new(Inner {
                rules,
                global_rules,
                variables,
                ac_scan,
                modules: imported_modules,
                external_symbols_map,
                namespaces,
                bytes_pool: bytes_pool.into_pool(),
            }),
            scan_params: ScanParams::default(),
            external_symbols_values,
            module_user_data: ModuleUserData::default(),
        }
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given byte slice.
    ///
    /// # Errors
    ///
    /// Can fail if a timeout has been configured and is reached during the scan. Since results
    /// can still have been partially computed, results are returned with the error.
    pub fn scan_mem<'scanner>(
        &'scanner self,
        mem: &[u8],
    ) -> Result<ScanResult<'scanner>, (ScanError, ScanResult<'scanner>)> {
        self.inner.scan(
            Memory::Direct(mem),
            &self.scan_params,
            &self.external_symbols_values,
            &self.module_user_data,
        )
    }

    /// Scan a file.
    ///
    /// Returns a list of rules that matched the given file.
    ///
    /// # Errors
    ///
    /// Fails if the file at the given path cannot be read, or if a timeout has been configured
    /// and is reached during the scan. Since results can still have been partially computed,
    /// results are returned with the error.
    pub fn scan_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<ScanResult, (ScanError, ScanResult)> {
        match std::fs::read(path.as_ref()) {
            Ok(contents) => self.scan_mem(&contents),
            Err(err) => Err((ScanError::CannotReadFile(err), ScanResult::default())),
        }
    }

    /// Scan a file using memmap to read from it.
    ///
    /// Returns a list of rules that matched the given file.
    ///
    /// # Errors
    ///
    /// Fails if the file at the given path cannot be opened or memory mapped, or if a timeout
    /// has been configured and is reached during the scan. Since results can still have been
    /// partially computed, results are returned with the error.
    ///
    /// # Safety
    ///
    /// See the safety documentation of [`memmap2::Mmap`]. It is unsafe to use this
    /// method as the behavior is undefined if the underlying file is modified while the map
    /// is still alive. For example, shrinking the underlying file can and will cause issues
    /// in this process: on Linux, a SIGBUS can be emitted, while on Windows, a structured
    /// exception can be raised.
    #[cfg(feature = "memmap")]
    pub unsafe fn scan_file_memmap<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<ScanResult, (ScanError, ScanResult)> {
        match std::fs::File::open(path.as_ref()).and_then(|file| {
            // Safety: guaranteed by the safety contract of this function
            unsafe { memmap2::Mmap::map(&file) }
        }) {
            Ok(mmap) => self.scan_mem(&mmap),
            Err(err) => Err((ScanError::CannotReadFile(err), ScanResult::default())),
        }
    }

    /// Scan the memory of a running process.
    ///
    /// Scan the memory regions of the process. By default, the behavior from libyara
    /// is kept, but this may not match exactly what is desired. For more details on
    /// the exact semantics of the scan, and how to adjust them, see
    /// [`ScanParams::fragmented_scan_mode`].
    ///
    /// Each memory region will by default be fetched entirely to be scanned. This can
    /// greatly increase memory usage during the scan. It can be a good idea to split
    /// those regions in chunks to bound this memory usage, which can be done using
    /// [`ScanParams::memory_chunk_size`].
    ///
    /// For greater control over which memory regions are scanned, the
    /// [`Scanner::scan_fragmented`] API can also be used, but the iterator over
    /// the memory region will need to be implemented manually. You will also need
    /// to set the [`ScanParams::process_memory`] flag to ensure the file-analysis
    /// modules keep their behavior.
    ///
    /// # Errors
    ///
    /// Fails if the process cannot be opened or its memory cannot be listed.
    /// Should fetches from some memory regions of the process fail, those regions will not be
    /// scanned, but the scan will keep going.
    #[cfg(feature = "process")]
    pub fn scan_process(&self, pid: u32) -> Result<ScanResult, (ScanError, ScanResult)> {
        match process::process_memory(pid) {
            Ok(memory) => self.inner.scan(
                Memory::new_fragmented(memory, self.scan_params.to_memory_params()),
                &self.scan_params,
                &self.external_symbols_values,
                &self.module_user_data,
            ),
            Err(err) => Err((err, ScanResult::default())),
        }
    }

    /// Scan fragmented memory, i.e. multiple byte slices, potentially disjointed.
    ///
    /// This API allows scanning a set of non-overlapping byte slices, instead
    /// of a single contiguous one.
    ///
    /// This is for example how process memory scanning works, as the memory of a
    /// process is a set of memory regions that are often non contiguous.
    ///
    /// For the exact semantics of this API, and how to adjust them, see
    /// [`ScanParams::fragmented_scan_mode`].
    ///
    /// If the fragmented memory belongs to a process, you probably want to
    /// set the [`ScanParams::process_memory`] flag. This is used by
    /// file-analysis modules to modify how they generate data from this
    /// memory.
    ///
    /// # Errors
    ///
    /// Fails if the process cannot be opened or its memory cannot be listed.
    /// Should fetches from some memory regions of the process fail, those regions will not be
    /// scanned, but the scan will keep going.
    pub fn scan_fragmented<T>(&self, obj: T) -> Result<ScanResult, (ScanError, ScanResult)>
    where
        T: FragmentedMemory,
    {
        self.inner.scan(
            Memory::new_fragmented(Box::new(obj), self.scan_params.to_memory_params()),
            &self.scan_params,
            &self.external_symbols_values,
            &self.module_user_data,
        )
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
                (ExternalValue::Boolean(a), ExternalValue::Boolean(b)) => *a = b,
                (ExternalValue::Integer(a), ExternalValue::Integer(b)) => *a = b,
                (ExternalValue::Float(a), ExternalValue::Float(b)) => *a = b,
                (ExternalValue::Bytes(a), ExternalValue::Bytes(b)) => *a = b,
                _ => return Err(DefineSymbolError::InvalidType),
            }
        }

        Ok(())
    }

    /// Set the data to be used by a module.
    ///
    /// Some module need external data to be provided. This is for example the case for the
    /// cuckoo module, which needs to be given the cuckoo report.
    pub fn set_module_data<Module>(&mut self, data: Module::UserData)
    where
        Module: ModuleData + 'static,
    {
        let _r = self
            .module_user_data
            .0
            .insert(TypeId::of::<Module>(), Arc::new(data));
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

    /// Get the value of a bytes symbol.
    #[must_use]
    pub fn get_bytes_symbol(&self, symbol: BytesSymbol) -> &[u8] {
        self.inner.bytes_pool.get(symbol)
    }

    /// Get the value of a string symbol.
    #[must_use]
    pub fn get_string_symbol(&self, symbol: StringSymbol) -> &str {
        self.inner.bytes_pool.get_str(symbol)
    }

    /// List rules contained in this scanner.
    #[must_use]
    pub fn rules(&self) -> RulesIter {
        RulesIter {
            global_rules: self.inner.global_rules.iter(),
            rules: self.inner.rules.iter(),
            namespaces: &self.inner.namespaces,
        }
    }
}

/// Iterator on the rules of a scanner.
#[derive(Debug)]
pub struct RulesIter<'scanner> {
    global_rules: std::slice::Iter<'scanner, Rule>,
    rules: std::slice::Iter<'scanner, Rule>,
    namespaces: &'scanner [Option<String>],
}

impl<'scanner> Iterator for RulesIter<'scanner> {
    type Item = RuleDetails<'scanner>;

    fn next(&mut self) -> Option<Self::Item> {
        let (rule, is_global) = match self.global_rules.next() {
            Some(rule) => (rule, true),
            None => (self.rules.next()?, false),
        };

        Some(RuleDetails {
            name: &rule.name,
            namespace: self
                .namespaces
                .get(rule.namespace_index)
                .and_then(|v| v.as_deref()),
            tags: &rule.tags,
            metadatas: &rule.metadatas,
            is_global,
            is_private: rule.is_private,
        })
    }
}

/// Details on a rule contained in a scanner
#[derive(Debug)]
#[non_exhaustive]
pub struct RuleDetails<'scanner> {
    /// Name of the rule.
    pub name: &'scanner str,

    /// Namespace containing the rule. None if in the default namespace.
    pub namespace: Option<&'scanner str>,

    /// Tags associated with the rule.
    pub tags: &'scanner [String],

    /// Metadata associated with the rule.
    pub metadatas: &'scanner [Metadata],

    /// Is the rule global
    pub is_global: bool,

    /// Is the rule private
    pub is_private: bool,
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
    ac_scan: ac_scan::AcScan,

    /// List of modules used during scanning.
    modules: Vec<Box<dyn Module>>,

    /// Mapping from names to index for external symbols.
    external_symbols_map: HashMap<String, usize>,

    /// Namespaces names.
    ///
    /// None is used for the default namespace.
    namespaces: Vec<Option<String>>,

    /// Bytes intern pool.
    bytes_pool: BytesPool,
}

impl Inner {
    fn scan<'scanner>(
        &'scanner self,
        mem: Memory,
        params: &'scanner ScanParams,
        external_symbols_values: &'scanner [ExternalValue],
        module_user_data: &'scanner ModuleUserData,
    ) -> Result<ScanResult<'scanner>, (ScanError, ScanResult<'scanner>)> {
        let mut scan_data = ScanData {
            mem,
            external_symbols_values,
            matched_rules: Vec::new(),
            module_values: evaluator::module::EvalData::new(&self.modules, module_user_data),
            statistics: if params.compute_statistics {
                Some(statistics::Evaluation::default())
            } else {
                None
            },
            timeout_checker: params.timeout_duration.map(TimeoutChecker::new),
            params,
            #[cfg(feature = "object")]
            entrypoint: None,
        };

        let res = self.do_scan(&mut scan_data);
        let results = ScanResult {
            matched_rules: scan_data.matched_rules,
            module_values: scan_data.module_values.values,
            statistics: scan_data.statistics.map(Box::new),
        };

        match res {
            Ok(()) => Ok(results),
            Err(err) => Err((err, results)),
        }
    }

    fn do_scan<'scanner>(
        &'scanner self,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), ScanError> {
        if let Some(mem) = scan_data.mem.get_direct() {
            // We can evaluate module values and then try to evaluate rules without matches.
            scan_data.module_values.scan_region(
                &Region { start: 0, mem },
                &self.modules,
                scan_data.params.process_memory,
            );
        }

        if can_use_no_scan_optimization(scan_data) {
            #[cfg(feature = "profiling")]
            let start = std::time::Instant::now();

            let res = self.evaluate_without_matches(scan_data);

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.no_scan_eval_duration = start.elapsed();
            }

            match res {
                Ok(()) => return Ok(()),
                Err(EvalError::Timeout) => return Err(ScanError::Timeout),
                Err(EvalError::Undecidable) => {
                    // Reset the rules that might have matched already.
                    scan_data.matched_rules.clear();
                }
            }
        }

        // First, run the regex set on the memory. This does a single pass on it, finding out
        // which variables have no miss at all.
        let var_matches = self.do_memory_scan(scan_data)?;

        let mut eval_ctx =
            EvalContext::new(Some(var_matches), self.rules.len(), self.namespaces.len());

        #[cfg(feature = "profiling")]
        let start = std::time::Instant::now();

        // First, evaluate global rules.
        for rule in &self.global_rules {
            match eval_ctx.eval_global_rule(self, rule, scan_data) {
                Ok(()) => (),
                Err(EvalError::Undecidable) => unreachable!(),
                Err(EvalError::Timeout) => return Err(ScanError::Timeout),
            }
        }

        // If all namespaces are disabled, there is no need to do any further work.
        if eval_ctx.namespace_disabled.iter().all(|v| *v) {
            scan_data.matched_rules.clear();
            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.rules_eval_duration = start.elapsed();
            }
            return Ok(());
        }

        // Evaluate all non global rules.
        for rule in &self.rules {
            match eval_ctx.eval_non_global_rule(self, rule, scan_data) {
                Ok(()) => (),
                Err(EvalError::Undecidable) => unreachable!(),
                Err(EvalError::Timeout) => return Err(ScanError::Timeout),
            }
        }

        #[cfg(feature = "profiling")]
        if let Some(stats) = scan_data.statistics.as_mut() {
            stats.rules_eval_duration = start.elapsed();
        }
        Ok(())
    }

    /// Evaluate all rules without availability of the variables' matches.
    ///
    /// This returns None if variables' matches must be computed, otherwise it returns the
    /// final result of the scan.
    fn evaluate_without_matches<'scanner>(
        &'scanner self,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), EvalError> {
        let mut eval_ctx = EvalContext::new(None, self.rules.len(), self.namespaces.len());

        // First, check global rules
        let mut has_unknown_globals = false;
        for rule in &self.global_rules {
            match eval_ctx.eval_global_rule(self, rule, scan_data) {
                Ok(()) => (),
                // Do not rethrow immediately, so that if one of the globals is false, it is
                // detected.
                Err(EvalError::Undecidable) => has_unknown_globals = true,
                Err(EvalError::Timeout) => return Err(EvalError::Timeout),
            }
        }
        if eval_ctx.namespace_disabled.iter().all(|v| *v) {
            // Reset the rules that might have matched already.
            scan_data.matched_rules.clear();
            return Ok(());
        }
        if has_unknown_globals {
            return Err(EvalError::Undecidable);
        }

        // Then, if all global rules matched, the normal rules
        for rule in &self.rules {
            eval_ctx.eval_non_global_rule(self, rule, scan_data)?;
        }

        Ok(())
    }

    fn do_memory_scan(&self, scan_data: &mut ScanData) -> Result<Vec<Vec<StringMatch>>, ScanError> {
        let mut matches = vec![Vec::new(); self.variables.len()];

        #[cfg(feature = "profiling")]
        let start = std::time::Instant::now();

        let mut ac_scan_data = ac_scan::ScanData {
            timeout_checker: scan_data.timeout_checker.as_mut(),
            #[cfg(feature = "profiling")]
            statistics: scan_data.statistics.as_mut(),
            variables: &self.variables,
            params: scan_data.params,
        };
        match &mut scan_data.mem {
            Memory::Direct(mem) => {
                // Scan the memory for all variables occurences.
                self.ac_scan.scan_region(
                    &Region { start: 0, mem },
                    &mut ac_scan_data,
                    &mut matches,
                )?;
            }
            Memory::Fragmented(fragmented) => {
                // Scan each region for all variables occurences.
                while fragmented.obj.next(&fragmented.params).is_some() {
                    #[cfg(feature = "profiling")]
                    let start_fetch = std::time::Instant::now();

                    let Some(region) = fragmented.obj.fetch(&fragmented.params) else {
                        continue;
                    };

                    #[cfg(feature = "profiling")]
                    if let Some(stats) = ac_scan_data.statistics.as_mut() {
                        stats.fetch_memory_duration += start_fetch.elapsed();
                    }

                    self.ac_scan
                        .scan_region(&region, &mut ac_scan_data, &mut matches)?;

                    // Also, compute the value for the entrypoint expression. Since
                    // we fetch each region here, this is much cheaper that refetching
                    // them later on when evaluating the expression.
                    #[cfg(feature = "object")]
                    if scan_data.entrypoint.is_none() {
                        scan_data.entrypoint = evaluator::entrypoint::get_pe_or_elf_entry_point(
                            region.mem,
                            scan_data.params.process_memory,
                        )
                        .and_then(|ep| {
                            let start = u64::try_from(region.start).ok()?;
                            ep.checked_add(start)
                        });
                    }

                    if scan_data.params.fragmented_scan_mode.modules_dynamic_values {
                        // And finally, evaluate the module values on each region.
                        scan_data.module_values.scan_region(
                            &region,
                            &self.modules,
                            scan_data.params.process_memory,
                        );
                    }
                }
            }
        }

        #[cfg(feature = "profiling")]
        if let Some(stats) = scan_data.statistics.as_mut() {
            stats.ac_duration = start.elapsed();
        }

        Ok(matches)
    }
}

/// Context used when evaluating all the rules.
///
/// This struct is used to hold all the data that needs to be updated
/// on every rule evaluation.
struct EvalContext {
    /// Variable matches. None if evaluation is done previous the scan is done.
    var_matches: Option<std::vec::IntoIter<Vec<StringMatch>>>,

    /// Current index into the variables list.
    var_index: usize,

    /// Results of "previous" rules.
    ///
    /// This is filled while iterating on rules and used when rules refer to the
    /// result of previous rules.
    previous_results: Vec<bool>,

    /// Is a namespace "disabled" or not.
    ///
    /// A namespace is disabled when it contains a global rule that is false.
    namespace_disabled: Vec<bool>,
}

impl EvalContext {
    fn new(
        var_matches: Option<Vec<Vec<StringMatch>>>,
        nb_rules: usize,
        nb_namespaces: usize,
    ) -> Self {
        Self {
            var_matches: var_matches.map(Vec::into_iter),
            var_index: 0,
            previous_results: Vec::with_capacity(nb_rules),
            namespace_disabled: vec![false; nb_namespaces],
        }
    }

    fn eval_global_rule<'scanner>(
        &mut self,
        scanner: &'scanner Inner,
        rule: &'scanner Rule,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), EvalError> {
        let res = self.eval_rule_inner(scanner, rule, scan_data)?;
        if !res {
            self.namespace_disabled[rule.namespace_index] = true;
        }
        Ok(())
    }

    fn eval_non_global_rule<'scanner>(
        &mut self,
        scanner: &'scanner Inner,
        rule: &'scanner Rule,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), EvalError> {
        let res = self.eval_rule_inner(scanner, rule, scan_data)?;
        self.previous_results.push(res);
        Ok(())
    }

    fn eval_rule_inner<'scanner>(
        &mut self,
        scanner: &'scanner Inner,
        rule: &'scanner Rule,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<bool, EvalError> {
        let var_matches: Option<Vec<_>> = self
            .var_matches
            .as_mut()
            .map(|matches| matches.take(rule.nb_variables).collect());
        let vars = &scanner.variables[self.var_index..(self.var_index + rule.nb_variables)];
        self.var_index += rule.nb_variables;

        if self.namespace_disabled[rule.namespace_index] {
            return Ok(false);
        }

        let res = evaluate_rule(
            rule,
            var_matches.as_deref(),
            &self.previous_results,
            &scanner.bytes_pool,
            scan_data,
        )?;

        if res && !rule.is_private {
            scan_data.matched_rules.push(build_matched_rule(
                rule,
                vars,
                &scanner.namespaces,
                var_matches.unwrap_or_default(),
            ));
        }

        Ok(res)
    }
}

fn can_use_no_scan_optimization(scan_data: &ScanData) -> bool {
    if scan_data.params.compute_full_matches {
        return false;
    }

    scan_data.mem.get_direct().is_some()
        || (!scan_data.params.fragmented_scan_mode.modules_dynamic_values
            && !scan_data.params.fragmented_scan_mode.can_refetch_regions)
}

#[derive(Debug)]
pub(crate) struct ScanData<'scanner, 'mem> {
    /// Memory to scan,
    pub(crate) mem: Memory<'mem>,

    /// Values of external symbols.
    pub(crate) external_symbols_values: &'scanner [ExternalValue],

    /// List of rules that matched.
    pub(crate) matched_rules: Vec<MatchedRule<'scanner>>,

    /// On-scan values of all modules used in the scanner.
    ///
    /// First element is the module name, second one is the dynamic values produced by the module.
    pub(crate) module_values: evaluator::module::EvalData<'scanner>,

    /// Statistics related to the scanning.
    pub(crate) statistics: Option<statistics::Evaluation>,

    /// Object used to check if the scan times out.
    pub(crate) timeout_checker: Option<TimeoutChecker>,

    /// Parameters linked to the scan.
    pub(crate) params: &'scanner ScanParams,

    /// Entrypoint value for the deprecated `entrypoint` expression.
    ///
    /// This is only set and computed ahead of time if scanning fragmented
    /// memory (such as a process memory). This is because this relies on
    /// parsing each region, and would thus be prohibitively expensive to
    /// compute on demand.
    /// However, when scanning direct memory (such as a file), this is
    /// unset and to be computed on demand, so as to not incur the
    /// cost of this computation on rules that do not use it.
    #[cfg(feature = "object")]
    pub(crate) entrypoint: Option<u64>,
}

impl ScanData<'_, '_> {
    pub(crate) fn check_timeout(&mut self) -> bool {
        self.timeout_checker
            .as_mut()
            .is_some_and(TimeoutChecker::check_timeout)
    }
}

fn build_matched_rule<'a>(
    rule: &'a Rule,
    variables: &'a [Variable],
    namespaces_names: &'a [Option<String>],
    var_matches: Vec<Vec<StringMatch>>,
) -> MatchedRule<'a> {
    MatchedRule {
        name: &rule.name,
        namespace: namespaces_names
            .get(rule.namespace_index)
            .and_then(|v| v.as_deref()),
        tags: &rule.tags,
        metadatas: &rule.metadatas,
        matches: var_matches
            .into_iter()
            .zip(variables.iter())
            .filter(|(_, var)| !var.is_private)
            .filter(|(matches, _)| !matches.is_empty())
            .map(|(matches, var)| StringMatches {
                name: &var.name,
                matches,
            })
            .collect(),
    }
}

/// Result of a scan
#[derive(Debug, Default)]
pub struct ScanResult<'scanner> {
    /// List of rules that matched.
    pub matched_rules: Vec<MatchedRule<'scanner>>,

    /// On-scan values of all modules used in the scanner.
    ///
    /// First element is the module name, second one is the dynamic values produced by the module.
    pub module_values: Vec<(&'static str, crate::module::Value)>,

    /// Statistics related to the scan.
    // This is boxed to reduce the size of the struct, especially as this field
    // is pratically never set outside of test/debug runs.
    pub statistics: Option<Box<statistics::Evaluation>>,
}

/// Description of a rule that matched during a scan.
#[derive(Debug)]
pub struct MatchedRule<'scanner> {
    /// Name of the rule.
    pub name: &'scanner str,

    /// Namespace containing the rule. None if in the default namespace.
    pub namespace: Option<&'scanner str>,

    /// Tags associated with the rule.
    pub tags: &'scanner [String],

    /// Metadata associated with the rule.
    pub metadatas: &'scanner [Metadata],

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
    use crate::compiler::CompilerBuilder;
    use crate::module::{EvalContext, ScanContext, StaticValue, Type, Value as ModuleValue};
    use crate::test_helpers::{
        test_type_traits, test_type_traits_non_clonable, test_type_unwind_safe,
    };

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

        fn get_dynamic_values(
            &self,
            _: &mut ScanContext,
            out: &mut HashMap<&'static str, ModuleValue>,
        ) {
            out.extend([
                ("array", ModuleValue::Array(vec![ModuleValue::Integer(3)])),
                (
                    "dict",
                    ModuleValue::Dictionary([(b"a".to_vec(), ModuleValue::Integer(3))].into()),
                ),
            ]);
        }
    }

    impl Test {
        fn to_bytes(_ctx: &mut EvalContext, args: Vec<ModuleValue>) -> Option<ModuleValue> {
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
                condition: {cond}
            }}
        "#
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
                    {cond}
            }}
        "#
        )
    }

    #[track_caller]
    fn test_eval_with_poison(rule_str: &str, mem: &[u8], expected: Option<bool>) {
        let mut compiler = CompilerBuilder::default().add_module(Test).build();
        let _r = compiler.add_rules_str(rule_str).unwrap();
        let scanner = compiler.into_scanner();

        let user_data = ModuleUserData::default();
        let mut module_values =
            evaluator::module::EvalData::new(&scanner.inner.modules, &user_data);
        module_values.scan_region(&Region { start: 0, mem }, &scanner.inner.modules, false);

        let mut scan_data = ScanData {
            mem: Memory::Direct(mem),
            external_symbols_values: &[],
            matched_rules: Vec::new(),
            module_values,
            statistics: None,
            timeout_checker: None,
            params: &ScanParams::default(),
            #[cfg(feature = "object")]
            entrypoint: None,
        };
        let mut previous_results = Vec::new();
        let rules = &scanner.inner.rules;
        for rule in &rules[..(rules.len() - 1)] {
            previous_results.push(
                evaluate_rule(
                    rule,
                    None,
                    &previous_results,
                    &scanner.inner.bytes_pool,
                    &mut scan_data,
                )
                .unwrap(),
            );
        }
        let last_res = evaluate_rule(
            &rules[rules.len() - 1],
            None,
            &previous_results,
            &scanner.inner.bytes_pool,
            &mut scan_data,
        );

        assert_eq!(last_res.ok(), expected);
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
            &empty_rule(r"test.to_bytes(entrypoint) matches /a/"),
            b"",
            Some(false),
        );
        test_eval_with_poison(
            &single_var_rule(r"test.to_bytes(#a) matches /a/"),
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
        test_type_traits(Scanner::new(Compiler::new()));
        test_type_unwind_safe::<Scanner>();

        test_type_traits_non_clonable(ScanResult {
            matched_rules: Vec::new(),
            module_values: Vec::new(),
            statistics: None,
        });
        test_type_traits_non_clonable(MatchedRule {
            name: "a",
            namespace: None,
            tags: &[],
            metadatas: &[],
            matches: Vec::new(),
        });
        test_type_traits_non_clonable(StringMatches {
            name: "a",
            matches: Vec::new(),
        });
        test_type_traits_non_clonable(DefineSymbolError::UnknownName);
        test_type_traits_non_clonable(ScanData {
            mem: Memory::Direct(b""),
            external_symbols_values: &[],
            matched_rules: Vec::new(),
            module_values: evaluator::module::EvalData {
                values: Vec::new(),
                data_map: crate::module::ModuleDataMap::new(&ModuleUserData::default()),
            },
            statistics: None,
            timeout_checker: None,
            #[cfg(feature = "object")]
            entrypoint: None,
            params: &ScanParams::default(),
        });
        test_type_traits_non_clonable(RulesIter {
            global_rules: [].iter(),
            rules: [].iter(),
            namespaces: &[],
        });
        test_type_traits_non_clonable(RuleDetails {
            name: "",
            namespace: None,
            tags: &[],
            metadatas: &[],
            is_global: false,
            is_private: false,
        });
    }
}
