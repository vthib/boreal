//! Provides the [`Scanner`] object used to scan bytes against a set of compiled rules.
use std::any::TypeId;
use std::collections::{HashMap, HashSet};
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

pub use crate::evaluator::module::EvaluatedModule;
pub use crate::evaluator::variable::StringMatch;

mod ac_scan;
mod error;
pub use error::ScanError;
mod params;
pub use params::{CallbackEvents, FragmentedScanMode, ScanParams};
#[cfg(feature = "serialize")]
pub use wire::DeserializeParams;

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
/// let scanner = compiler.finalize();
///
/// // Use the scanner to run the rules against byte strings or files.
/// let scan_result = scanner.scan_mem(b"abc").unwrap();
/// assert_eq!(scan_result.rules.len(), 1);
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
/// let scanner = compiler.finalize();
///
/// let thread1 = {
///     let mut scanner = scanner.clone();
///     std::thread::spawn(move || {
///         scanner.define_symbol("extension", "exe");
///         let res = scanner.scan_mem(b"").unwrap();
///         assert!(res.rules.is_empty());
///     })
/// };
/// let thread2 = {
///     let mut scanner = scanner.clone();
///     std::thread::spawn(move || {
///          scanner.define_symbol("extension", "pdf");
///          let res = scanner.scan_mem(b"").unwrap();
///          assert_eq!(res.rules.len(), 1);
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

/// Events occurring during a scan that can be received in a callback.
///
/// Which events are used depend on the [`ScanParams::callback_events`] setting. By default,
/// only [`ScanEvent::RuleMatch`] are reported.
///
/// This enum is on purpose non exhaustive to allow adding events to it without breaking
/// compatibility. It is recommended to always return Continue on unknown events.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScanEvent<'scanner, 'a> {
    /// A rule has been matched.
    ///
    /// The [`CallbackEvents::RULE_MATCH`] bitflag must be set to receive this event,
    /// which it is by default.
    RuleMatch(EvaluatedRule<'scanner>),

    /// A rule has not been matched.
    ///
    /// It is not recommended to set this flag as it can slow down the scan considerably.
    ///
    /// The [`CallbackEvents::RULE_NO_MATCH`] bitflag must be set to receive this event.
    RuleNoMatch(EvaluatedRule<'scanner>),

    /// A module has been imported.
    ///
    /// The [`CallbackEvents::MODULE_IMPORT`] bitflag must be set to receive this event.
    ModuleImport(&'a EvaluatedModule<'scanner>),

    /// List scan statistics once the scan is finished.
    ///
    /// The [`CallbackEvents::SCAN_STATISTICS`] bitflag must be set to receive this event.
    /// The [`ScanParams::compute_statistics`] parameter must also have been set to true, and
    /// the `profiling` feature must have been enabled during compilation.
    ///
    /// Note that this event, if enabled, will always be passed to the callback, even if
    /// the scan is interrupted by an error or if a previous callback call has returned
    /// [`ScanCallbackResult::Abort`].
    ///
    /// Additionally, the return value of the callback for this event is ignored.
    ScanStatistics(statistics::Evaluation),

    /// A string has reached the match limit.
    ///
    /// The [`CallbackEvents::STRING_REACHED_MATCH_LIMIT`] bitflag must be set
    /// to receive this event.
    StringReachedMatchLimit(StringIdentifier<'scanner>),
}

/// Details of a string, which can be used to uniquely identify it.
#[derive(Debug)]
#[non_exhaustive]
pub struct StringIdentifier<'scanner> {
    /// Namespace of the rule containing the string.
    pub rule_namespace: &'scanner str,

    /// Name of the rule containing the string.
    pub rule_name: &'scanner str,

    /// Name of the string.
    pub string_name: &'scanner str,

    /// Declaration index of the string in the rule.
    ///
    /// Since strings can be anonymous, this can be used to find the
    /// right string.
    pub string_index: usize,
}

/// List of result statuses that a scan callback can return.
#[derive(Debug)]
pub enum ScanCallbackResult {
    /// Continue with the scan.
    Continue,
    /// Abort the scan immediately.
    ///
    /// The scan will end with the [`ScanError::CallbackAbort`] error.
    Abort,
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
                #[cfg(feature = "serialize")]
                profile,
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

    /// Scan a byte slice, getting results through a callback.
    ///
    /// Use a callback to be notified of events, for example when a rule is matched.
    ///
    /// This has several differences on the regular [`Scanner::scan_mem`] method:
    ///
    /// - Instead of accumulating all matched rules to be returned at the end of the
    ///   scan, the callback is called when each rule matches, and can decide whether
    ///   to accumulate those results or not.
    /// - The callback can stop the scan on any event.
    /// - The callback can be called on more events than only on rule match. See
    ///   [`ScanEvent`] for a complete list.
    ///
    /// # Errors
    ///
    /// Can fail if a timeout has been configured and is reached during the scan,
    /// or if the callback aborts the scan.
    pub fn scan_mem_with_callback<'scanner, 'cb, F>(
        &'scanner self,
        mem: &[u8],
        callback: F,
    ) -> Result<(), ScanError>
    where
        F: for<'a> FnMut(ScanEvent<'scanner, 'a>) -> ScanCallbackResult + Send + Sync + 'cb,
    {
        self.inner.scan_with_callback(
            Memory::Direct(mem),
            &self.scan_params,
            &self.external_symbols_values,
            &self.module_user_data,
            Box::new(callback),
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

    /// Scan a file, getting results through a callback.
    ///
    /// See [`Scanner::scan_mem_with_callback`] for more details on the callback based
    /// API.
    ///
    /// # Errors
    ///
    /// Can fail if a timeout has been configured and is reached during the scan.
    pub fn scan_file_with_callback<'scanner, 'cb, P, F>(
        &'scanner self,
        path: P,
        callback: F,
    ) -> Result<(), ScanError>
    where
        P: AsRef<std::path::Path>,
        F: for<'a> FnMut(ScanEvent<'scanner, 'a>) -> ScanCallbackResult + Send + Sync + 'cb,
    {
        match std::fs::read(path.as_ref()) {
            Ok(contents) => self.scan_mem_with_callback(&contents, callback),
            Err(err) => Err(ScanError::CannotReadFile(err)),
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

    /// Scan a file using memmap to read from it, getting results through a callback.
    ///
    /// See [`Scanner::scan_mem_with_callback`] for more details on the callback based
    /// API.
    ///
    /// # Errors
    ///
    /// See [`Scanner::scan_file_memmap`] for error documentation. The scan can also fail
    /// if the callback aborts it.
    ///
    /// # Safety
    ///
    /// See the safety documentation of [`Scanner::scan_file_memmap`].
    #[cfg(feature = "memmap")]
    pub unsafe fn scan_file_memmap_with_callback<'scanner, 'cb, P, F>(
        &'scanner self,
        path: P,
        callback: F,
    ) -> Result<(), ScanError>
    where
        P: AsRef<std::path::Path>,
        F: for<'a> FnMut(ScanEvent<'scanner, 'a>) -> ScanCallbackResult + Send + Sync + 'cb,
    {
        match std::fs::File::open(path.as_ref()).and_then(|file| {
            // Safety: guaranteed by the safety contract of this function
            unsafe { memmap2::Mmap::map(&file) }
        }) {
            Ok(mmap) => self.scan_mem_with_callback(&mmap, callback),
            Err(err) => Err(ScanError::CannotReadFile(err)),
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

    /// Scan the memory of a running process, getting results through a callback.
    ///
    /// See [`Scanner::scan_mem_with_callback`] for more details on the callback based
    /// API.
    ///
    /// # Errors
    ///
    /// See [`Scanner::scan_process`] for error documentation. The scan can also fail
    /// if the callback aborts it.
    #[cfg(feature = "process")]
    pub fn scan_process_with_callback<'scanner, 'cb, F>(
        &'scanner self,
        pid: u32,
        callback: F,
    ) -> Result<(), ScanError>
    where
        F: for<'a> FnMut(ScanEvent<'scanner, 'a>) -> ScanCallbackResult + Send + Sync + 'cb,
    {
        let memory = process::process_memory(pid)?;

        self.inner.scan_with_callback(
            Memory::new_fragmented(memory, self.scan_params.to_memory_params()),
            &self.scan_params,
            &self.external_symbols_values,
            &self.module_user_data,
            Box::new(callback),
        )
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

    /// Scan fragmented memory, getting results through a callback.
    ///
    /// See [`Scanner::scan_mem_with_callback`] for more details on the callback based
    /// API.
    ///
    /// # Errors
    ///
    /// See [`Scanner::scan_fragmented`] for error documentation. The scan can also fail
    /// if the callback aborts it.
    pub fn scan_fragmented_with_callback<'scanner, 'cb, T, F>(
        &'scanner self,
        obj: T,
        callback: F,
    ) -> Result<(), ScanError>
    where
        T: FragmentedMemory,
        F: for<'a> FnMut(ScanEvent<'scanner, 'a>) -> ScanCallbackResult + Send + Sync + 'cb,
    {
        self.inner.scan_with_callback(
            Memory::new_fragmented(Box::new(obj), self.scan_params.to_memory_params()),
            &self.scan_params,
            &self.external_symbols_values,
            &self.module_user_data,
            Box::new(callback),
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

    /// Serialize the scanner into bytes.
    ///
    /// This method serializes the scanner into a bytestring that can be used
    /// to recreate the scanner through the [`Scanner::from_bytes_unchecked`]
    /// method.
    ///
    /// There are several limitations to this serialization:
    ///
    /// - The scanner cannot be serialized entirely. Notably, several objects
    ///   generated during the compilation of rules cannot be serialized, which
    ///   means they need to be compiled again upon deserialization. This can
    ///   be relatively fast in most cases, but this implies that the
    ///   deserialization of a scanner is not guaranteed to be much faster
    ///   than adding rules and compiling them.
    ///
    /// - The module data set in the scanner through the use of the
    ///   [`Scanner::set_module_data`] method cannot be serialized. Those data
    ///   must be set by hand again after deserialization.
    ///
    /// - Deserialization is only guaranteed to work if the serialization
    ///   was done on the same version of this crate. That is, the serialized
    ///   format does not follow semantic versioning.
    ///
    /// - The serialization format does not include any consistency or full
    ///   validity checks. Deserializing may generate a scanner that can panic
    ///   upon use if the serialized data has been tampered with.
    ///
    /// For all these reasons, it is highly preferable to go through adding
    /// rules in textual format and compiling them to generate a scanner, rather
    /// than using the serialized format. Serialization should only be used
    /// if and only if:
    ///
    /// - The libraries used to serialize and deserialize are guaranteed to be
    ///   at the same version.
    /// - The serialized bytes are wrapped into a system to control those bytes
    ///   are valid and not modified through a data integrity checking setup.
    ///
    /// # Errors
    ///
    /// This function can fail if the provided buffer is too small and cannot
    /// be extended. If a Vec is passed, this cannot happen.
    #[cfg(feature = "serialize")]
    pub fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use crate::wire::Serialize;

        crate::wire::serialize_header(*b"scnr", writer)?;
        self.serialize(writer)?;

        Ok(())
    }

    /// Deserialize a scanner from a bytestring.
    ///
    /// This method allows recreating a [`Scanner`] that was previously serialized
    /// through the [`Scanner::to_bytes`] method.
    ///
    /// Note that this functions trusts the provided buffer was generated from
    /// a call to [`Scanner::to_bytes`] and has not been tampered with. You must
    /// add your own layer of data integrity if this byte string does not come
    /// from a trusted input.
    ///
    /// If the serialized scanner used a custom module or the console module,
    /// those modules must be provided in the `params` parameter.
    ///
    /// See [`Scanner::to_bytes`] documentation for more details on the limits of
    /// this serialization format.
    ///
    /// # Errors
    ///
    /// This function can fail if:
    ///
    /// - the serialization was done in a version that is incompatible with the current one
    /// - the serialized scanner used a module that is not built into this library or
    ///   provided in the `params` object.
    /// - the provided bytes do not deserialize properly into a Scanner object.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut compiler = boreal::Compiler::new();
    /// compiler.add_rules_str("rule a { strings: $a = \"abc\" condition: $a }").unwrap();
    /// let scanner = compiler.finalize();
    ///
    /// let mut buffer = Vec::new();
    /// scanner.to_bytes(&mut buffer).unwrap();
    ///
    /// let params = boreal::scanner::DeserializeParams::default();
    /// let scanner2 = boreal::Scanner::from_bytes_unchecked(&buffer, params).unwrap();
    ///
    /// let scan_result = scanner2.scan_mem(b"abc").unwrap();
    /// assert_eq!(scan_result.rules.len(), 1);
    /// ```
    #[cfg(feature = "serialize")]
    pub fn from_bytes_unchecked(bytes: &[u8], params: DeserializeParams) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        crate::wire::deserialize_header(*b"scnr", &mut cursor)?;
        let this = wire::deserialize_scanner(params, &mut cursor)?;

        Ok(this)
    }
}

/// Iterator on the rules of a scanner.
#[derive(Debug)]
pub struct RulesIter<'scanner> {
    global_rules: std::slice::Iter<'scanner, Rule>,
    rules: std::slice::Iter<'scanner, Rule>,
    namespaces: &'scanner [String],
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
            namespace: self.namespaces[rule.namespace_index].as_ref(),
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

    /// Namespace containing the rule.
    pub namespace: &'scanner str,

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
    namespaces: Vec<String>,

    /// Bytes intern pool.
    bytes_pool: BytesPool,

    /// Profile used to compile the Aho-Corasick
    #[cfg(feature = "serialize")]
    profile: crate::compiler::CompilerProfile,
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
            external_symbols_values,
            rules: Vec::new(),
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
            callback: None,
            string_reached_match_limit: HashSet::new(),
        };

        let res = self.do_scan(mem, &mut scan_data);
        let results = ScanResult {
            rules: scan_data.rules,
            modules: scan_data.module_values.evaluated_modules,
            statistics: scan_data.statistics.map(Box::new),
        };

        match res {
            Ok(()) => Ok(results),
            Err(err) => Err((err, results)),
        }
    }

    fn scan_with_callback<'scanner>(
        &'scanner self,
        mem: Memory<'_>,
        params: &'scanner ScanParams,
        external_symbols_values: &'scanner [ExternalValue],
        module_user_data: &'scanner ModuleUserData,
        callback: ScanCallback<'scanner, '_>,
    ) -> Result<(), ScanError> {
        let mut scan_data = ScanData {
            external_symbols_values,
            rules: Vec::new(),
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
            callback: Some(callback),
            string_reached_match_limit: HashSet::new(),
        };

        let res = self.do_scan(mem, &mut scan_data);

        if (scan_data.params.callback_events & CallbackEvents::SCAN_STATISTICS).0 != 0 {
            if let Some(cb) = &mut scan_data.callback {
                if let Some(stats) = scan_data.statistics {
                    // Ignore the return value for this event, there is no point in aborting
                    // here.
                    let _r = (cb)(ScanEvent::ScanStatistics(stats));
                }
            }
        }

        res
    }

    fn do_scan<'scanner>(
        &'scanner self,
        mut mem: Memory,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), ScanError> {
        if let Some(mem) = mem.get_direct() {
            // We can evaluate module values and then try to evaluate rules without matches.
            scan_data
                .module_values
                .scan_region(&Region { start: 0, mem }, scan_data.params.process_memory);

            scan_data.send_module_import_events_to_cb()?;
        }

        if can_use_no_scan_optimization(&mem, scan_data) {
            #[cfg(feature = "profiling")]
            let start = std::time::Instant::now();

            let res = self.evaluate_without_matches(&mut mem, scan_data);

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.no_scan_eval_duration = start.elapsed();
            }

            match res {
                Ok(()) => {
                    scan_data.handle_already_matched_rules_and_callback()?;
                    return Ok(());
                }
                Err(EvalError::Timeout) => {
                    scan_data.handle_already_matched_rules_and_callback()?;
                    return Err(ScanError::Timeout);
                }
                Err(EvalError::CallbackAbort) => {
                    return Err(ScanError::CallbackAbort);
                }
                Err(EvalError::Undecidable) => {
                    // Reset the rules that might have matched already.
                    // FIXME: those should not be cleared, but kept: there is
                    // no need to reevaluate them.
                    scan_data.rules.clear();
                }
            }
        }

        // First, run the regex set on the memory. This does a single pass on it, finding out
        // which variables have no miss at all.
        let var_matches = self.do_memory_scan(&mut mem, scan_data)?;

        let mut eval_ctx =
            EvalContext::new(Some(var_matches), self.rules.len(), self.namespaces.len());

        #[cfg(feature = "profiling")]
        let start = std::time::Instant::now();

        // First, evaluate global rules.
        for rule in &self.global_rules {
            match eval_ctx.eval_global_rule(self, rule, &mut mem, scan_data) {
                Ok(()) => (),
                Err(EvalError::Undecidable) => unreachable!(),
                Err(EvalError::Timeout) => return Err(ScanError::Timeout),
                Err(EvalError::CallbackAbort) => return Err(ScanError::CallbackAbort),
            }
        }

        // If we include not matched rules, we need to fixup the results of
        // some global rules. For example, if a namespace contains two global
        // rules A and B, with A matching and B not matching, then A must be
        // set to "not matching" since its results are invalidated by B not
        // matching.
        if scan_data.params.include_not_matched_rules {
            for (rule, evaluated_rule) in self.global_rules.iter().zip(scan_data.rules.iter_mut()) {
                if eval_ctx.namespace_disabled[rule.namespace_index] {
                    evaluated_rule.matched = false;
                }
            }
        } else
        // If we only include matched rules and all namespaces are disabled,
        // there is no need to do any further work.
        if eval_ctx.namespace_disabled.iter().all(|v| *v) {
            scan_data.rules.clear();
            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.rules_eval_duration = start.elapsed();
            }
            return Ok(());
        }

        // If there is a callback, we need to call it for every global matched rule.
        // This was delayed since a single global rule non matching would invalidate
        // all the previous ones.
        scan_data.handle_already_matched_rules_and_callback()?;

        // Evaluate all non global rules.
        for rule in &self.rules {
            match eval_ctx.eval_non_global_rule(self, rule, &mut mem, scan_data, true) {
                Ok(()) => (),
                Err(EvalError::Undecidable) => unreachable!(),
                Err(EvalError::Timeout) => return Err(ScanError::Timeout),
                Err(EvalError::CallbackAbort) => return Err(ScanError::CallbackAbort),
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
        mem: &mut Memory,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), EvalError> {
        let mut eval_ctx = EvalContext::new(None, self.rules.len(), self.namespaces.len());

        // First, check global rules
        let mut has_unknown_globals = false;
        for rule in &self.global_rules {
            match eval_ctx.eval_global_rule(self, rule, mem, scan_data) {
                Ok(()) => (),
                // Do not rethrow immediately, so that if one of the globals is false, it is
                // detected.
                Err(EvalError::Undecidable) => has_unknown_globals = true,
                Err(EvalError::Timeout) => return Err(EvalError::Timeout),
                Err(EvalError::CallbackAbort) => return Err(EvalError::CallbackAbort),
            }
        }
        if eval_ctx.namespace_disabled.iter().all(|v| *v) {
            // Reset the rules that might have matched already.
            scan_data.rules.clear();
            return Ok(());
        }
        if has_unknown_globals {
            return Err(EvalError::Undecidable);
        }

        // Then, if all global rules matched, the normal rules
        for rule in &self.rules {
            eval_ctx.eval_non_global_rule(self, rule, mem, scan_data, false)?;
        }

        Ok(())
    }

    fn do_memory_scan<'scanner>(
        &'scanner self,
        mem: &mut Memory,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<Vec<Vec<StringMatch>>, ScanError> {
        let mut matches = vec![Vec::new(); self.variables.len()];

        #[cfg(feature = "profiling")]
        let start = std::time::Instant::now();

        match mem {
            Memory::Direct(mem) => {
                // Scan the memory for all variables occurences.
                self.ac_scan.scan_region(
                    &Region { start: 0, mem },
                    self,
                    scan_data,
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
                    if let Some(stats) = scan_data.statistics.as_mut() {
                        stats.fetch_memory_duration += start_fetch.elapsed();
                    }

                    self.ac_scan
                        .scan_region(&region, self, scan_data, &mut matches)?;

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
                        scan_data
                            .module_values
                            .scan_region(&region, scan_data.params.process_memory);
                    }
                }

                scan_data.send_module_import_events_to_cb()?;
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
        mem: &mut Memory,
        scan_data: &mut ScanData<'scanner, '_>,
    ) -> Result<(), EvalError> {
        let res = self.eval_rule_inner(
            scanner, rule, mem, scan_data,
            // XXX: evaluation of global rules always delay the match rule
            // callback: this is because any non match will invalidate all
            // the previous matches.
            false,
        )?;
        if !res {
            self.namespace_disabled[rule.namespace_index] = true;
        }
        Ok(())
    }

    fn eval_non_global_rule<'scanner>(
        &mut self,
        scanner: &'scanner Inner,
        rule: &'scanner Rule,
        mem: &mut Memory,
        scan_data: &mut ScanData<'scanner, '_>,
        call_callback: bool,
    ) -> Result<(), EvalError> {
        let res = self.eval_rule_inner(scanner, rule, mem, scan_data, call_callback)?;
        self.previous_results.push(res);
        Ok(())
    }

    fn eval_rule_inner<'scanner>(
        &mut self,
        scanner: &'scanner Inner,
        rule: &'scanner Rule,
        mem: &mut Memory,
        scan_data: &mut ScanData<'scanner, '_>,
        call_callback: bool,
    ) -> Result<bool, EvalError> {
        let var_matches: Option<Vec<_>> = self
            .var_matches
            .as_mut()
            .map(|matches| matches.take(rule.nb_variables).collect());
        let vars = &scanner.variables[self.var_index..(self.var_index + rule.nb_variables)];
        self.var_index += rule.nb_variables;

        let matched = if self.namespace_disabled[rule.namespace_index] {
            false
        } else {
            evaluate_rule(
                rule,
                var_matches.as_deref(),
                &self.previous_results,
                &scanner.bytes_pool,
                mem,
                scan_data,
            )?
        };

        if rule.is_private {
            return Ok(matched);
        }

        if matched || scan_data.params.include_not_matched_rules {
            let matched_rule = build_matched_rule(
                rule,
                vars,
                &scanner.namespaces,
                var_matches.unwrap_or_default(),
                matched,
            );
            match &mut scan_data.callback {
                Some(cb) if call_callback => {
                    let mut result = ScanCallbackResult::Continue;
                    if matched
                        && (scan_data.params.callback_events & CallbackEvents::RULE_MATCH).0 != 0
                    {
                        result = (cb)(ScanEvent::RuleMatch(matched_rule));
                    } else if !matched
                        && (scan_data.params.callback_events & CallbackEvents::RULE_NO_MATCH).0 != 0
                    {
                        result = (cb)(ScanEvent::RuleNoMatch(matched_rule));
                    }
                    match result {
                        ScanCallbackResult::Continue => (),
                        ScanCallbackResult::Abort => return Err(EvalError::CallbackAbort),
                    }
                }
                Some(_) | None => scan_data.rules.push(matched_rule),
            }
        }

        Ok(matched)
    }
}

fn can_use_no_scan_optimization(mem: &Memory, scan_data: &ScanData) -> bool {
    if scan_data.params.compute_full_matches {
        return false;
    }
    // Mixing no scan optimization with this parameter is annoying and non
    // trivial. Since this parameter is mainly here for compatibility purposes,
    // lets just avoid making the code more complicated for this particular
    // situation. If there is a real use case for this, it can be revisited.
    if scan_data.params.include_not_matched_rules {
        return false;
    }

    mem.get_direct().is_some()
        || (!scan_data.params.fragmented_scan_mode.modules_dynamic_values
            && !scan_data.params.fragmented_scan_mode.can_refetch_regions)
}

type ScanCallback<'scanner, 'cb> =
    Box<dyn for<'a> FnMut(ScanEvent<'scanner, 'a>) -> ScanCallbackResult + Send + Sync + 'cb>;

pub(crate) struct ScanData<'scanner, 'cb> {
    /// Values of external symbols.
    pub(crate) external_symbols_values: &'scanner [ExternalValue],

    /// List of rules evaluations.
    pub(crate) rules: Vec<EvaluatedRule<'scanner>>,

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

    /// Callback receiving scan events.
    ///
    /// Can be unset, in which case matched rules are accumulated into the
    /// `rules` field.
    pub(crate) callback: Option<ScanCallback<'scanner, 'cb>>,

    /// Set indicating which variable reached the match limit.
    ///
    /// Only used if the callback is set and the relevant scan event is
    /// enabled.
    pub string_reached_match_limit: HashSet<usize>,
}

impl std::fmt::Debug for ScanData<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ScanData");

        let _r = d
            .field("external_symbols_values", &self.external_symbols_values)
            .field("rules", &self.rules)
            .field("module_values", &self.module_values)
            .field("statistics", &self.statistics)
            .field("timeout_checker", &self.timeout_checker)
            .field("params", &self.params)
            .field(
                "callback",
                &self.callback.as_ref().map(|cb| {
                    let ptr: *const _ = cb;
                    ptr
                }),
            );

        #[cfg(feature = "object")]
        let _r = d.field("entrypoint", &self.entrypoint);

        d.finish()
    }
}

impl ScanData<'_, '_> {
    pub(crate) fn check_timeout(&mut self) -> bool {
        self.timeout_checker
            .as_mut()
            .is_some_and(TimeoutChecker::check_timeout)
    }

    // Call the callback on all the already matched rules.
    //
    // Sometimes, it is necessary to evaluate rules while delaying their
    // statuses of "matched rules", because this status can become invalid.
    // For example, when evaluating global rules, or when evaluating without
    // the variable scan.
    //
    // When this happens, matched rules are accumulated as if no callbacks
    // was specified. Once those matched rules are validated, the callback,
    // if it exists, must be called.
    fn handle_already_matched_rules_and_callback(&mut self) -> Result<(), ScanError> {
        let Some(cb) = &mut self.callback else {
            return Ok(());
        };

        for rule in self.rules.drain(..) {
            let mut result = ScanCallbackResult::Continue;
            if rule.matched && (self.params.callback_events & CallbackEvents::RULE_MATCH).0 != 0 {
                result = (cb)(ScanEvent::RuleMatch(rule));
            } else if !rule.matched
                && (self.params.callback_events & CallbackEvents::RULE_NO_MATCH).0 != 0
            {
                result = (cb)(ScanEvent::RuleNoMatch(rule));
            }
            match result {
                ScanCallbackResult::Continue => (),
                ScanCallbackResult::Abort => return Err(ScanError::CallbackAbort),
            }
        }

        Ok(())
    }

    fn send_module_import_events_to_cb(&mut self) -> Result<(), ScanError> {
        let Some(cb) = &mut self.callback else {
            return Ok(());
        };
        if (self.params.callback_events & CallbackEvents::MODULE_IMPORT).0 == 0 {
            return Ok(());
        }

        for evaluated_module in &self.module_values.evaluated_modules {
            match (cb)(ScanEvent::ModuleImport(evaluated_module)) {
                ScanCallbackResult::Continue => (),
                ScanCallbackResult::Abort => return Err(ScanError::CallbackAbort),
            }
        }

        Ok(())
    }
}

fn build_matched_rule<'a>(
    rule: &'a Rule,
    variables: &'a [Variable],
    namespaces_names: &'a [String],
    var_matches: Vec<Vec<StringMatch>>,
    matched: bool,
) -> EvaluatedRule<'a> {
    EvaluatedRule {
        name: &rule.name,
        namespace: namespaces_names[rule.namespace_index].as_ref(),
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
                has_xor_modifier: var.matcher.modifiers.xor_start.is_some(),
            })
            .collect(),
        matched,
    }
}

/// Result of a scan
#[derive(Debug, Default)]
pub struct ScanResult<'scanner> {
    /// List of rules of interest for this scan.
    ///
    /// By default, this is a list of the rules that matched.
    /// If [`ScanParams::include_not_matched_rules`] is set, this list will also include
    /// rules that did not match.  Use the `EvaluatedRule::matched`] boolean to distinguish
    /// between the two.
    pub rules: Vec<EvaluatedRule<'scanner>>,

    /// Results of the evaluation of modules during the scan.
    pub modules: Vec<EvaluatedModule<'scanner>>,

    /// Statistics related to the scan.
    // This is boxed to reduce the size of the struct, especially as this field
    // is pratically never set outside of test/debug runs.
    pub statistics: Option<Box<statistics::Evaluation>>,
}

/// Result of a rule evaluation during a scan.
#[derive(Debug)]
pub struct EvaluatedRule<'scanner> {
    /// Name of the rule.
    pub name: &'scanner str,

    /// Namespace containing the rule.
    pub namespace: &'scanner str,

    /// Tags associated with the rule.
    pub tags: &'scanner [String],

    /// Metadata associated with the rule.
    pub metadatas: &'scanner [Metadata],

    /// List of matched strings, with details on their matches.
    pub matches: Vec<StringMatches<'scanner>>,

    /// Did the rule match.
    ///
    /// There is no need to check this flag unless the [`ScanParams::include_not_matched_rules`]
    /// parameter is set, as only matching rules are listed by default.
    pub matched: bool,
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

    /// Does the string have a xor modifier.
    pub has_xor_modifier: bool,
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

#[cfg(feature = "serialize")]
mod wire {
    use std::collections::HashMap;
    use std::io;
    use std::sync::Arc;

    use crate::wire::{Deserialize, Serialize};

    use crate::compiler::variable::Variable;
    use crate::compiler::{CompilerProfile, ExternalValue};
    use crate::module::{Module, ModuleUserData, StaticValue};
    use crate::wire::DeserializeContext;

    use super::{ac_scan::AcScan, Inner, Rule, Scanner};
    use super::{BytesPool, ScanParams};

    /// Parameters used during deserialization of a [`Scanner`].
    ///
    /// See [`Scanner::from_bytes_unchecked`].
    #[derive(Debug)]
    pub struct DeserializeParams {
        modules: HashMap<&'static str, Box<dyn Module>>,
    }

    impl Default for DeserializeParams {
        fn default() -> Self {
            let mut modules = HashMap::new();

            crate::module::add_default_modules(|module| {
                let _r = modules.insert(module.get_name(), module);
            });

            Self { modules }
        }
    }

    impl DeserializeParams {
        /// Add a module to be available during deserialization.
        ///
        /// If any serialized rule used a module, this module must be known when deserializing
        /// rules. All the modules defined in [`crate::module`] are available except for
        /// the console module, so there is no need to add them through this API. See
        /// the list documented in the [`crate::compiler::CompilerBuilder::new`] API.
        ///
        /// However, any modules that may have been added when compiling the rules before
        /// serialization must be added here, including the console module or any third-party
        /// ones.
        ///
        /// If the same module has already been added, it will be replaced by this one.
        /// This can be useful to change the parameters of a module.
        pub fn add_module<M: Module + 'static>(&mut self, module: M) {
            let _r = self.modules.insert(module.get_name(), Box::new(module));
        }
    }

    impl Serialize for Scanner {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.scan_params.serialize(writer)?;
            self.external_symbols_values.serialize(writer)?;
            (*self.inner).serialize(writer)?;
            Ok(())
        }
    }

    pub(super) fn deserialize_scanner<R: io::Read>(
        params: DeserializeParams,
        reader: &mut R,
    ) -> io::Result<Scanner> {
        let scan_params = ScanParams::deserialize_reader(reader)?;
        let external_symbols_values = <Vec<ExternalValue>>::deserialize_reader(reader)?;
        let inner = deserialize_inner(params, reader)?;
        Ok(Scanner {
            inner: Arc::new(inner),
            scan_params,
            external_symbols_values,
            module_user_data: ModuleUserData::default(),
        })
    }

    impl Serialize for Inner {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.external_symbols_map.serialize(writer)?;
            self.namespaces.serialize(writer)?;
            self.bytes_pool.serialize(writer)?;
            self.variables.serialize(writer)?;
            serialize_modules(&self.modules, writer)?;
            self.global_rules.serialize(writer)?;
            self.rules.serialize(writer)?;
            self.profile.serialize(writer)?;
            Ok(())
        }
    }

    fn deserialize_inner<R: io::Read>(
        params: DeserializeParams,
        reader: &mut R,
    ) -> io::Result<Inner> {
        let external_symbols_map = <HashMap<String, usize>>::deserialize_reader(reader)?;
        let namespaces = <Vec<String>>::deserialize_reader(reader)?;
        let bytes_pool = BytesPool::deserialize_reader(reader)?;
        let variables = <Vec<Variable>>::deserialize_reader(reader)?;
        let modules = deserialize_modules(params.modules, reader)?;

        let ctx = DeserializeContext {
            modules_static_values: modules
                .iter()
                .map(|module| StaticValue::Object(module.get_static_values()))
                .collect(),
        };
        let global_rules = deserialize_rules(&ctx, reader)?;
        let rules = deserialize_rules(&ctx, reader)?;

        let profile = CompilerProfile::deserialize_reader(reader)?;
        let ac_scan = AcScan::new(&variables, profile);

        Ok(Inner {
            rules,
            global_rules,
            variables,
            ac_scan,
            modules,
            external_symbols_map,
            namespaces,
            bytes_pool,
            profile,
        })
    }

    impl Serialize for CompilerProfile {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Self::Speed => 0_u8.serialize(writer),
                Self::Memory => 1_u8.serialize(writer),
            }
        }
    }

    impl Deserialize for CompilerProfile {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let tag = u8::deserialize_reader(reader)?;
            match tag {
                0 => Ok(Self::Speed),
                1 => Ok(Self::Memory),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid value for CompilerProfile: {tag}"),
                )),
            }
        }
    }

    fn deserialize_rules<R: io::Read>(
        ctx: &DeserializeContext,
        reader: &mut R,
    ) -> io::Result<Vec<Rule>> {
        let len = u32::deserialize_reader(reader)?;
        let len = usize::try_from(len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("length too big: {len}"))
        })?;
        let mut rules = Vec::with_capacity(len);
        for _ in 0..len {
            rules.push(Rule::deserialize(ctx, reader)?);
        }
        Ok(rules)
    }

    fn serialize_modules<W: io::Write>(
        modules: &[Box<dyn Module>],
        writer: &mut W,
    ) -> io::Result<()> {
        let len = u32::try_from(modules.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("modules length too big: {}", modules.len()),
            )
        })?;
        len.serialize(writer)?;
        for module in modules {
            module.get_name().serialize(writer)?;
        }
        Ok(())
    }

    fn deserialize_modules<R: io::Read>(
        mut available_modules: HashMap<&'static str, Box<dyn Module>>,
        reader: &mut R,
    ) -> io::Result<Vec<Box<dyn Module>>> {
        let len = u32::deserialize_reader(reader)?;
        let len = usize::try_from(len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("length too big: {len}"))
        })?;
        let mut modules = Vec::with_capacity(len);
        for _ in 0..len {
            let name = String::deserialize_reader(reader)?;
            match available_modules.remove(&*name) {
                Some(module) => modules.push(module),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown module to import: {name}"),
                    ))
                }
            }
        }
        Ok(modules)
    }

    #[cfg(test)]
    mod tests {
        use crate::bytes_pool::BytesPoolBuilder;
        use crate::compiler::expression::Expression;
        use crate::module::{Math, Time};
        use crate::wire::tests::{
            test_invalid_deserialization, test_round_trip, test_round_trip_custom_deser,
        };

        use super::*;

        #[test]
        fn test_wire_scanner() {
            let scanner = Scanner {
                scan_params: ScanParams::default(),
                external_symbols_values: vec![ExternalValue::Integer(23)],
                module_user_data: ModuleUserData::default(),
                inner: Arc::new(Inner {
                    external_symbols_map: HashMap::new(),
                    namespaces: Vec::new(),
                    bytes_pool: BytesPoolBuilder::default().into_pool(),
                    variables: Vec::new(),
                    modules: vec![Box::new(Math)],
                    global_rules: Vec::new(),
                    rules: Vec::new(),
                    profile: CompilerProfile::Speed,
                    ac_scan: AcScan::new(&[], CompilerProfile::Speed),
                }),
            };

            let truncate_offset_errors = [0, 32, 46];

            let mut buf = [0; 46];
            for offset in &truncate_offset_errors {
                assert!(scanner.serialize(&mut &mut buf[..*offset]).is_err());
            }

            let mut buf = Vec::new();
            scanner.serialize(&mut buf).unwrap();
            for offset in &truncate_offset_errors {
                assert!(deserialize_scanner(
                    DeserializeParams::default(),
                    &mut io::Cursor::new(&buf[..*offset])
                )
                .is_err());
            }

            let scanner2 =
                deserialize_scanner(DeserializeParams::default(), &mut io::Cursor::new(buf))
                    .unwrap();
            assert_eq!(scanner.scan_params, scanner2.scan_params);
            assert_eq!(
                scanner.external_symbols_values,
                scanner2.external_symbols_values
            );
            assert_eq!(scanner2.inner.modules.len(), 1);
            assert_eq!(scanner2.inner.modules[0].get_name(), "math");
        }

        #[test]
        fn test_wire_inner() {
            let inner = Inner {
                external_symbols_map: [("abc".to_owned(), 33), ("zyx".to_owned(), 12)]
                    .into_iter()
                    .collect(),
                namespaces: vec!["abc".to_owned()],
                bytes_pool: BytesPoolBuilder::default().into_pool(),
                variables: Vec::new(),
                modules: vec![Box::new(Math), Box::new(Time)],
                global_rules: Vec::new(),
                rules: Vec::new(),
                profile: CompilerProfile::Speed,
                ac_scan: AcScan::new(&[], CompilerProfile::Speed),
            };

            let truncate_offset_errors = [0, 34, 45, 49, 53, 73, 77, 81];

            let mut buf = [0; 83];
            for offset in &truncate_offset_errors {
                assert!(inner.serialize(&mut &mut buf[..*offset]).is_err());
            }

            let mut buf = Vec::new();
            inner.serialize(&mut buf).unwrap();
            for offset in &truncate_offset_errors {
                assert!(deserialize_inner(
                    DeserializeParams::default(),
                    &mut io::Cursor::new(&buf[..*offset])
                )
                .is_err());
            }

            let inner2 =
                deserialize_inner(DeserializeParams::default(), &mut io::Cursor::new(buf)).unwrap();
            assert_eq!(inner.external_symbols_map, inner2.external_symbols_map);
            assert_eq!(inner.namespaces, inner2.namespaces);
            assert_eq!(inner.bytes_pool, inner2.bytes_pool);
            assert_eq!(inner.variables, inner2.variables);
            assert_eq!(inner2.modules.len(), 2);
            assert_eq!(inner2.modules[0].get_name(), "math");
            assert_eq!(inner2.modules[1].get_name(), "time");
            assert_eq!(inner.global_rules, inner2.global_rules);
            assert_eq!(inner.rules, inner2.rules);
            assert_eq!(inner.profile, inner2.profile);
        }

        #[test]
        fn test_wire_modules() {
            fn build_available_modules() -> HashMap<&'static str, Box<dyn Module>> {
                let mut map: HashMap<&'static str, Box<dyn Module>> = HashMap::new();
                let _r = map.insert("time", Box::new(Time));
                let _r = map.insert("math", Box::new(Math));
                map
            }

            let modules: Vec<Box<dyn Module>> = vec![Box::new(Time), Box::new(Math)];

            let mut buf = [0; 5];
            assert!(serialize_modules(&modules, &mut &mut buf[..1]).is_err());
            assert!(serialize_modules(&modules, &mut &mut buf[..5]).is_err());
            let mut buf = Vec::new();
            serialize_modules(&modules, &mut buf).unwrap();

            assert!(deserialize_modules(
                build_available_modules(),
                &mut io::Cursor::new(&buf[..1])
            )
            .is_err());
            assert!(deserialize_modules(
                build_available_modules(),
                &mut io::Cursor::new(&buf[..5])
            )
            .is_err());
            let modules =
                deserialize_modules(build_available_modules(), &mut io::Cursor::new(&buf)).unwrap();
            assert_eq!(modules.len(), 2);
            assert_eq!(modules[0].get_name(), "time");
            assert_eq!(modules[1].get_name(), "math");

            // Unknown module
            assert!(deserialize_modules(HashMap::new(), &mut io::Cursor::new(&buf)).is_err());
        }

        #[test]
        fn test_wire_rules() {
            let ctx = DeserializeContext::default();
            let rules = vec![Rule {
                name: "a".to_owned(),
                namespace_index: 0,
                tags: Vec::new(),
                metadatas: Vec::new(),
                nb_variables: 0,
                condition: Expression::Filesize,
                is_private: false,
            }];
            test_round_trip_custom_deser(&rules, |reader| deserialize_rules(&ctx, reader), &[0, 4]);
        }

        #[test]
        fn test_wire_compiler_profile() {
            test_round_trip(&CompilerProfile::Speed, &[0]);
            test_round_trip(&CompilerProfile::Memory, &[0]);

            test_invalid_deserialization::<CompilerProfile>(b"\x05");
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
        let scanner = compiler.finalize();

        let user_data = ModuleUserData::default();
        let mut module_values =
            evaluator::module::EvalData::new(&scanner.inner.modules, &user_data);
        module_values.scan_region(&Region { start: 0, mem }, false);

        let mut mem = Memory::Direct(mem);
        let mut scan_data = ScanData {
            external_symbols_values: &[],
            rules: Vec::new(),
            module_values,
            statistics: None,
            timeout_checker: None,
            params: &ScanParams::default(),
            #[cfg(feature = "object")]
            entrypoint: None,
            callback: None,
            string_reached_match_limit: HashSet::new(),
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
                    &mut mem,
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
            &mut mem,
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
            rules: Vec::new(),
            modules: Vec::new(),
            statistics: None,
        });
        test_type_traits_non_clonable(EvaluatedRule {
            name: "a",
            namespace: "b",
            tags: &[],
            metadatas: &[],
            matches: Vec::new(),
            matched: false,
        });
        test_type_traits_non_clonable(StringMatches {
            name: "a",
            matches: Vec::new(),
            has_xor_modifier: false,
        });
        test_type_traits_non_clonable(DefineSymbolError::UnknownName);
        test_type_traits_non_clonable(ScanData {
            external_symbols_values: &[],
            rules: Vec::new(),
            module_values: evaluator::module::EvalData {
                evaluated_modules: Vec::new(),
                data_map: crate::module::ModuleDataMap::new(&ModuleUserData::default()),
            },
            statistics: None,
            timeout_checker: None,
            #[cfg(feature = "object")]
            entrypoint: None,
            params: &ScanParams::default(),
            callback: Some(Box::new(|_evt| ScanCallbackResult::Continue)),
            string_reached_match_limit: HashSet::new(),
        });
        test_type_traits_non_clonable(RulesIter {
            global_rules: [].iter(),
            rules: [].iter(),
            namespaces: &[],
        });
        test_type_traits_non_clonable(RuleDetails {
            name: "",
            namespace: "c",
            tags: &[],
            metadatas: &[],
            is_global: false,
            is_private: false,
        });
        test_type_traits_non_clonable(StringIdentifier {
            rule_namespace: "a",
            rule_name: "",
            string_name: "",
            string_index: 0,
        });
        #[cfg(feature = "serialize")]
        test_type_traits_non_clonable(DeserializeParams::default());
    }
}
