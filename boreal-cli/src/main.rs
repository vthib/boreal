//! CLI tool to scan files and processes using boreal.
//!
//! This tool attempts to expose the same interface as the yara CLI tool if possible,
//! with some additional options added.
#![allow(unsafe_code)]

// Used in integration tests, not in the library.
// This is to remove the "unused_crate_dependencies" warning, maybe a better solution
// could be found.
#[cfg(test)]
use {assert_cmd as _, predicates as _, tempfile as _};

use std::fs::File;
use std::io::{BufRead, BufReader, StdoutLock, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::JoinHandle;
use std::time::Duration;

use boreal::compiler::{CompilerBuilder, CompilerParams};
use boreal::module::{Console, ConsoleData, Value as ModuleValue};
use boreal::scanner::{
    CallbackEvents, EvaluatedRule, ScanCallbackResult, ScanError, ScanEvent, ScanParams,
};
use boreal::{statistics, Compiler, Metadata, MetadataValue, Scanner};

use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::{
    self,
    termcolor::{ColorChoice, StandardStream},
};
use crossbeam_channel::{bounded, Receiver, Sender};
use walkdir::WalkDir;

mod args;
use args::{
    CallbackOptions, CompileScanExecution, CompilerOptions, ExecutionMode, InputOptions,
    ScannerOptions, WarningMode,
};

fn main() -> ExitCode {
    let mut args = args::build_command().get_matches();

    let (subcommand_name, subargs) = args.remove_subcommand().unwrap();
    let exec_mode = match &*subcommand_name {
        "yr" => ExecutionMode::from_yr_args(subargs),
        _ => unreachable!(),
    };

    match exec_mode {
        ExecutionMode::CompileAndScan(v) => compile_and_scan(v),
        #[cfg(feature = "serialize")]
        ExecutionMode::LoadAndScan(v) => load_and_scan(v),
        #[cfg(feature = "serialize")]
        ExecutionMode::CompileAndSave(v) => compile_and_save(v),
        ExecutionMode::ListModules => list_modules(),
    }
}

fn compile_and_scan(options: CompileScanExecution) -> ExitCode {
    let CompileScanExecution {
        warning_mode,
        compiler_options,
        scanner_options,
        callback_options,
        input_options,
        rules_file,
    } = options;

    let Some(scanner) = compile_rules(&rules_file, compiler_options, warning_mode) else {
        return ExitCode::FAILURE;
    };

    scan_input(scanner, scanner_options, &callback_options, &input_options)
}

#[cfg(feature = "serialize")]
fn load_and_scan(options: args::LoadScanExecution) -> ExitCode {
    let args::LoadScanExecution {
        scanner_options,
        callback_options,
        input_options,
        scanner_file,
    } = options;

    let Some(scanner) = load_scanner(&scanner_file) else {
        return ExitCode::FAILURE;
    };

    scan_input(scanner, scanner_options, &callback_options, &input_options)
}

#[cfg(feature = "serialize")]
fn compile_and_save(options: args::CompileSaveExecution) -> ExitCode {
    let args::CompileSaveExecution {
        warning_mode,
        compiler_options,
        rules_file,
        destination_path,
    } = options;

    let Some(scanner) = compile_rules(&rules_file, compiler_options, warning_mode) else {
        return ExitCode::FAILURE;
    };
    save_scanner(&scanner, Path::new(&destination_path))
}

fn scan_input(
    mut scanner: Scanner,
    scanner_options: ScannerOptions,
    callback_options: &CallbackOptions,
    input_options: &InputOptions,
) -> ExitCode {
    if let Err(err) = set_scanner_options(&mut scanner, scanner_options) {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }
    update_scanner_params_from_callback_options(&mut scanner, callback_options);

    let mut nb_rules = 0;
    match Input::new(input_options) {
        Ok(Input::Directory(path)) => {
            let (thread_pool, sender) = ThreadPool::new(
                &scanner,
                callback_options,
                input_options.nb_threads,
                input_options.no_mmap,
            );

            send_directory(&path, input_options, &sender);
            drop(sender);
            thread_pool.join();

            ExitCode::SUCCESS
        }
        Ok(Input::File(path)) => {
            match scan_file(
                &scanner,
                &path,
                callback_options,
                input_options.no_mmap,
                &mut nb_rules,
            ) {
                Ok(()) => {
                    if callback_options.print_count {
                        println!("{}: {}", path.display(), nb_rules);
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("Cannot scan {}: {}", path.display(), err);
                    ExitCode::FAILURE
                }
            }
        }
        Ok(Input::Process(pid)) => {
            match scan_process(&scanner, pid, callback_options, &mut nb_rules) {
                Ok(()) => {
                    if callback_options.print_count {
                        println!("{pid}: {nb_rules}");
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("Cannot scan {pid}: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(Input::Files(files)) => {
            let (thread_pool, sender) = ThreadPool::new(
                &scanner,
                callback_options,
                input_options.nb_threads,
                input_options.no_mmap,
            );

            for path in files {
                if path.is_dir() {
                    send_directory(&path, input_options, &sender);
                } else {
                    sender.send(path).unwrap();
                }
            }
            drop(sender);
            thread_pool.join();

            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn list_modules() -> ExitCode {
    let compiler = Compiler::new();
    // TODO: add console module

    let mut names: Vec<_> = compiler.available_modules().collect();
    names.sort_unstable();

    for name in names {
        println!("{name}");
    }

    ExitCode::SUCCESS
}

fn compile_rules(
    rules_file: &Path,
    options: CompilerOptions,
    warning_mode: WarningMode,
) -> Option<Scanner> {
    let CompilerOptions {
        profile,
        compute_statistics,
        max_strings_per_rule,
        defines,
    } = options;
    let mut builder = CompilerBuilder::new();

    // Regardless of whether the console logs are disabled, add the module so that rules that use it
    // can still compile properly.
    // If the logs are disabled, it will be updated in the scanner, so just print the log here.
    builder = builder.add_module(Console::with_callback(move |log| {
        println!("{log}");
    }));

    if let Some(profile) = profile {
        builder = builder.profile(profile);
    }

    let mut compiler = builder.build();

    let mut params = CompilerParams::default()
        .fail_on_warnings(matches!(warning_mode, WarningMode::Fail))
        .compute_statistics(compute_statistics);
    if let Some(limit) = max_strings_per_rule {
        params = params.max_strings_per_rule(limit);
    }
    compiler.set_params(params);

    if let Some(defines) = defines {
        for (name, value) in defines {
            let _r = compiler.define_symbol(name, value);
        }
    }

    match compiler.add_rules_file(rules_file) {
        Ok(status) => {
            if !matches!(warning_mode, WarningMode::Ignore) {
                for warn in status.warnings() {
                    display_diagnostic(rules_file, warn);
                }
            }
            for rule_stat in status.statistics() {
                display_rule_stats(rule_stat);
            }
        }
        Err(err) => {
            display_diagnostic(rules_file, &err);
            return None;
        }
    }

    Some(compiler.into_scanner())
}

#[cfg(feature = "serialize")]
fn load_scanner(scanner_file: &Path) -> Option<Scanner> {
    let contents = match std::fs::read(scanner_file) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Unable to read from {}: {:?}", scanner_file.display(), err);
            return None;
        }
    };

    let mut params = boreal::scanner::DeserializeParams::default();
    // If the logs are disabled, it will be updated in the scanner, so just print the log here.
    params.add_module(Console::with_callback(move |log| {
        println!("{log}");
    }));

    match Scanner::from_bytes_unchecked(&contents, params) {
        Ok(v) => Some(v),
        Err(err) => {
            eprintln!("Unable to deserialize rules: {err:?}");
            None
        }
    }
}

#[cfg(feature = "serialize")]
fn save_scanner(scanner: &Scanner, path: &Path) -> ExitCode {
    match std::fs::exists(path) {
        Ok(false) => (),
        Ok(true) => {
            eprintln!("File {} already exists, not saving rules", path.display());
            return ExitCode::FAILURE;
        }
        Err(err) => {
            eprintln!("Unable to inspect file {}: {:?}", path.display(), err);
            return ExitCode::FAILURE;
        }
    }

    let mut file = match File::create(path) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Unable to create file {}: {:?}", path.display(), err);
            return ExitCode::FAILURE;
        }
    };
    match scanner.to_bytes(&mut file) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Cannot serialize rules into {}: {:?}", path.display(), err);
            ExitCode::FAILURE
        }
    }
}

fn set_scanner_options(scanner: &mut Scanner, options: ScannerOptions) -> Result<(), String> {
    scanner.set_scan_params(build_scan_params(&options));

    if let Some(module_data) = options.module_data {
        #[allow(clippy::never_loop)]
        for (name, path) in module_data {
            #[cfg(feature = "cuckoo")]
            {
                use ::boreal::module::{Cuckoo, CuckooData};
                if name == "cuckoo" {
                    let contents = std::fs::read_to_string(&path).map_err(|err| {
                        format!(
                            "Unable to read {} data from file {}: {:?}",
                            name,
                            path.display(),
                            err
                        )
                    })?;
                    match CuckooData::from_json_report(&contents) {
                        Some(data) => scanner.set_module_data::<Cuckoo>(data),
                        None => {
                            return Err("The data for the cuckoo module is invalid".to_string());
                        }
                    }
                    continue;
                }
            }
            #[cfg(not(feature = "cuckoo"))]
            // Suppress unused var warnings
            {
                drop(path);
            }

            return Err(format!("Cannot set data for unsupported module {name}"));
        }
    }

    if options.no_console_logs {
        scanner.set_module_data::<Console>(ConsoleData::new(|_log| {}));
    }

    Ok(())
}

fn build_scan_params(options: &ScannerOptions) -> ScanParams {
    let mut scan_params = ScanParams::default()
        .memory_chunk_size(options.memory_chunk_size)
        .timeout_duration(options.timeout.map(Duration::from_secs));

    if let Some(size) = options.max_fetched_region_size {
        scan_params = scan_params.max_fetched_region_size(size);
    }

    if let Some(scan_mode) = options.fragmented_scan_mode {
        scan_params = scan_params.fragmented_scan_mode(scan_mode);
    }

    if let Some(limit) = options.string_max_nb_matches {
        scan_params = scan_params.string_max_nb_matches(limit);
    }

    scan_params
}

fn update_scanner_params_from_callback_options(scanner: &mut Scanner, options: &CallbackOptions) {
    let mut callback_events = CallbackEvents::empty();
    match options.warning_mode {
        WarningMode::Ignore => (),
        WarningMode::Fail | WarningMode::Print => {
            callback_events |= CallbackEvents::STRING_REACHED_MATCH_LIMIT;
        }
    }
    if options.print_module_data {
        callback_events |= CallbackEvents::MODULE_IMPORT;
    }
    if options.print_statistics {
        callback_events |= CallbackEvents::SCAN_STATISTICS;
    }
    if options.negate {
        callback_events |= CallbackEvents::RULE_NO_MATCH;
    } else {
        callback_events |= CallbackEvents::RULE_MATCH;
    }

    scanner.set_scan_params(
        scanner
            .scan_params()
            .clone()
            .compute_full_matches(options.print_strings_matches())
            .compute_statistics(options.print_statistics)
            .include_not_matched_rules(options.negate)
            .callback_events(callback_events),
    );
}

#[derive(Debug)]
enum Input {
    Directory(PathBuf),
    File(PathBuf),
    Process(u32),
    Files(Vec<PathBuf>),
}

impl Input {
    fn new(options: &InputOptions) -> Result<Self, String> {
        // Same semantics as YARA: only parse it as a PID if there is no
        // file with this name.
        let path = PathBuf::from(&options.input);

        Ok(if options.scan_list {
            let file = File::open(&path)
                .map_err(|err| format!("cannot open scan list {}: {}", path.display(), err))?;
            let reader = BufReader::new(file);
            let mut files = Vec::new();
            for line in reader.lines() {
                let line = line.map_err(|err| {
                    format!("cannot read from scan list {}: {}", path.display(), err)
                })?;
                files.push(PathBuf::from(line));
            }
            Input::Files(files)
        } else if path.is_dir() {
            Input::Directory(path)
        } else if path.exists() {
            Input::File(path)
        } else {
            match options.input.parse() {
                Ok(pid) => Self::Process(pid),
                Err(_) => Input::File(path),
            }
        })
    }
}

fn send_directory(path: &Path, options: &InputOptions, sender: &Sender<PathBuf>) {
    let mut walker = WalkDir::new(path).follow_links(!options.no_follow_symlinks);
    if !options.recursive {
        walker = walker.max_depth(1);
    }

    for entry in walker {
        let entry = match entry {
            Ok(v) => v,
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        if let Some(max_size) = options.skip_larger {
            if max_size > 0 && entry.depth() > 0 {
                let file_length = entry.metadata().ok().map_or(0, |meta| meta.len());
                if file_length >= max_size {
                    eprintln!(
                        "skipping {} ({} bytes) because it's larger than {} bytes.",
                        entry.path().display(),
                        file_length,
                        max_size
                    );
                    continue;
                }
            }
        }

        sender.send(entry.path().to_path_buf()).unwrap();
    }
}

fn scan_file(
    scanner: &Scanner,
    path: &Path,
    options: &CallbackOptions,
    no_mmap: bool,
    nb_rules: &mut u64,
) -> Result<(), ScanError> {
    let what = path.display().to_string();

    let res = if cfg!(feature = "memmap") && !no_mmap {
        // Safety: By default, we accept that this CLI tool can abort if the underlying
        // file is truncated while the scan is ongoing.
        unsafe {
            scanner.scan_file_memmap_with_callback(path, |event| {
                handle_event(scanner, event, &what, options, nb_rules)
            })
        }
    } else {
        scanner.scan_file_with_callback(path, |event| {
            handle_event(scanner, event, &what, options, nb_rules)
        })
    };

    match res {
        Ok(()) | Err(ScanError::CallbackAbort) => Ok(()),
        Err(err) => Err(err),
    }
}

fn scan_process(
    scanner: &Scanner,
    pid: u32,
    options: &CallbackOptions,
    nb_rules: &mut u64,
) -> Result<(), ScanError> {
    let what = pid.to_string();
    let res = scanner.scan_process_with_callback(pid, |event| {
        handle_event(scanner, event, &what, options, nb_rules)
    });
    match res {
        Ok(()) | Err(ScanError::CallbackAbort) => Ok(()),
        Err(err) => Err(err),
    }
}

fn handle_event(
    scanner: &Scanner,
    event: ScanEvent,
    what: &str,
    options: &CallbackOptions,
    nb_rules: &mut u64,
) -> ScanCallbackResult {
    // Lock stdout to avoid having multiple threads interlap their writes
    let mut stdout = std::io::stdout().lock();

    match event {
        ScanEvent::RuleMatch(rule) => {
            *nb_rules += 1;
            if !options.print_count {
                display_rule(&mut stdout, &rule, scanner, what, options);
            }
        }
        ScanEvent::RuleNoMatch(rule) => {
            *nb_rules += 1;
            if !options.print_count {
                display_rule(&mut stdout, &rule, scanner, what, options);
            }
        }
        ScanEvent::ModuleImport {
            module_name,
            dynamic_values,
        } => {
            // A module value must be an object. Filter out empty ones, it means the module has not
            // generated any values.
            if let ModuleValue::Object(map) = &dynamic_values {
                if !map.is_empty() {
                    write!(stdout, "{module_name}").unwrap();
                    print_module_value(&mut stdout, dynamic_values, 4);
                }
            }
        }
        ScanEvent::ScanStatistics(stats) => {
            writeln!(stdout, "{what}: {stats:#?}").unwrap();
        }
        ScanEvent::StringReachedMatchLimit(string_identifier) => {
            eprintln!(
                "warning: string ${} in rule {}:{} reached the maximum number of matches",
                string_identifier.string_name,
                string_identifier.rule_namespace,
                string_identifier.rule_name,
            );

            if matches!(options.warning_mode, WarningMode::Fail) {
                return ScanCallbackResult::Abort;
            }
        }
        _ => (),
    }

    if options.count_limit.is_some_and(|limit| *nb_rules >= limit) {
        ScanCallbackResult::Abort
    } else {
        ScanCallbackResult::Continue
    }
}

fn display_rule(
    stdout: &mut StdoutLock,
    rule: &EvaluatedRule,
    scanner: &Scanner,
    what: &str,
    options: &CallbackOptions,
) {
    if let Some(id) = options.identifier.as_ref() {
        if rule.name != id {
            return;
        }
    }
    if let Some(tag) = options.tag.as_ref() {
        if rule.tags.iter().all(|t| t != tag) {
            return;
        }
    }

    // <rule_namespace>:<rule_name> [<ruletags>] <matched object>
    if options.print_namespace {
        write!(stdout, "{}:", rule.namespace).unwrap();
    }
    write!(stdout, "{}", &rule.name).unwrap();
    if options.print_tags {
        write!(stdout, " [{}]", rule.tags.join(",")).unwrap();
    }
    if options.print_metadata {
        print_metadata(stdout, scanner, rule.metadatas);
    }
    writeln!(stdout, " {what}").unwrap();

    if options.print_strings_matches() {
        for string in &rule.matches {
            for m in &string.matches {
                // <offset>:<length>:<name>: <match>
                write!(stdout, "0x{:x}:", m.base + m.offset).unwrap();
                if options.print_string_length {
                    write!(stdout, "{}:", m.length).unwrap();
                }
                write!(stdout, "${}", string.name).unwrap();
                if options.print_xor_key {
                    write!(stdout, ":xor(0x{:02x},", m.xor_key).unwrap();
                    print_bytes(stdout, &m.data, m.xor_key);
                    write!(stdout, ")").unwrap();
                }
                if options.print_strings_matches_data {
                    write!(stdout, ": ").unwrap();
                    print_bytes(stdout, &m.data, 0);
                }
                writeln!(stdout).unwrap();
            }
        }
    }
}

fn print_metadata(stdout: &mut StdoutLock, scanner: &Scanner, metadatas: &[Metadata]) {
    write!(stdout, " [").unwrap();
    for (i, meta) in metadatas.iter().enumerate() {
        if i != 0 {
            write!(stdout, ",").unwrap();
        }
        write!(stdout, "{}=", scanner.get_string_symbol(meta.name)).unwrap();
        match meta.value {
            MetadataValue::Bytes(b) => {
                write!(stdout, "\"").unwrap();
                print_bytes(stdout, scanner.get_bytes_symbol(b), 0);
                write!(stdout, "\"").unwrap();
            }
            MetadataValue::Integer(i) => {
                write!(stdout, "{i}").unwrap();
            }
            MetadataValue::Boolean(b) => {
                write!(stdout, "{b}").unwrap();
            }
        }
    }
    write!(stdout, "]").unwrap();
}

fn print_bytes(stdout: &mut StdoutLock, data: &[u8], xor_key: u8) {
    for c in data {
        let c = *c ^ xor_key;
        for b in std::ascii::escape_default(c) {
            write!(stdout, "{}", b as char).unwrap();
        }
    }
}

struct ThreadPool {
    threads: Vec<JoinHandle<()>>,
}

impl ThreadPool {
    fn new(
        scanner: &Scanner,
        callback_options: &CallbackOptions,
        nb_threads: usize,
        no_mmap: bool,
    ) -> (Self, Sender<PathBuf>) {
        let (sender, receiver) = bounded(nb_threads * 5);
        (
            Self {
                threads: (0..nb_threads)
                    .map(|_| Self::worker_thread(scanner, &receiver, callback_options, no_mmap))
                    .collect(),
            },
            sender,
        )
    }

    fn join(self) {
        for handle in self.threads {
            handle.join().unwrap();
        }
    }

    fn worker_thread(
        scanner: &Scanner,
        receiver: &Receiver<PathBuf>,
        callback_options: &CallbackOptions,
        no_mmap: bool,
    ) -> JoinHandle<()> {
        let scanner = scanner.clone();
        let receiver = receiver.clone();
        let callback_options = callback_options.clone();

        std::thread::spawn(move || {
            while let Ok(path) = receiver.recv() {
                let mut nb_rules = 0;
                if let Err(err) =
                    scan_file(&scanner, &path, &callback_options, no_mmap, &mut nb_rules)
                {
                    eprintln!("Cannot scan file {}: {}", path.display(), err);
                }
                if callback_options.print_count {
                    println!("{}: {}", path.display(), nb_rules);
                }
            }
        })
    }
}

fn display_diagnostic(path: &Path, err: &boreal::compiler::AddRuleError) {
    let writer = StandardStream::stderr(ColorChoice::Auto);
    let config = term::Config::default();

    let files = match &err.path {
        Some(path) => {
            let contents = std::fs::read_to_string(path).unwrap_or_else(|_| String::new());
            SimpleFile::new(path.display().to_string(), contents)
        }
        None => SimpleFile::new(path.display().to_string(), String::new()),
    };
    let writer = &mut writer.lock();
    if let Err(e) = term::emit(writer, &config, &files, &err.to_diagnostic()) {
        eprintln!("cannot emit diagnostics: {e}");
    }
}

fn display_rule_stats(stats: &statistics::CompiledRule) {
    print!("{}:{}", stats.namespace, stats.name);
    match &stats.filepath {
        Some(path) => println!(" (from {})", path.display()),
        None => println!(),
    }
    for var in &stats.strings {
        let lits: Vec<_> = var.literals.iter().map(|v| ByteString(v)).collect();
        let atoms: Vec<_> = var.atoms.iter().map(|v| ByteString(v)).collect();
        println!("  {}", var.expr);
        println!("    literals: {:?}", &lits);
        println!("    atoms: {:?}", &atoms);
        println!("    atoms quality: {}", var.atoms_quality);
        println!("    algo: {}", var.matching_algo);
    }
}

/// Print a module value.
///
/// This is a recursive function.
///
/// The invariants are:
///
///   - on entry, the previous line is unfinished (no newline written yet)
///   - on exit, the line has been ended (last written char is a newline)
///
/// This is so that the caller can either:
///
/// - print " = ..." for primitive values
/// - print "\n..." for compound values
fn print_module_value(stdout: &mut StdoutLock, value: &ModuleValue, indent: usize) {
    match value {
        ModuleValue::Integer(i) => writeln!(stdout, " = {i} (0x{i:x})").unwrap(),
        ModuleValue::Float(v) => writeln!(stdout, " = {v}").unwrap(),
        ModuleValue::Bytes(bytes) => {
            writeln!(stdout, " = {:?}", ByteString(bytes)).unwrap();
        }
        ModuleValue::Regex(regex) => writeln!(stdout, " = /{}/", regex.as_str()).unwrap(),
        ModuleValue::Boolean(b) => writeln!(stdout, " = {b:?}").unwrap(),
        ModuleValue::Object(obj) => {
            if obj.is_empty() {
                writeln!(stdout, " = {{}}").unwrap();
                return;
            }

            writeln!(stdout).unwrap();

            // For improved readability, we sort the keys before printing. Cost is of no concern,
            // this is only for CLI debugging.
            let mut keys: Vec<_> = obj.keys().collect();
            keys.sort_unstable();
            for key in keys {
                write!(stdout, "{:indent$}{}", "", key).unwrap();
                print_module_value(stdout, &obj[key], indent + 4);
            }
        }
        ModuleValue::Array(array) => {
            if array.is_empty() {
                writeln!(stdout, " = []").unwrap();
                return;
            }

            writeln!(stdout,).unwrap();
            for (index, subval) in array.iter().enumerate() {
                write!(stdout, "{:indent$}[{}]", "", index).unwrap();
                print_module_value(stdout, subval, indent + 4);
            }
        }
        ModuleValue::Dictionary(dict) => {
            if dict.is_empty() {
                writeln!(stdout, " = {{}}").unwrap();
                return;
            }

            writeln!(stdout).unwrap();

            // For improved readability, we sort the keys before printing. Cost is of no concern,
            // this is only for CLI debugging.
            let mut keys: Vec<_> = dict.keys().collect();
            keys.sort_unstable();
            for key in keys {
                write!(stdout, "{:indent$}[{:?}]", "", ByteString(key)).unwrap();
                print_module_value(stdout, &dict[key], indent + 4);
            }
        }
        ModuleValue::Function(_) => writeln!(stdout, "[function]").unwrap(),
        ModuleValue::Undefined => writeln!(stdout, "[undef]").unwrap(),
    }
}

struct ByteString<'a>(&'a [u8]);

impl std::fmt::Debug for ByteString<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(self.0) {
            Ok(s) => write!(f, "{s:?}"),
            Err(_) => write!(f, "{{ {} }}", hex::encode(self.0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use boreal::scanner::FragmentedScanMode;

    use super::*;

    #[test]
    fn test_types() {
        fn test<T: Clone + std::fmt::Debug + Send + Sync>(t: T) {
            #[allow(clippy::redundant_clone)]
            let _r = t.clone();
            let _r = format!("{:?}", &t);
        }
        fn test_non_clonable<T: std::fmt::Debug + Send + Sync>(t: T) {
            let _r = format!("{:?}", &t);
        }

        test(CallbackOptions {
            print_strings_matches_data: false,
            print_string_length: false,
            print_xor_key: false,
            print_metadata: false,
            print_namespace: false,
            print_tags: false,
            print_count: false,
            print_statistics: false,
            print_module_data: false,
            count_limit: None,
            identifier: None,
            tag: None,
            negate: false,
            warning_mode: WarningMode::Fail,
        });
        test_non_clonable(Input::Process(32));
    }

    #[test]
    fn test_scan_params_from_args() {
        fn parse(cmdline: &str) -> ScanParams {
            let mut args = args::build_command().get_matches_from(cmdline.split(' '));
            let mut args = args.remove_subcommand().unwrap().1;
            build_scan_params(&ScannerOptions::from_args(&mut args))
        }

        let params = parse("boreal yr --max-process-memory-chunk 500 rules input");
        assert_eq!(params.get_memory_chunk_size(), Some(500));

        let params = parse("boreal yr --max-fetched-region-size 500 rules input");
        assert_eq!(params.get_max_fetched_region_size(), 500);

        let params = parse("boreal yr --fragmented-scan-mode legacy rules input");
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::legacy()
        );
        let params = parse("boreal yr --fragmented-scan-mode fast rules input");
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::fast()
        );
        let params = parse("boreal yr --fragmented-scan-mode singlepass rules input");
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::single_pass()
        );
    }
}
