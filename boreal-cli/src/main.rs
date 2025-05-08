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

use boreal::module::Value as ModuleValue;
use boreal::scanner::{EvaluatedRule, ScanCallbackResult, ScanError, ScanEvent};
use boreal::{statistics, Compiler, Metadata, MetadataValue, Scanner};

use clap::ArgMatches;
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::{
    self,
    termcolor::{ColorChoice, StandardStream},
};
use crossbeam_channel::{bounded, Receiver, Sender};
use walkdir::WalkDir;

mod args;
use args::{CallbackOptions, InputOptions, WarningMode};

fn main() -> ExitCode {
    let mut args = args::build_command().get_matches();

    if args.get_flag("module_names") {
        let compiler = Compiler::new();

        let mut names: Vec<_> = compiler.available_modules().collect();
        names.sort_unstable();

        for name in names {
            println!("{name}");
        }

        return ExitCode::SUCCESS;
    }

    let warning_mode = WarningMode::from_args(&args);

    let Some(mut scanner) = build_scanner(&mut args, warning_mode) else {
        return ExitCode::FAILURE;
    };

    let scanner_options = args::ScannerOptions::from_args(&mut args);
    if let Err(err) = args::set_scanner_options(&mut scanner, scanner_options) {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }

    let callback_options = CallbackOptions::from_args(&args, warning_mode);
    args::update_scanner_params_from_callback_options(&mut scanner, &callback_options);

    #[cfg(feature = "serialize")]
    if args.get_flag("save") {
        return save_scanner(&scanner, &args);
    }

    let no_mmap = if cfg!(feature = "memmap") {
        args.get_flag("no_mmap")
    } else {
        false
    };
    let nb_threads = if let Some(nb) = args.get_one::<usize>("threads") {
        std::cmp::min(1, *nb)
    } else {
        std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(32)
    };

    let input_options = InputOptions::from_args(&mut args);

    let mut nb_rules = 0;
    match Input::new(&input_options) {
        Ok(Input::Directory(path)) => {
            let (thread_pool, sender) =
                ThreadPool::new(&scanner, &callback_options, nb_threads, no_mmap);

            send_directory(&path, &input_options, &sender);
            drop(sender);
            thread_pool.join();

            ExitCode::SUCCESS
        }
        Ok(Input::File(path)) => {
            match scan_file(&scanner, &path, &callback_options, no_mmap, &mut nb_rules) {
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
            match scan_process(&scanner, pid, &callback_options, &mut nb_rules) {
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
            let (thread_pool, sender) =
                ThreadPool::new(&scanner, &callback_options, nb_threads, no_mmap);

            for path in files {
                if path.is_dir() {
                    send_directory(&path, &input_options, &sender);
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

fn build_scanner(args: &mut ArgMatches, warning_mode: WarningMode) -> Option<Scanner> {
    let rules_file: PathBuf = args.remove_one("rules_file").unwrap();

    #[cfg(feature = "serialize")]
    if args.get_flag("load_from_bytes") {
        return load_scanner_from_bytes(&rules_file);
    }

    let compiler_options = args::CompilerOptions::from_args(args);
    let mut compiler = args::build_compiler(compiler_options, warning_mode);

    match compiler.add_rules_file(&rules_file) {
        Ok(status) => {
            if !matches!(warning_mode, WarningMode::Ignore) {
                for warn in status.warnings() {
                    display_diagnostic(&rules_file, warn);
                }
            }
            for rule_stat in status.statistics() {
                display_rule_stats(rule_stat);
            }
        }
        Err(err) => {
            display_diagnostic(&rules_file, &err);
            return None;
        }
    }

    Some(compiler.into_scanner())
}

#[cfg(feature = "serialize")]
fn load_scanner_from_bytes(rules_file: &Path) -> Option<Scanner> {
    let contents = match std::fs::read(rules_file) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Unable to read from {}: {:?}", rules_file.display(), err);
            return None;
        }
    };

    let mut params = boreal::scanner::DeserializeParams::default();
    // If the logs are disabled, it will be updated in the scanner, so just print the log here.
    params.add_module(boreal::module::Console::with_callback(move |log| {
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
fn save_scanner(scanner: &Scanner, args: &ArgMatches) -> ExitCode {
    let input: &String = args.get_one("input").unwrap();
    let path = PathBuf::from(input);

    match std::fs::exists(&path) {
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

    let mut file = match File::create(&path) {
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
}
