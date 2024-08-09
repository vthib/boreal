use std::fs::File;
use std::io::{BufRead, BufReader, StdoutLock, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::JoinHandle;
use std::time::Duration;

use boreal::compiler::{CompilerBuilder, CompilerProfile, ExternalValue};
use boreal::module::{Console, Value as ModuleValue};
use boreal::scanner::{FragmentedScanMode, ScanError, ScanParams, ScanResult};
use boreal::{statistics, Compiler, Metadata, MetadataValue, Scanner};

use clap::{command, value_parser, Arg, ArgAction, ArgMatches, Command};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::{
    self,
    termcolor::{ColorChoice, StandardStream},
};
use crossbeam_channel::{bounded, Receiver, Sender};
use walkdir::WalkDir;

fn build_command() -> Command {
    let mut command = command!()
        .arg(
            Arg::new("no_follow_symlinks")
                .short('N')
                .long("no-follow-symlinks")
                .action(ArgAction::SetTrue)
                .help("Do not follow symlinks when scanning"),
        )
        .arg(
            Arg::new("print_module_data")
                .short('D')
                .long("print-module-data")
                .action(ArgAction::SetTrue)
                .help("Print module data"),
        )
        .arg(
            Arg::new("recursive")
                .short('r')
                .long("recursive")
                .action(ArgAction::SetTrue)
                .help("Recursively search directories"),
        )
        .arg(
            Arg::new("skip_larger")
                .short('z')
                .long("skip-larger")
                .value_name("MAX_SIZE")
                .value_parser(value_parser!(u64))
                .help("Skip files larger than the given size when scanning a directory"),
        )
        .arg(
            Arg::new("threads")
                .short('p')
                .long("threads")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Number of threads to use when scanning directories"),
        )
        .arg(
            Arg::new("profile")
                .long("profile")
                .value_name("speed|memory")
                .value_parser(parse_compiler_profile)
                .help("Profile to use when compiling rules"),
        )
        .arg(
            Arg::new("rules_file")
                .value_parser(value_parser!(PathBuf))
                .required_unless_present("module_names")
                .help("Path to a yara file containing rules"),
        )
        .arg(
            Arg::new("input")
                .value_parser(value_parser!(String))
                .required_unless_present("module_names")
                .help("File or directory to scan"),
        )
        .arg(
            Arg::new("define")
                .short('d')
                .long("define")
                .value_name("VAR=VALUE")
                .action(ArgAction::Append)
                .value_parser(parse_define)
                .help("Define a symbol that can be used in rules"),
        )
        .arg(
            Arg::new("fail_on_warnings")
                .long("fail-on-warnings")
                .action(ArgAction::SetTrue)
                .help("Fail compilation of rules on warnings"),
        )
        .arg(
            Arg::new("module_names")
                .short('M')
                .long("module-names")
                .action(ArgAction::SetTrue)
                .help("Display the names of all available modules"),
        )
        .arg(
            Arg::new("string_statistics")
                .long("string-stats")
                .action(ArgAction::SetTrue)
                .help("Display statistics on rules' compilation"),
        )
        .arg(
            Arg::new("scan_statistics")
                .long("scan-stats")
                .action(ArgAction::SetTrue)
                .help("Display statistics on rules' evaluation"),
        )
        .arg(
            Arg::new("memory_chunk_size")
                .long("max-process-memory-chunk")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Maximum chunk size when scanning processes"),
        )
        .arg(
            Arg::new("max_fetched_region_size")
                .long("max-fetched-region-size")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Maximum size fetched from a process region"),
        )
        .arg(
            Arg::new("fragmented_scan_mode")
                .long("fragmented-scan-mode")
                .value_name("legacy|fast|singlepass")
                .value_parser(parse_fragmented_scan_mode)
                .help("Specify scan mode for fragmented memory (e.g. process scanning)"),
        )
        .arg(
            Arg::new("print_namespace")
                .short('e')
                .long("print-namespace")
                .action(ArgAction::SetTrue)
                .help("Print rule namespace"),
        )
        .arg(
            Arg::new("print_strings")
                .short('s')
                .long("print-strings")
                .action(ArgAction::SetTrue)
                .help("Print strings matches")
                .long_help(
                    "Note that enabling this parameter will force the \
                     computation of all string matches,\ndisabling \
                     the no scan optimization in the process.",
                ),
        )
        .arg(
            Arg::new("print_string_length")
                .short('L')
                .long("print-string-length")
                .action(ArgAction::SetTrue)
                .help("Print the length of strings matches")
                .long_help(
                    "Note that enabling this parameter will force the \
                     computation of all string matches,\ndisabling \
                     the no scan optimization in the process.",
                ),
        )
        .arg(
            Arg::new("print_metadata")
                .short('m')
                .long("print-meta")
                .action(ArgAction::SetTrue)
                .help("Print rule metadatas"),
        )
        .arg(
            Arg::new("print_tags")
                .short('g')
                .long("print-tags")
                .action(ArgAction::SetTrue)
                .help("Print rule tags"),
        )
        .arg(
            Arg::new("identifier")
                .short('i')
                .long("identifier")
                .value_name("IDENTIFIER")
                .value_parser(value_parser!(String))
                .help("Print only rules with the given name"),
        )
        .arg(
            Arg::new("tag")
                .short('t')
                .long("tag")
                .value_name("TAG")
                .value_parser(value_parser!(String))
                .help("Print only rules with the given tag"),
        )
        .arg(
            Arg::new("no_console_logs")
                .short('q')
                .long("disable-console-logs")
                .action(ArgAction::SetTrue)
                .help("Disable printing console log messages"),
        )
        .arg(
            Arg::new("timeout")
                .short('a')
                .long("timeout")
                .value_name("SECONDS")
                .value_parser(value_parser!(u64))
                .help("Set the timeout duration before scanning is aborted"),
        )
        .arg(
            Arg::new("no_warnings")
                .short('w')
                .long("no-warnings")
                .action(ArgAction::SetTrue)
                .help("Do not print warnings"),
        )
        .arg(
            Arg::new("scan_list")
                .long("scan-list")
                .action(ArgAction::SetTrue)
                .help("Scan files listed in input, each line is a path to a file or directory"),
        );

    if cfg!(feature = "memmap") {
        command = command.arg(
            Arg::new("no_mmap")
                .long("no-mmap")
                .action(ArgAction::SetTrue)
                .help("Disable the use of memory maps.")
                .long_help(
                    "Disable the use of memory maps.\n\
                    By default, memory maps are used to load files to scan.\n\
                    This can cause the program to abort unexpectedly \
                    if files are simultaneous truncated.",
                ),
        );
    }

    command
}

fn main() -> ExitCode {
    let mut args = build_command().get_matches();

    if args.get_flag("module_names") {
        let compiler = Compiler::new();

        let mut names: Vec<_> = compiler.available_modules().collect();
        names.sort_unstable();

        for name in names {
            println!("{name}");
        }

        return ExitCode::SUCCESS;
    }

    let mut scanner = {
        let rules_file: PathBuf = args.remove_one("rules_file").unwrap();

        let mut builder = CompilerBuilder::new();

        // Even if the console logs are disabled, add the module so that rules that use it
        // can still compile properly.
        let no_console_logs = args.get_flag("no_console_logs");
        builder = builder.add_module(Console::with_callback(move |log| {
            if !no_console_logs {
                println!("{log}");
            }
        }));

        if let Some(profile) = args.get_one::<CompilerProfile>("profile") {
            builder = builder.profile(*profile);
        }

        let mut compiler = builder.build();

        compiler.set_params(
            boreal::compiler::CompilerParams::default()
                .fail_on_warnings(args.get_flag("fail_on_warnings"))
                .compute_statistics(args.get_flag("string_statistics")),
        );

        if let Some(defines) = args.remove_many::<(String, ExternalValue)>("define") {
            for (name, value) in defines {
                compiler.define_symbol(name, value);
            }
        }

        match compiler.add_rules_file(&rules_file) {
            Ok(status) => {
                if !args.get_flag("no_warnings") {
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
                return ExitCode::FAILURE;
            }
        }

        compiler.into_scanner()
    };

    let scan_options = ScanOptions::new(&args);

    let mut scan_params = scan_params_from_args(&args);
    if scan_options.print_strings_matches() {
        scan_params = scan_params.compute_full_matches(true);
    }
    scanner.set_scan_params(scan_params);

    match Input::new(&args) {
        Ok(Input::Directory(path)) => {
            let (thread_pool, sender) = ThreadPool::new(&scanner, &scan_options, &args);

            send_directory(&path, &args, &sender);
            drop(sender);
            thread_pool.join();

            ExitCode::SUCCESS
        }
        Ok(Input::File(path)) => match scan_file(&scanner, &path, &scan_options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Cannot scan {}: {}", path.display(), err);
                ExitCode::FAILURE
            }
        },
        Ok(Input::Process(pid)) => match scan_process(&scanner, pid, &scan_options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Cannot scan {}: {}", pid, err);
                ExitCode::FAILURE
            }
        },
        Ok(Input::Files(files)) => {
            let (thread_pool, sender) = ThreadPool::new(&scanner, &scan_options, &args);

            for path in files {
                if path.is_dir() {
                    send_directory(&path, &args, &sender);
                } else {
                    sender.send(path).unwrap();
                }
            }
            drop(sender);
            thread_pool.join();

            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}", err);
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
    fn new(args: &ArgMatches) -> Result<Self, String> {
        let input: &String = args.get_one("input").unwrap();
        let scan_list = args.get_flag("scan_list");

        // Same semantics as YARA: only parse it as a PID if there is no
        // file with this name.
        let path = PathBuf::from(input);

        Ok(if scan_list {
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
            match input.parse() {
                Ok(pid) => Self::Process(pid),
                Err(_) => Input::File(path),
            }
        })
    }
}

fn send_directory(path: &Path, args: &ArgMatches, sender: &Sender<PathBuf>) {
    let mut walker = WalkDir::new(path).follow_links(!args.get_flag("no_follow_symlinks"));
    if !args.get_flag("recursive") {
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

        if let Some(max_size) = args.get_one::<u64>("skip_larger") {
            if *max_size > 0 && entry.depth() > 0 {
                let file_length = entry.metadata().ok().map_or(0, |meta| meta.len());
                if file_length >= *max_size {
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

fn scan_params_from_args(args: &ArgMatches) -> ScanParams {
    let mut scan_params = ScanParams::default()
        .compute_statistics(args.get_flag("scan_statistics"))
        .memory_chunk_size(args.get_one::<usize>("memory_chunk_size").copied())
        .timeout_duration(
            args.get_one::<u64>("timeout")
                .map(|s| Duration::from_secs(*s)),
        );

    if let Some(size) = args.get_one::<usize>("max_fetched_region_size") {
        scan_params = scan_params.max_fetched_region_size(*size);
    }

    if let Some(scan_mode) = args.get_one::<FragmentedScanMode>("fragmented_scan_mode") {
        scan_params = scan_params.fragmented_scan_mode(*scan_mode);
    }

    scan_params
}

fn parse_define(arg: &str) -> Result<(String, ExternalValue), String> {
    let Some((name, value)) = arg.split_once('=') else {
        return Err("missing '=' delimiter".to_owned());
    };

    let external_value = if value == "true" {
        ExternalValue::Boolean(true)
    } else if value == "false" {
        ExternalValue::Boolean(false)
    } else if value.contains('.') {
        match value.parse::<f64>() {
            Ok(v) => ExternalValue::Float(v),
            Err(_) => ExternalValue::Bytes(value.as_bytes().to_vec()),
        }
    } else {
        match value.parse::<i64>() {
            Ok(v) => ExternalValue::Integer(v),
            Err(_) => ExternalValue::Bytes(value.as_bytes().to_vec()),
        }
    };

    Ok((name.to_owned(), external_value))
}

fn parse_fragmented_scan_mode(scan_mode: &str) -> Result<FragmentedScanMode, String> {
    match scan_mode {
        "legacy" => Ok(FragmentedScanMode::legacy()),
        "fast" => Ok(FragmentedScanMode::fast()),
        "singlepass" => Ok(FragmentedScanMode::single_pass()),
        _ => Err("invalid value".to_string()),
    }
}

fn parse_compiler_profile(profile: &str) -> Result<CompilerProfile, String> {
    match profile {
        "speed" => Ok(CompilerProfile::Speed),
        "memory" => Ok(CompilerProfile::Memory),
        _ => Err("invalid value".to_string()),
    }
}

#[derive(Clone, Debug)]
struct ScanOptions {
    print_module_data: bool,
    print_strings_matches_data: bool,
    print_string_length: bool,
    print_metadata: bool,
    print_namespace: bool,
    print_tags: bool,
    no_mmap: bool,
    identifier: Option<String>,
    tag: Option<String>,
}

impl ScanOptions {
    fn new(args: &ArgMatches) -> Self {
        Self {
            print_module_data: args.get_flag("print_module_data"),
            print_strings_matches_data: args.get_flag("print_strings"),
            print_string_length: args.get_flag("print_string_length"),
            print_metadata: args.get_flag("print_metadata"),
            print_namespace: args.get_flag("print_namespace"),
            print_tags: args.get_flag("print_tags"),
            no_mmap: if cfg!(feature = "memmap") {
                args.get_flag("no_mmap")
            } else {
                false
            },
            identifier: args.get_one("identifier").cloned(),
            tag: args.get_one("tag").cloned(),
        }
    }

    fn print_strings_matches(&self) -> bool {
        self.print_strings_matches_data || self.print_string_length
    }
}

fn scan_file(scanner: &Scanner, path: &Path, options: &ScanOptions) -> Result<(), ScanError> {
    let res = if cfg!(feature = "memmap") && !options.no_mmap {
        // Safety: By default, we accept that this CLI tool can abort if the underlying
        // file is truncated while the scan is ongoing.
        unsafe { scanner.scan_file_memmap(path) }
    } else {
        scanner.scan_file(path)
    };

    let what = path.display().to_string();
    match res {
        Ok(res) => {
            display_scan_results(scanner, res, &what, options);
            Ok(())
        }
        Err((err, res)) => {
            display_scan_results(scanner, res, &what, options);
            Err(err)
        }
    }
}

fn scan_process(scanner: &Scanner, pid: u32, options: &ScanOptions) -> Result<(), ScanError> {
    let what = pid.to_string();
    match scanner.scan_process(pid) {
        Ok(res) => {
            display_scan_results(scanner, res, &what, options);
            Ok(())
        }
        Err((err, res)) => {
            display_scan_results(scanner, res, &what, options);
            Err(err)
        }
    }
}

fn display_scan_results(scanner: &Scanner, res: ScanResult, what: &str, options: &ScanOptions) {
    // Print module data first
    if options.print_module_data {
        for (module_name, module_value) in res.module_values {
            // A module value must be an object. Filter out empty ones, it means the module has not
            // generated any values.
            if let ModuleValue::Object(map) = &module_value {
                if !map.is_empty() {
                    print!("{module_name}");
                    print_module_value(&module_value, 4);
                }
            }
        }
    }

    // Lock stdout to avoid having multiple threads interlap their writes
    let mut stdout = std::io::stdout().lock();

    // Then, print matching rules.
    for rule in res.matched_rules {
        if let Some(id) = options.identifier.as_ref() {
            if rule.name != id {
                continue;
            }
        }
        if let Some(tag) = options.tag.as_ref() {
            if rule.tags.iter().all(|t| t != tag) {
                continue;
            }
        }

        // <rule_namespace>:<rule_name> [<ruletags>] <matched object>
        if options.print_namespace {
            write!(stdout, "{}:", rule.namespace.unwrap_or("default")).unwrap();
        }
        write!(stdout, "{}", &rule.name).unwrap();
        if options.print_tags {
            write!(stdout, " [{}]", rule.tags.join(",")).unwrap();
        }
        if options.print_metadata {
            print_metadata(&mut stdout, scanner, rule.metadatas);
        }
        writeln!(stdout, " {}", what).unwrap();

        if options.print_strings_matches() {
            for string in &rule.matches {
                for m in &string.matches {
                    // <offset>:<length>:<name>: <match>
                    write!(stdout, "0x{:x}:", m.base + m.offset).unwrap();
                    if options.print_string_length {
                        write!(stdout, "{}:", m.length).unwrap();
                    }
                    write!(stdout, "${}", string.name).unwrap();
                    if options.print_strings_matches_data {
                        write!(stdout, ": ").unwrap();
                        print_bytes(&mut stdout, &m.data);
                    }
                    writeln!(stdout).unwrap();
                }
            }
        }
    }

    // Finally, print the statistics
    if let Some(stats) = res.statistics {
        writeln!(stdout, "{}: {:#?}", what, stats).unwrap();
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
                print_bytes(stdout, scanner.get_bytes_symbol(b));
                write!(stdout, "\"").unwrap();
            }
            MetadataValue::Integer(i) => {
                write!(stdout, "{}", i).unwrap();
            }
            MetadataValue::Boolean(b) => {
                write!(stdout, "{}", b).unwrap();
            }
        }
    }
    write!(stdout, "]").unwrap();
}

fn print_bytes(stdout: &mut StdoutLock, data: &[u8]) {
    for c in data {
        for b in std::ascii::escape_default(*c) {
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
        scan_options: &ScanOptions,
        args: &ArgMatches,
    ) -> (Self, Sender<PathBuf>) {
        let nb_cpus = if let Some(nb) = args.get_one::<usize>("threads") {
            std::cmp::min(1, *nb)
        } else {
            std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(32)
        };

        let (sender, receiver) = bounded(nb_cpus * 5);
        (
            Self {
                threads: (0..nb_cpus)
                    .map(|_| Self::worker_thread(scanner, &receiver, scan_options))
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
        scan_options: &ScanOptions,
    ) -> JoinHandle<()> {
        let scanner = scanner.clone();
        let receiver = receiver.clone();
        let scan_options = scan_options.clone();

        std::thread::spawn(move || {
            while let Ok(path) = receiver.recv() {
                if let Err(err) = scan_file(&scanner, &path, &scan_options) {
                    eprintln!("Cannot scan file {}: {}", path.display(), err);
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
    print!(
        "{}:{}",
        stats.namespace.as_deref().unwrap_or("default"),
        stats.name
    );
    match &stats.filepath {
        Some(path) => println!(" (from {})", path.display()),
        None => println!(),
    };
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
fn print_module_value(value: &ModuleValue, indent: usize) {
    match value {
        ModuleValue::Integer(i) => println!(" = {i} (0x{i:x})"),
        ModuleValue::Float(v) => println!(" = {v}"),
        ModuleValue::Bytes(bytes) => {
            println!(" = {:?}", ByteString(bytes));
        }
        ModuleValue::Regex(regex) => println!(" = /{}/", regex.as_str()),
        ModuleValue::Boolean(b) => println!(" = {b:?}"),
        ModuleValue::Object(obj) => {
            if obj.is_empty() {
                println!(" = {{}}");
                return;
            }

            println!();

            // For improved readability, we sort the keys before printing. Cost is of no concern,
            // this is only for CLI debugging.
            let mut keys: Vec<_> = obj.keys().collect();
            keys.sort_unstable();
            for key in keys {
                print!("{:indent$}{}", "", key);
                print_module_value(&obj[key], indent + 4);
            }
        }
        ModuleValue::Array(array) => {
            if array.is_empty() {
                println!(" = []");
                return;
            }

            println!();
            for (index, subval) in array.iter().enumerate() {
                print!("{:indent$}[{}]", "", index);
                print_module_value(subval, indent + 4);
            }
        }
        ModuleValue::Dictionary(dict) => {
            if dict.is_empty() {
                println!(" = {{}}");
                return;
            }

            println!();

            // For improved readability, we sort the keys before printing. Cost is of no concern,
            // this is only for CLI debugging.
            let mut keys: Vec<_> = dict.keys().collect();
            keys.sort_unstable();
            for key in keys {
                print!("{:indent$}[{:?}]", "", ByteString(key));
                print_module_value(&dict[key], indent + 4);
            }
        }
        ModuleValue::Function(_) => println!("[function]"),
        ModuleValue::Undefined => println!("[undef]"),
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
    fn verify_cli() {
        build_command().debug_assert();
    }

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

        test(ScanOptions {
            print_module_data: false,
            print_strings_matches_data: false,
            print_string_length: false,
            print_metadata: false,
            print_namespace: false,
            print_tags: false,
            no_mmap: false,
            identifier: None,
            tag: None,
        });
        test_non_clonable(Input::Process(32));
    }

    #[test]
    fn test_scan_params_from_args() {
        fn parse(cmdline: &str) -> ScanParams {
            let args = build_command().get_matches_from(cmdline.split(' '));
            scan_params_from_args(&args)
        }

        let params = parse("boreal --max-process-memory-chunk 500 rules input");
        assert_eq!(params.get_memory_chunk_size(), Some(500));

        let params = parse("boreal --max-fetched-region-size 500 rules input");
        assert_eq!(params.get_max_fetched_region_size(), 500);

        let params = parse("boreal --fragmented-scan-mode legacy rules input");
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::legacy()
        );
        let params = parse("boreal --fragmented-scan-mode fast rules input");
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::fast()
        );
        let params = parse("boreal --fragmented-scan-mode singlepass rules input");
        assert_eq!(
            params.get_fragmented_scan_mode(),
            FragmentedScanMode::single_pass()
        );
    }
}
