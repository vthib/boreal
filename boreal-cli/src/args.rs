use std::{path::PathBuf, time::Duration};

use boreal::{
    compiler::{CompilerBuilder, CompilerParams, CompilerProfile, ExternalValue},
    module::{Console, ConsoleData},
    scanner::{CallbackEvents, FragmentedScanMode, ScanParams},
    Compiler, Scanner,
};
use clap::{command, parser::Values, value_parser, Arg, ArgAction, ArgMatches, Command};

#[derive(Debug)]
pub struct CompilerOptions {
    pub profile: Option<CompilerProfile>,
    pub compute_statistics: bool,
    pub max_strings_per_rule: Option<usize>,
    pub defines: Option<Values<(String, ExternalValue)>>,
}

#[derive(Debug)]
pub struct ScannerOptions {
    memory_chunk_size: Option<usize>,
    timeout: Option<u64>,
    max_fetched_region_size: Option<usize>,
    fragmented_scan_mode: Option<FragmentedScanMode>,
    string_max_nb_matches: Option<u32>,
    module_data: Option<Values<(String, PathBuf)>>,
    no_console_logs: bool,
}

#[derive(Clone, Debug)]
pub struct CallbackOptions {
    pub print_strings_matches_data: bool,
    pub print_string_length: bool,
    pub print_xor_key: bool,
    pub print_metadata: bool,
    pub print_namespace: bool,
    pub print_tags: bool,
    pub print_count: bool,
    pub print_statistics: bool,
    pub print_module_data: bool,
    pub count_limit: Option<u64>,
    pub identifier: Option<String>,
    pub tag: Option<String>,
    pub negate: bool,
    pub warning_mode: WarningMode,
}

#[derive(Debug)]
pub struct InputOptions {
    pub scan_list: bool,
    pub no_follow_symlinks: bool,
    pub recursive: bool,
    pub skip_larger: Option<u64>,
    pub input: String,
}

#[derive(Debug, Copy, Clone)]
pub enum WarningMode {
    /// Fail compilation and scan when a warning happens.
    Fail,
    /// Print warnings but keep going.
    Print,
    /// Ignore warnings.
    Ignore,
}

pub fn build_command() -> Command {
    let mut command = command!()
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
                .help("Path to a yara file containing rules")
                .long_help(
                    "Path to a yara file containing rules.\n\
                     If -C is specified, this is the path to a file containing serialized rules."
                )
        )
        .arg(
            Arg::new("input")
                .value_parser(value_parser!(String))
                .required_unless_present("module_names")
                .help("File or directory to scan")
                .long_help(
                    "File or directory to scan.\n\
                     If --save is specified, this is the path to the file to create."
                )
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
            Arg::new("print_scan_statistics")
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
            Arg::new("max_strings_per_rule")
                .long("max-strings-per-rule")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Maximum number of strings in a single rule")
        )
        .arg(
            Arg::new("string_max_nb_matches")
                .long("string-max-nb-matches")
                .value_name("NUMBER")
                .value_parser(value_parser!(u32))
                .help("Maximum number of matches for a single string, default is 1000")
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
            Arg::new("print_xor_key")
                .short('X')
                .long("print-xor-key")
                .action(ArgAction::SetTrue)
                .help("Print the xor key and the plaintext of matched strings")
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
            Arg::new("count")
                .short('c')
                .long("count")
                .action(ArgAction::SetTrue)
                .help("Print number of rules that matched (or did not match if negate is set)"),
        )
        .arg(
            Arg::new("count_limit")
                .short('l')
                .long("max-rules")
                .value_name("NUMBER")
                .value_parser(value_parser!(u64))
                .help("Abort the scan once NUMBER rules have been matched (or not matched if negate is set)")
        )
        .arg(
            Arg::new("negate")
                .short('n')
                .long("negate")
                .action(ArgAction::SetTrue)
                .help("only print rules that *do not* match"),
        )
        .arg(
            Arg::new("no_follow_symlinks")
                .short('N')
                .long("no-follow-symlinks")
                .action(ArgAction::SetTrue)
                .help("Do not follow symlinks when scanning"),
        )
        .arg(
            Arg::new("do_not_print_warnings")
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
        )
        .arg(
            Arg::new("module_data")
                .short('x')
                .long("module-data")
                .value_name("MODULE=FILE")
                .action(ArgAction::Append)
                .value_parser(parse_module_data)
                .help("Specify the data to use in a module")
                .long_help(
                    "Specify the data to use in a module.\n\
                     Note that only the cuckoo module is supported."
                )
        );

    if cfg!(feature = "serialize") {
        command = command
            .arg(
                Arg::new("save")
                    .long("save")
                    .action(ArgAction::SetTrue)
                    .help("Serialize the compiled rules into bytes and save it at the given path")
                    .long_help(
                        "Serialize the compiled rules into bytes and save it at the given path.\n\
                    The last argument must be the path to the file that will be created to\n\
                    hold this serialization. The file must not already exists.\n\
                    This differs from normal execution where the path points to an existing file\n\
                    that must be scanned.",
                    ),
            )
            .arg(
                Arg::new("load_from_bytes")
                    .short('C')
                    .long("compiled-rules")
                    .action(ArgAction::SetTrue)
                    .help("Load compiled rules from bytes. See --save option"),
            );
    }

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

impl WarningMode {
    pub fn from_args(args: &ArgMatches) -> Self {
        if args.get_flag("fail_on_warnings") {
            Self::Fail
        } else if args.get_flag("do_not_print_warnings") {
            Self::Ignore
        } else {
            Self::Print
        }
    }
}

impl InputOptions {
    pub fn from_args(args: &mut ArgMatches) -> Self {
        Self {
            scan_list: args.get_flag("scan_list"),
            no_follow_symlinks: args.get_flag("no_follow_symlinks"),
            recursive: args.get_flag("recursive"),
            skip_larger: args.remove_one::<u64>("skip_larger"),
            input: args.remove_one("input").unwrap(),
        }
    }
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

fn parse_module_data(arg: &str) -> Result<(String, PathBuf), String> {
    let Some((name, path)) = arg.split_once('=') else {
        return Err("missing '=' delimiter".to_owned());
    };

    Ok((name.to_owned(), PathBuf::from(path)))
}

impl ScannerOptions {
    pub fn from_args(args: &mut ArgMatches) -> Self {
        Self {
            memory_chunk_size: args.remove_one("memory_chunk_size"),
            timeout: args.remove_one("timeout"),
            max_fetched_region_size: args.remove_one("max_fetched_region_size"),
            fragmented_scan_mode: args.remove_one("fragmented_scan_mode"),
            string_max_nb_matches: args.remove_one("string_max_nb_matches"),
            module_data: args.remove_many::<(String, PathBuf)>("module_data"),
            no_console_logs: args.get_flag("no_console_logs"),
        }
    }
}

pub fn set_scanner_options(scanner: &mut Scanner, options: ScannerOptions) -> Result<(), String> {
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

pub fn update_scanner_params_from_callback_options(
    scanner: &mut Scanner,
    options: &CallbackOptions,
) {
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

impl CallbackOptions {
    pub fn from_args(args: &ArgMatches, warning_mode: WarningMode) -> Self {
        Self {
            print_strings_matches_data: args.get_flag("print_strings"),
            print_string_length: args.get_flag("print_string_length"),
            print_xor_key: args.get_flag("print_xor_key"),
            print_metadata: args.get_flag("print_metadata"),
            print_namespace: args.get_flag("print_namespace"),
            print_tags: args.get_flag("print_tags"),
            print_count: args.get_flag("count"),
            print_statistics: args.get_flag("print_scan_statistics"),
            print_module_data: args.get_flag("print_module_data"),
            count_limit: args.get_one::<u64>("count_limit").copied(),
            identifier: args.get_one("identifier").cloned(),
            tag: args.get_one("tag").cloned(),
            negate: args.get_flag("negate"),
            warning_mode,
        }
    }

    pub fn print_strings_matches(&self) -> bool {
        self.print_strings_matches_data || self.print_string_length || self.print_xor_key
    }
}

impl CompilerOptions {
    pub fn from_args(args: &mut ArgMatches) -> Self {
        Self {
            profile: args.remove_one::<CompilerProfile>("profile"),
            compute_statistics: args.get_flag("string_statistics"),
            max_strings_per_rule: args.remove_one::<usize>("max_strings_per_rule"),
            defines: args.remove_many::<(String, ExternalValue)>("define"),
        }
    }
}

pub fn build_compiler(options: CompilerOptions, warning_mode: WarningMode) -> Compiler {
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

    compiler
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        build_command().debug_assert();
    }

    #[test]
    fn test_scan_params_from_args() {
        fn parse(cmdline: &str) -> ScanParams {
            let mut args = build_command().get_matches_from(cmdline.split(' '));
            build_scan_params(&ScannerOptions::from_args(&mut args))
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
