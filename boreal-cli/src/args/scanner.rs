use std::path::PathBuf;

use boreal::scanner::FragmentedScanMode;
use clap::parser::Values;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

#[derive(Debug)]
pub struct ScannerOptions {
    pub memory_chunk_size: Option<usize>,
    pub timeout: Option<u64>,
    pub max_fetched_region_size: Option<usize>,
    pub fragmented_scan_mode: Option<FragmentedScanMode>,
    pub string_max_nb_matches: Option<u32>,
    pub module_data: Option<Values<(String, PathBuf)>>,
    pub no_console_logs: bool,
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

pub fn add_scanner_args(command: Command) -> Command {
    command
        .next_help_heading("Scanning options")
        .arg(
            Arg::new("memory_chunk_size")
                .long("max-process-memory-chunk")
                .value_name("NUMBER")
                .value_parser(value_parser!(usize))
                .help("Maximum chunk size when scanning processes"),
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
            Arg::new("string_max_nb_matches")
                .long("string-max-nb-matches")
                .value_name("NUMBER")
                .value_parser(value_parser!(u32))
                .help("Maximum number of matches for a single string, default is 1000"),
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
                    "Specify the data to use in a module.\n\n\
                     Note that only the cuckoo module is supported.",
                ),
        )
        .arg(
            Arg::new("no_console_logs")
                .short('q')
                .long("disable-console-logs")
                .action(ArgAction::SetTrue)
                .help("Disable printing console log messages"),
        )
}

fn parse_fragmented_scan_mode(scan_mode: &str) -> Result<FragmentedScanMode, String> {
    match scan_mode {
        "legacy" => Ok(FragmentedScanMode::legacy()),
        "fast" => Ok(FragmentedScanMode::fast()),
        "singlepass" => Ok(FragmentedScanMode::single_pass()),
        _ => Err("invalid value".to_string()),
    }
}

fn parse_module_data(arg: &str) -> Result<(String, PathBuf), String> {
    let Some((name, path)) = arg.split_once('=') else {
        return Err("missing '=' delimiter".to_owned());
    };

    Ok((name.to_owned(), PathBuf::from(path)))
}
