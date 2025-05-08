use std::path::PathBuf;

use boreal::{
    compiler::{CompilerProfile, ExternalValue},
    scanner::FragmentedScanMode,
};
use clap::{command, value_parser, Arg, ArgAction, Command};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        build_command().debug_assert();
    }
}
