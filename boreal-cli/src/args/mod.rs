#[cfg(feature = "serialize")]
use std::path::PathBuf;

use clap::parser::Values;
use clap::{command, value_parser, Arg, ArgAction, ArgMatches, Command};

mod callback;
pub use callback::CallbackOptions;
mod compiler;
pub use compiler::CompilerOptions;
mod input;
pub use input::InputOptions;
mod scanner;
pub use scanner::ScannerOptions;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExecutionMode {
    /// Compile rules and scan an input
    CompileAndScan(CompileScanExecution),

    /// Load a serialized scanner and scan
    #[cfg(feature = "serialize")]
    LoadAndScan(LoadScanExecution),

    /// Compile rules and serialize the scanner.
    #[cfg(feature = "serialize")]
    CompileAndSave(CompileSaveExecution),

    /// List available modules.
    ListModules,
}

impl ExecutionMode {
    pub fn from_yr_args(mut args: ArgMatches) -> Result<Self, String> {
        if args.get_flag("module_names") {
            return Ok(Self::ListModules);
        }

        let positional_args: Values<String> = args.remove_many("args").unwrap();
        if positional_args.len() < 2 {
            return Err("Invalid number of arguments, at least one rules file \
                and a scan target must be specified"
                .to_owned());
        }

        let mut rules_files: Vec<String> = positional_args.into_iter().collect();
        let input = rules_files.pop().unwrap();

        let warning_mode = WarningMode::from_args(&args);
        let scanner_options = ScannerOptions::from_args(&mut args);
        let callback_options = CallbackOptions::from_args(&args, warning_mode);
        let input_options = InputOptions::from_args(&mut args, Some(input));

        #[cfg(feature = "serialize")]
        if args.get_flag("load_from_bytes") {
            if rules_files.len() != 1 {
                return Err("Only a single rules path must be passed when -C is used".to_owned());
            }
            return Ok(Self::LoadAndScan(LoadScanExecution {
                scanner_options,
                callback_options,
                input_options,
                scanner_file: PathBuf::from(rules_files.pop().unwrap()),
            }));
        }

        let compiler_options = CompilerOptions::from_args(&mut args, Some(rules_files));
        Ok(Self::CompileAndScan(CompileScanExecution {
            warning_mode,
            compiler_options,
            scanner_options,
            callback_options,
            input_options,
        }))
    }
}

pub fn build_command() -> Command {
    let mut command = command!().subcommand_required(true);

    command = command.subcommand(build_scan_subcommand());

    #[cfg(feature = "serialize")]
    {
        command = command.subcommand(build_save_subcommand());
        command = command.subcommand(build_load_subcommand());
    }

    command = command.subcommand(build_yr_subcommand());
    command = command.subcommand(
        Command::new("list-modules").about("Display the names of all available modules"),
    );

    command
}

fn build_yr_subcommand() -> Command {
    let mut command = Command::new("yr")
        .about("Invoke boreal with a yara-compatible interface")
        .long_about(
            "This subcommand allows specifying options exactly as done with the yara CLI.\n\
             This allows substituting uses of the yara CLI without risks.\n\
             This API can be a bit ambiguous at times with multiple rules inputs, and many options \
             can be specified that will not be used in some contexts.\n\
             For these reasons, using the other subcommands is recommended for improved clarity.",
        );

    if cfg!(feature = "serialize") {
        command = command.arg(
            Arg::new("load_from_bytes")
                .short('C')
                .long("compiled-rules")
                .action(ArgAction::SetTrue)
                .help("Load compiled rules from bytes.")
                .long_help(
                    "Load compiled rules from bytes.\n\n\
                    If specified, then a single rules path must be \
                    specified, which must point to a file containing \
                    serialized rules.\n\
                    See the scan subcommand for how to generate such a file.",
                ),
        );
    }

    command = callback::add_callback_args(command);
    command = compiler::add_compiler_args(command, true);
    command = input::add_input_args(command, true);
    command = scanner::add_scanner_args(command);
    command = add_warnings_args(command);

    command = command
        .next_help_heading(None)
        .arg(
            Arg::new("module_names")
                .short('M')
                .long("module-names")
                .action(ArgAction::SetTrue)
                .help("Display the names of all available modules"),
        )
        .arg(
            Arg::new("args")
                .value_parser(value_parser!(String))
                .action(ArgAction::Append)
                .help("List of rules file followed by the file, directory or pid to scan")
                .long_help(
                    "List of rules file followed by the file, directory or pid to scan.\n\n\
\
                [NAMESPACE:]RULES_FILE... [FILE | DIRECTORY | PID | SCAN_LIST]\n\n\
\
                At least two arguments must be specified: the path to the \
                rules file, and the input to scan.\nSeveral rules files can \
                be specified: the last argument will always be the input to \
                scan.\n\n\
\
                The path to rules files can be prefixed by the namespace in \
                which to compile the rules, followed by a colon.\n\
                This can notably be used to avoid name collisions when \
                using multiple rules files.\n\n\
\
                If --scan-list is specified, the input is a file containing \
                a list of inputs to scan, one per line.",
                )
                .required_unless_present("module_names"),
        );

    command
}

#[derive(Debug)]
pub struct CompileScanExecution {
    pub warning_mode: WarningMode,
    pub compiler_options: CompilerOptions,
    pub scanner_options: ScannerOptions,
    pub callback_options: CallbackOptions,
    pub input_options: InputOptions,
}

impl CompileScanExecution {
    pub fn from_args(mut args: ArgMatches) -> Self {
        let warning_mode = WarningMode::from_args(&args);

        Self {
            warning_mode,
            compiler_options: CompilerOptions::from_args(&mut args, None),
            scanner_options: ScannerOptions::from_args(&mut args),
            callback_options: CallbackOptions::from_args(&args, warning_mode),
            input_options: InputOptions::from_args(&mut args, None),
        }
    }
}

fn build_scan_subcommand() -> Command {
    let mut command = Command::new("scan")
        .about("Compile rules and scan a target")
        .override_usage("boreal scan [OPTIONS] [-f RULES]... [FILE | DIRECTORY | PID | SCAN_LIST]");

    command = add_warnings_args(command);
    command = compiler::add_compiler_args(command, false);
    command = scanner::add_scanner_args(command);
    command = callback::add_callback_args(command);
    command = input::add_input_args(command, false);

    command
}

#[cfg(feature = "serialize")]
#[derive(Debug)]
pub struct CompileSaveExecution {
    pub warning_mode: WarningMode,
    pub compiler_options: CompilerOptions,

    pub destination_path: PathBuf,
}

#[cfg(feature = "serialize")]
impl CompileSaveExecution {
    pub fn from_args(mut args: ArgMatches) -> Self {
        let warning_mode = WarningMode::from_args(&args);

        Self {
            warning_mode,
            compiler_options: CompilerOptions::from_args(&mut args, None),
            destination_path: args.remove_one("output_file").unwrap(),
        }
    }
}

#[cfg(feature = "serialize")]
fn build_save_subcommand() -> Command {
    let mut command = Command::new("save")
        .about("Compile rules and serialize the results into a file")
        .override_usage("boreal save [OPTIONS] [-f RULES]... [OUTPUT_FILE]");

    command = command.arg(
        Arg::new("output_file")
            .value_parser(value_parser!(PathBuf))
            .help("Path where the serialization of the compiled rules will be written"),
    );

    command = add_warnings_args(command);
    command = compiler::add_compiler_args(command, false);

    command
}

#[cfg(feature = "serialize")]
#[derive(Debug)]
pub struct LoadScanExecution {
    pub scanner_options: ScannerOptions,
    pub callback_options: CallbackOptions,
    pub input_options: InputOptions,

    pub scanner_file: PathBuf,
}

#[cfg(feature = "serialize")]
impl LoadScanExecution {
    pub fn from_args(mut args: ArgMatches) -> Self {
        let warning_mode = WarningMode::from_args(&args);

        Self {
            scanner_options: ScannerOptions::from_args(&mut args),
            callback_options: CallbackOptions::from_args(&args, warning_mode),
            input_options: InputOptions::from_args(&mut args, None),
            scanner_file: args.remove_one("compiled_rules").unwrap(),
        }
    }
}

#[cfg(feature = "serialize")]
fn build_load_subcommand() -> Command {
    let mut command = Command::new("load").about("Load compiled rules from a file and scan");

    command = command.arg(
        Arg::new("compiled_rules")
            .value_parser(value_parser!(PathBuf))
            .help("Path to a file containing serialized compiled rules"),
    );

    command = add_warnings_args(command);
    command = scanner::add_scanner_args(command);
    command = callback::add_callback_args(command);
    command = input::add_input_args(command, false);

    command
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

fn add_warnings_args(command: Command) -> Command {
    command
        .next_help_heading(None)
        .arg(
            Arg::new("fail_on_warnings")
                .long("fail-on-warnings")
                .action(ArgAction::SetTrue)
                .help("Fail compilation or abort scans on warnings"),
        )
        .arg(
            Arg::new("do_not_print_warnings")
                .short('w')
                .long("no-warnings")
                .action(ArgAction::SetTrue)
                .help("Do not print warnings"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        build_command().debug_assert();
    }
}
