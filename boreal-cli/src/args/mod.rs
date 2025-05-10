use std::path::PathBuf;

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
    pub fn from_yr_args(mut args: ArgMatches) -> Self {
        if args.get_flag("module_names") {
            return Self::ListModules;
        }

        let warning_mode = WarningMode::from_args(&args);
        let scanner_options = ScannerOptions::from_args(&mut args);
        let callback_options = CallbackOptions::from_args(&args, warning_mode);
        let input_options = InputOptions::from_args(&mut args);
        let rules_file: PathBuf = args.remove_one("rules_file").unwrap();

        #[cfg(feature = "serialize")]
        if args.get_flag("load_from_bytes") {
            return Self::LoadAndScan(LoadScanExecution {
                scanner_options,
                callback_options,
                input_options,
                scanner_file: rules_file,
            });
        }

        let mut compiler_options = CompilerOptions::from_args(&mut args, true);
        compiler_options.rules_files = vec![rules_file];

        Self::CompileAndScan(CompileScanExecution {
            warning_mode,
            compiler_options,
            scanner_options,
            callback_options,
            input_options,
        })
    }
}

pub fn build_command() -> Command {
    let mut command = command!().subcommand_required(true);

    command = command.subcommand(build_yr_subcommand());
    command = command.subcommand(build_scan_subcommand());
    command = command.subcommand(
        Command::new("list-modules").about("Display the names of all available modules"),
    );

    #[cfg(feature = "serialize")]
    {
        command = command.subcommand(build_save_subcommand());
        command = command.subcommand(build_load_subcommand());
    }

    command
}

fn build_yr_subcommand() -> Command {
    let mut command = Command::new("yr")
        .about("Invoke boreal with a yara-compatible interface")
        .long_about(
            "This subcommand allows specifying options exactly as done with the yara CLI.\n\
             This allows substituting uses of the yara CLI without risks.\n\
             This API can be a bit ambiguous at times with multiple rules inputs, and many options\n\
             can be specified that will not be used in some contexts.\n\
             For these reasons, using the other subcommands is recommended for improved clarity.")
        .next_help_heading(None);

    // Add all options in the yr subcommand. The type of invokation will
    // be distinguished through the detection of specific options (see `ExecutionMode::from_yr_args`).
    command = command
        .arg(
            Arg::new("rules_file")
                .value_parser(value_parser!(PathBuf))
                .required_unless_present("module_names")
                .help("Path to a yara file containing rules")
                .long_help(
                    "Path to a yara file containing rules.\n\
                     If -C is specified, this is the path to a file containing serialized rules.",
                ),
        )
        .arg(
            Arg::new("module_names")
                .short('M')
                .long("module-names")
                .action(ArgAction::SetTrue)
                .help("Display the names of all available modules"),
        );

    if cfg!(feature = "serialize") {
        command = command.arg(
            Arg::new("load_from_bytes")
                .short('C')
                .long("compiled-rules")
                .action(ArgAction::SetTrue)
                .help("Load compiled rules from bytes. See save subcommand"),
        );
    }

    command = callback::add_callback_args(command);
    command = compiler::add_compiler_args(command, true);
    command = input::add_input_args(command, true);
    command = scanner::add_scanner_args(command);
    command = add_warnings_args(command);

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
            compiler_options: CompilerOptions::from_args(&mut args, false),
            scanner_options: ScannerOptions::from_args(&mut args),
            callback_options: CallbackOptions::from_args(&args, warning_mode),
            input_options: InputOptions::from_args(&mut args),
        }
    }
}

fn build_scan_subcommand() -> Command {
    let mut command =
        Command::new("scan").about("Compile rules and scan a file, a directory or a process");

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
            compiler_options: CompilerOptions::from_args(&mut args, false),
            destination_path: args.remove_one("destination_path").unwrap(),
        }
    }
}

#[cfg(feature = "serialize")]
fn build_save_subcommand() -> Command {
    let mut command =
        Command::new("save").about("Compile rules and serialize the results into a file");

    command = command.arg(
        Arg::new("destination_path")
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
            input_options: InputOptions::from_args(&mut args),
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
