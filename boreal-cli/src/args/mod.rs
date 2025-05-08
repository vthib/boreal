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

#[derive(Debug)]
pub struct CompileScanExecution {
    pub warning_mode: WarningMode,
    pub compiler_options: CompilerOptions,
    pub scanner_options: ScannerOptions,
    pub callback_options: CallbackOptions,
    pub input_options: InputOptions,

    pub rules_file: PathBuf,
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
#[derive(Debug)]
pub struct CompileSaveExecution {
    pub warning_mode: WarningMode,
    pub compiler_options: CompilerOptions,

    pub rules_file: PathBuf,
    pub destination_path: String,
}

impl ExecutionMode {
    pub fn from_args(mut args: ArgMatches) -> Self {
        if args.get_flag("module_names") {
            return Self::ListModules;
        }

        let warning_mode = WarningMode::from_args(&args);

        #[cfg(feature = "serialize")]
        if args.get_flag("save") {
            return Self::CompileAndSave(CompileSaveExecution {
                warning_mode,
                compiler_options: CompilerOptions::from_args(&mut args),
                rules_file: args.remove_one("rules_file").unwrap(),
                destination_path: args.remove_one("input").unwrap(),
            });
        }

        #[cfg(feature = "serialize")]
        if args.get_flag("load_from_bytes") {
            return Self::LoadAndScan(LoadScanExecution {
                scanner_options: ScannerOptions::from_args(&mut args),
                callback_options: CallbackOptions::from_args(&args, warning_mode),
                input_options: InputOptions::from_args(&mut args),
                scanner_file: args.remove_one("rules_file").unwrap(),
            });
        }

        Self::CompileAndScan(CompileScanExecution {
            warning_mode,
            compiler_options: CompilerOptions::from_args(&mut args),
            scanner_options: ScannerOptions::from_args(&mut args),
            callback_options: CallbackOptions::from_args(&args, warning_mode),
            input_options: InputOptions::from_args(&mut args),
            rules_file: args.remove_one("rules_file").unwrap(),
        })
    }
}

pub fn build_command() -> Command {
    let mut command = command!();

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

    command = callback::add_callback_args(command);
    command = compiler::add_compiler_args(command);
    command = input::add_input_args(command);
    command = scanner::add_scanner_args(command);
    command = add_warning_args(command);

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

fn add_warning_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("fail_on_warnings")
                .long("fail-on-warnings")
                .action(ArgAction::SetTrue)
                .help("Fail compilation of rules on warnings"),
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
