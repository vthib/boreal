use std::path::{Path, PathBuf};
use std::process::ExitCode;

use boreal::Compiler;
use boreal::{module::Value as ModuleValue, Scanner};

use clap::Parser;
use codespan_reporting::diagnostic::Diagnostic;
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::{
    self,
    termcolor::{ColorChoice, StandardStream},
};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    /// Path to a yara file containing rules.
    #[clap(value_parser)]
    rules_file: PathBuf,

    /// File or directory to scan.
    #[clap(value_parser)]
    input: PathBuf,

    /// Do not follow symlinks when scanning
    #[clap(short = 'N', long, value_parser)]
    no_follow_symlinks: bool,

    /// Print module data
    #[clap(short = 'D', long, value_parser)]
    print_module_data: bool,

    /// Recursively search directories
    #[clap(short = 'r', long, value_parser)]
    recursive: bool,

    /// Skip files larger than the given size when scanning a directory
    #[clap(short = 'z', long, value_parser, value_name = "MAX_SIZE")]
    skip_larger: Option<u64>,
}

fn display_diagnostic(path: &Path, contents: &str, diagnostic: Diagnostic<()>) {
    let writer = StandardStream::stderr(ColorChoice::Always);
    let config = term::Config::default();

    let path = path.display().to_string();
    let files = SimpleFile::new(&path, contents);
    let writer = &mut writer.lock();
    if let Err(e) = term::emit(writer, &config, &files, &diagnostic) {
        eprintln!("cannot emit diagnostics: {}", e);
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let scanner = {
        let rules_contents = match std::fs::read_to_string(&args.rules_file) {
            Ok(v) => v,
            Err(err) => {
                eprintln!(
                    "Unable to open rule file {}: {}",
                    args.rules_file.display(),
                    err
                );
                return ExitCode::FAILURE;
            }
        };

        let mut compiler = Compiler::new();
        if let Err(err) = compiler.add_rules_str(&rules_contents) {
            display_diagnostic(&args.rules_file, &rules_contents, err.to_diagnostic());
            return ExitCode::FAILURE;
        }

        compiler.into_scanner()
    };

    let mut walker = WalkDir::new(&args.input).follow_links(!args.no_follow_symlinks);
    if !args.recursive {
        walker = walker.max_depth(1);
    }

    let mut has_success = false;
    for entry in walker {
        let entry = match entry {
            Ok(v) => v,
            Err(err) => {
                eprintln!("{}", err);
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        if let Some(max_size) = args.skip_larger {
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

        match scan_file(&scanner, entry.path(), &args) {
            Ok(()) => has_success = true,
            Err(err) => eprintln!("Cannot scan {}: {}", entry.path().display(), err),
        }
    }

    if has_success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn scan_file(scanner: &Scanner, path: &Path, args: &Args) -> std::io::Result<()> {
    let file_contents = std::fs::read(path)?;
    let res = scanner.scan_mem(&file_contents);

    if args.print_module_data {
        for (module_name, module_value) in res.module_values {
            // A module value must be an object. Filter out empty ones, it means the module has not
            // generated any values.
            match &*module_value {
                ModuleValue::Object(map) if !map.is_empty() => {
                    print!("{}", module_name);
                    print_module_value(&module_value, 4);
                }
                _ => (),
            }
        }
    }
    for rule in res.matched_rules {
        println!("{} {}", &rule.name, path.display());
    }

    Ok(())
}

/// Print a module value.
///
/// This is a recursive function.
/// The invariants are:
///   - on entry, the previous line is unfinished (no newline written yet)
///   - on exit, the line has been ended (last written char is a newline)
/// This is so that the caller can either:
/// - print " = ..." for primitive values
/// - print "\n..." for compound values
fn print_module_value(value: &ModuleValue, indent: usize) {
    match value {
        ModuleValue::Integer(i) => println!(" = {} (0x{:x})", i, i),
        ModuleValue::Float(v) => println!(" = {}", v),
        ModuleValue::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(s) => println!(" = {:?}", s),
            Err(_) => println!(" = {{ {} }}", hex::encode(bytes)),
        },
        ModuleValue::Regex(regex) => println!(" = /{}/", regex.as_regex().as_str()),
        ModuleValue::Boolean(b) => println!(" = {:?}", b),
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
                match std::str::from_utf8(key) {
                    Ok(s) => print!("{:indent$}[{:?}]", "", s),
                    Err(_) => print!("{:indent$}[{{ {} }}]", "", hex::encode(key)),
                };
                print_module_value(&dict[key], indent + 4);
            }
        }
        ModuleValue::Function(_) => println!("[function]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Args::command().debug_assert();
    }
}
