use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::JoinHandle;

use boreal::Compiler;
use boreal::{module::Value as ModuleValue, Scanner};

use clap::Parser;
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term::{
    self,
    termcolor::{ColorChoice, StandardStream},
};
use crossbeam_channel::{bounded, Receiver, Sender};
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

    /// Number of threads to use when scanning directories
    #[clap(short = 'p', long, value_parser, value_name = "NUMBER")]
    threads: Option<usize>,
}

fn display_diagnostic(path: &Path, err: &boreal::compiler::AddRuleError) {
    let writer = StandardStream::stderr(ColorChoice::Always);
    let config = term::Config::default();

    let files = match &err.path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(contents) => SimpleFile::new(path.display().to_string(), contents),
            Err(err) => {
                eprintln!(
                    "Cannot read {} after compilation error: {}",
                    path.display(),
                    err
                );
                return;
            }
        },
        None => SimpleFile::new(path.display().to_string(), String::new()),
    };
    let writer = &mut writer.lock();
    if let Err(e) = term::emit(writer, &config, &files, &err.to_diagnostic()) {
        eprintln!("cannot emit diagnostics: {}", e);
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let scanner = {
        let mut compiler = Compiler::new();
        match compiler.add_rules_file(&args.rules_file) {
            Ok(status) => {
                for warn in status.warnings() {
                    display_diagnostic(&args.rules_file, warn);
                }
            }
            Err(err) => {
                display_diagnostic(&args.rules_file, &err);
                return ExitCode::FAILURE;
            }
        }

        compiler.into_scanner()
    };

    if args.input.is_dir() {
        let mut walker = WalkDir::new(&args.input).follow_links(!args.no_follow_symlinks);
        if !args.recursive {
            walker = walker.max_depth(1);
        }

        let (thread_pool, sender) = ThreadPool::new(&scanner, &args);

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

            sender.send(entry.path().to_path_buf()).unwrap();
        }

        drop(sender);
        thread_pool.join();

        ExitCode::SUCCESS
    } else {
        match scan_file(&scanner, &args.input, args.print_module_data) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Cannot scan {}: {}", args.input.display(), err);
                ExitCode::FAILURE
            }
        }
    }
}

fn scan_file(scanner: &Scanner, path: &Path, print_module_data: bool) -> std::io::Result<()> {
    let res = scanner.scan_file(path)?;

    if print_module_data {
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

struct ThreadPool {
    threads: Vec<JoinHandle<()>>,
}

impl ThreadPool {
    fn new(scanner: &Scanner, args: &Args) -> (Self, Sender<PathBuf>) {
        let nb_cpus = if let Some(nb) = args.threads {
            std::cmp::min(1, nb)
        } else {
            std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(32)
        };

        let (sender, receiver) = bounded(nb_cpus * 5);
        (
            Self {
                threads: (0..nb_cpus)
                    .map(|_| Self::worker_thread(scanner, &receiver, args))
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
        args: &Args,
    ) -> JoinHandle<()> {
        let scanner = scanner.clone();
        let receiver = receiver.clone();
        let print_module_data = args.print_module_data;

        std::thread::spawn(move || {
            while let Ok(path) = receiver.recv() {
                if let Err(err) = scan_file(&scanner, &path, print_module_data) {
                    eprintln!("Cannot scan file {}: {}", path.display(), err);
                }
            }
        })
    }
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
