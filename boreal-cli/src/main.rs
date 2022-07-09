use std::path::PathBuf;
use std::process::exit;

use boreal::module::Value as ModuleValue;
use boreal::Compiler;

use clap::Parser;
use codespan_reporting::{
    files::SimpleFile,
    term::{
        self,
        termcolor::{ColorChoice, StandardStream},
    },
};

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    /// Path to a yara file containing rules.
    #[clap(value_parser)]
    rules_file: PathBuf,

    /// Input to scan.
    #[clap(value_parser)]
    file: PathBuf,

    /// Print module data.
    #[clap(short = 'D', long, value_parser)]
    print_module_data: bool,
}

fn main() -> Result<(), std::io::Error> {
    let args = Args::parse();

    let scanner = {
        let rules_contents = std::fs::read_to_string(&args.rules_file)?;

        let mut compiler = Compiler::new();
        if let Err(err) = compiler.add_rules_str(&rules_contents) {
            let writer = StandardStream::stderr(ColorChoice::Always);
            let config = codespan_reporting::term::Config::default();

            let path = args.rules_file.display().to_string();
            let files = SimpleFile::new(&path, &rules_contents);
            let diag = err.to_diagnostic();
            if let Err(e) = term::emit(&mut writer.lock(), &config, &files, &diag) {
                eprintln!("cannot emit diagnostics: {}", e);
            }
            exit(2);
        }

        compiler.into_scanner()
    };

    let file_contents = std::fs::read(&args.file)?;
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
        println!("{} {}", &rule.name, args.file.display());
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
        ModuleValue::Regex(regex) => println!(" = /{}/", regex.as_str()),
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
