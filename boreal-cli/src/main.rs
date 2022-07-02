use std::path::PathBuf;
use std::process::exit;

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
    for rule in res.matched_rules {
        println!("{} {}", &rule.name, args.file.display());
    }

    Ok(())
}
