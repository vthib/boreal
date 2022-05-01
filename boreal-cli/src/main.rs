use std::path::PathBuf;
use std::process::exit;

use boreal::Compiler;
use codespan_reporting::{
    files::SimpleFile,
    term::{
        self,
        termcolor::{ColorChoice, StandardStream},
    },
};

fn main() -> Result<(), std::io::Error> {
    // TODO: make a proper binary with proper parameters
    let yara_filepath = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("give a path to a yara file as argument to this binary");
        exit(1);
    });

    let path = PathBuf::from(&yara_filepath);
    let contents = std::fs::read_to_string(&path)?;

    let mut compiler = Compiler::new();
    match compiler.add_rules_str(&contents) {
        Err(err) => {
            let writer = StandardStream::stderr(ColorChoice::Always);
            let config = codespan_reporting::term::Config::default();

            let files = SimpleFile::new(yara_filepath, &contents);
            let diag = err.to_diagnostic();
            if let Err(e) = term::emit(&mut writer.lock(), &config, &files, &diag) {
                eprintln!("cannot emit diagnostics: {}", e);
            }
            exit(2);
        }
        Ok(_) => {
            println!("successfully added rules from {}", path.display());
        }
    }
    Ok(())
}
