use std::path::PathBuf;
use std::process::exit;

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
    match boreal::parser::parse_str(&contents) {
        Err(err) => {
            let writer = StandardStream::stderr(ColorChoice::Always);
            let config = codespan_reporting::term::Config::default();

            let files = SimpleFile::new(yara_filepath, &contents);
            for diag in err.get_diagnostics() {
                if let Err(e) = term::emit(&mut writer.lock(), &config, &files, &diag) {
                    eprintln!("cannot emit diagnostics: {}", e);
                }
            }
            exit(2);
        }
        Ok(rules) => {
            println!(
                "successfully parsed {} rules from {}",
                rules.len(),
                path.display()
            );
        }
    }
    Ok(())
}