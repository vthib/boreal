//! Parsing methods for .yar files.
//!
//! This module mainly intends to match the lexical patterns used in libyara.
//!
//! All of the parsing functions, unless otherwise indicated, depends on the
//! following invariants:
//! - The received input has already been left-trimmed
//! - The returned input is right-trimmed
//! The [`nom_recipes::rtrim`] function is provided to make this easier.
//!
//! Progress:
//! [x] hex strings initial impl is complete, need integration testing.
//! [ ] re strings needs to be investigated.
//! [ ] yar files are in progress.
//!   lexer:
//!     [x] identifiers
//!     [x] strings
//!     [x] regexes
//!     [ ] includes
//!   parser:
//!     [ ] all
//!
//! TODO:
//! [ ] check error reporting
//! [ ] replace `from_external_error` with a custom err: the desc is dropped
//!     by nom...
use std::path::Path;

use nom::Finish;

mod expression;
mod hex_string;
mod nom_recipes;
mod number;
mod rule;
mod string;

/// Parse a YARA file.
///
/// Returns the list of rules declared in the file.
///
/// # Errors
///
/// Returns an error if the parsing fails, or if there are
/// trailing data in the file that has not been parsed.
// FIXME: do not return a box error
pub fn parse_file<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<crate::rule::Rule>, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;

    // FIXME: work on the error reporting...
    match rule::parse_yara_file(&contents).finish() {
        Err(e) => Err(format!("parsing error: {:?}", e).into()),
        Ok((input, _)) if !input.is_empty() => {
            Err(format!("yara files has trailing data: {}", input).into())
        }
        Ok((_, rules)) => Ok(rules),
    }
}

#[cfg(test)]
mod tests;
