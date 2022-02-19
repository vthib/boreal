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

// Deny most of allowed by default lints from rustc.
#![deny(explicit_outlives_requirements)]
#![deny(keyword_idents)]
#![deny(macro_use_extern_crate)]
#![deny(missing_docs)]
#![deny(non_ascii_idents)]
#![deny(noop_method_call)]
#![deny(pointer_structural_match)]
#![deny(rust_2021_compatibility)]
#![deny(single_use_lifetimes)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unsafe_code)]
#![deny(unused_crate_dependencies)]
#![deny(unused_extern_crates)]
#![deny(unused_import_braces)]
#![deny(unused_lifetimes)]
#![deny(unused_qualifications)]
#![deny(unused_results)]
// Do the same for clippy
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::match_same_arms)]

// TODO: To activate before release
// #![deny(clippy::cargo)]

mod error;
pub use error::Error;
mod expression;
pub use expression::Expression;
mod hex_string;
mod nom_recipes;
mod number;
mod rule;
pub use rule::{Metadata, Rule, VariableDeclaration, VariableDeclarationValue, VariableModifiers};
mod string;
pub use string::Regex;
mod types;

/// Parse a YARA file.
///
/// Returns the list of rules declared in the file.
///
/// # Errors
///
/// Returns an error if the parsing fails, or if there are
/// trailing data in the file that has not been parsed.
pub fn parse_str(input: &str) -> Result<Vec<Rule>, Error> {
    use nom::Finish;

    let input = types::Input::new(input);
    let (input, rules) = rule::parse_yara_file(input).finish()?;

    if !input.cursor().is_empty() {
        let pos = input.get_position();

        return Err(error::Error::new(
            types::Span {
                start: pos,
                end: pos + 1,
            },
            error::ErrorKind::HasTrailingData,
        ));
    }

    Ok(rules)
}

#[cfg(test)]
mod tests;
