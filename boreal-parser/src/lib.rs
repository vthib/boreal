//! Parsing methods for .yar files.
//!
//! This module mainly intends to match the lexical patterns used in libyara.

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
#![allow(clippy::range_plus_one)]
#![allow(clippy::too_many_lines)]

// TODO: To activate before release
// #![deny(clippy::cargo)]

// Parsing uses the [`nom`] crate, adapted for textual parsing.
//
// All of the parsing functions, unless otherwise indicated, depends on the
// following invariants:
// - The received input has already been left-trimmed
// - The returned input is right-trimmed
// The [`nom_recipes::rtrim`] function is provided to make this easier.

mod error;
pub use error::Error;
mod expression;
pub use expression::{
    Expression, ExpressionKind, ForIterator, ForSelection, Identifier, IdentifierOperation,
    IdentifierOperationType, ReadIntegerType, RuleSet, VariableSet,
};
mod file;
pub use file::{YaraFile, YaraFileComponent};
mod hex_string;
pub use hex_string::{HexToken, Jump as HexJump, Mask as HexMask};
mod nom_recipes;
mod number;
mod rule;
pub use rule::{
    Metadata, Rule, VariableDeclaration, VariableDeclarationValue, VariableFlags, VariableModifiers,
};
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
pub fn parse_str(input: &str) -> Result<YaraFile, Error> {
    use nom::Finish;

    let input = types::Input::new(input);
    let (input, rules) = file::parse_yara_file(input).finish()?;

    if !input.cursor().is_empty() {
        let pos = input.get_position();

        return Err(error::Error::new(
            pos..(pos + 1),
            error::ErrorKind::HasTrailingData,
        ));
    }

    Ok(rules)
}

#[cfg(test)]
mod tests;
