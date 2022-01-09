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
//! Not handled:
//! [ ] string modifiers xor range and base64 alphabet.
//!
//! TODO:
//! [ ] check error reporting
//! [ ] replace `from_external_error` with a custom err: the desc is dropped
//!     by nom...

mod expression;
mod hex_string;
mod nom_recipes;
mod number;
mod rule;
mod string;

#[cfg(test)]
mod test_utils;
