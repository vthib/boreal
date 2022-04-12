//! TODO doc

// Deny most of allowed by default lints from rustc.
#![deny(explicit_outlives_requirements)]
#![deny(keyword_idents)]
#![deny(macro_use_extern_crate)]
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
#![allow(clippy::unnested_or_patterns)]
#![allow(clippy::match_same_arms)]

// TODO: To activate before release
// #![deny(missing_docs)]
// #![deny(clippy::cargo)]

// Used in integration tests, not in the library.
// This is to remove the "unused_crate_dependencies" warning, maybe a better solution
// could be found.
#[cfg(test)]
use base64 as _;
#[cfg(test)]
use const_format as _;
#[cfg(test)]
use yara as _;

mod compiler;
mod evaluator;
pub mod module;
mod scanner;
pub use scanner::{AddRuleError, Scanner};
