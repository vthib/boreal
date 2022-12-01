//! **boreal** is a YARA rules evaluator, used to search for textual and binary patterns.
//!
//! This crate is a reimplementation of the [YARA library](https://github.com/VirusTotal/yara).
//! It aims to provide the same set of functionalities, and be fully compatible with all existing
//! YARA rules.
//!
//! Here is an example on how to use the library.
//!
//! ```
//! use boreal::Compiler;
//!
//! // Rules must first be added to a compiler.
//! let mut compiler = Compiler::new();
//! compiler.add_rules_str(r#"
//! rule example {
//!     meta:
//!         description = "This is an YARA rule example"
//!         date = "2022-11-11"
//!     strings:
//!         $s1 = { 78 6d 6c 68 74 74 70 2e 73 65 6e 64 28 29 }
//!         $s2 = "tmp.dat" fullword wide
//!     condition:
//!         any of them
//! }
//! "#)?;
//!
//! // Then, all added rules are compiled into a scanner object.
//! let scanner = compiler.into_scanner();
//!
//! // Use this object to scan strings or files.
//! let res = scanner.scan_mem(b"<\0t\0m\0p\0.\0d\0a\0t\0>\0");
//! assert!(res.matched_rules.iter().any(|rule| rule.name == "example"));
//!
//! # Ok::<(), boreal::compiler::AddRuleError>(())
//! ```

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
#![allow(clippy::too_many_lines)]
#![allow(clippy::single_match_else)]
// Would be nice to not need this, thanks macho module
#![allow(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::cargo)]

// Used in integration tests, not in the library.
// This is to remove the "unused_crate_dependencies" warning, maybe a better solution
// could be found.
#[cfg(test)]
use base64 as _;
#[cfg(test)]
use const_format as _;
#[cfg(test)]
use glob as _;
#[cfg(test)]
use tempfile as _;
#[cfg(test)]
use walkdir as _;
#[cfg(test)]
use yara as _;

// Used in benches
#[cfg(feature = "bench")]
use criterion as _;

pub mod compiler;
pub use compiler::Compiler;
mod evaluator;
mod limits;
pub mod module;
pub mod regex;
pub mod scanner;
pub use scanner::Scanner;

#[cfg(test)]
mod test_helpers;
