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
//! let res = scanner.scan_mem(b"<\0t\0m\0p\0.\0d\0a\0t\0>\0").unwrap();
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
#![deny(unsafe_op_in_unsafe_fn)]
// Do the same for clippy
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::undocumented_unsafe_blocks)]
// Allow some useless pedantic lints
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::unnested_or_patterns)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::single_match_else)]
#![allow(clippy::inline_always)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::cargo)]
// Handled by cargo-deny
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

// Used in integration tests, not in the library.
// This is to remove the "unused_crate_dependencies" warning, maybe a better solution
// could be found.
#[cfg(test)]
use base64 as _;
#[cfg(test)]
use glob as _;
#[cfg(test)]
use tempfile as _;
#[cfg(test)]
use yara as _;

// If the "hash" feature is enabled but not the "object" feature, the tlsh2 crate
// is added but unused, Since it depends on both being enabled. I don't think
// there is a way to express this in the cargo dependencies, and this dependency
// is extremely light, so it is just ignored in this case.
#[cfg(all(feature = "hash", not(feature = "object")))]
use tlsh2 as _;

pub(crate) mod atoms;
mod bitmaps;
pub mod compiler;
pub use compiler::Compiler;
mod evaluator;
mod matcher;
pub mod memory;
pub mod module;
pub mod regex;
pub mod scanner;
pub use scanner::Scanner;
pub mod statistics;
mod timeout;

// Re-exports those symbols since they are exposed in the results of a scan. This avoids
// having to depend on boreal-parser simply to match on those metadatas.
pub use boreal_parser::rule::{Metadata, MetadataValue};

#[cfg(test)]
mod test_helpers;
