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
//! let scanner = compiler.finalize();
//!
//! // Use this object to scan strings or files.
//! let res = scanner.scan_mem(b"<\0t\0m\0p\0.\0d\0a\0t\0>\0").unwrap();
//! assert!(res.rules.iter().any(|rule| rule.name == "example"));
//!
//! # Ok::<(), boreal::compiler::AddRuleError>(())
//! ```

#![allow(unsafe_code)]
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
mod bytes_pool;
pub use bytes_pool::{BytesSymbol, StringSymbol};
pub mod compiler;
pub use compiler::rule::{Metadata, MetadataValue};
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
#[cfg(feature = "serialize")]
mod wire;

#[cfg(test)]
mod test_helpers;
