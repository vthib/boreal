//! Parser for YARA rules.
//!
//! This crate is designed to be used by the [`boreal` crate](https://docs.rs/boreal/%2A/boreal/).
//!
//! It exposes a main entrypoint function, [`parse`], which parses the contents of a YARA file.
//!
//! ```rust
//! use boreal_parser::*;
//! use boreal_parser::expression::*;
//! use boreal_parser::file::*;
//! use boreal_parser::rule::*;
//!
//! let file = parse(r#"
//! import "pe"
//!
//! private rule b : tag1 {
//!     meta:
//!         a = true
//!     strings:
//!         $b = "\\mspaint.exe" wide
//!     condition:
//!         pe.is_dll() and all of them
//! }"#)?;
//!
//! assert_eq!(
//!     file.components[0],
//!     YaraFileComponent::Import(Import {
//!         name: "pe".to_owned(),
//!         span: 1..12,
//!     })
//! );
//! assert_eq!(
//!     file.components[1],
//!     YaraFileComponent::Rule(Box::new(Rule {
//!         name: "b".to_owned(),
//!         name_span: 27..28,
//!         tags: vec![RuleTag {
//!             tag: "tag1".to_owned(),
//!             span: 31..35
//!         }],
//!         metadatas: vec![Metadata {
//!             name: "a".to_owned(),
//!             value: MetadataValue::Boolean(true)
//!         }],
//!         variables: vec![VariableDeclaration {
//!             name: "b".to_owned(),
//!             value: VariableDeclarationValue::Bytes(b"\\mspaint.exe".to_vec()),
//!             modifiers: VariableModifiers {
//!                 wide: true,
//!                 ..Default::default()
//!             },
//!             span: 86..111,
//!         }],
//!
//!         condition: Expression {
//!             expr: ExpressionKind::And(vec![
//!                 Expression {
//!                     expr: ExpressionKind::Identifier(Identifier {
//!                         name: "pe".to_owned(),
//!                         name_span: 135..137,
//!                         operations: vec![
//!                             IdentifierOperation {
//!                                 op: IdentifierOperationType::Subfield(
//!                                     "is_dll".to_owned()
//!                                 ),
//!                                 span: 137..144,
//!                             },
//!                             IdentifierOperation {
//!                                 op: IdentifierOperationType::FunctionCall(vec![]),
//!                                 span: 144..146,
//!                             }
//!                         ],
//!                     }),
//!                     span: 135..146,
//!                 },
//!                 Expression {
//!                     expr: ExpressionKind::For {
//!                         selection: ForSelection::All,
//!                         set: VariableSet { elements: vec![] },
//!
//!                         body: None,
//!                     },
//!                     span: 151..162,
//!                 }
//!             ]),
//!             span: 135..162
//!         },
//!         is_private: true,
//!         is_global: false,
//!     }))
//! );
//!
//! # Ok::<(), boreal_parser::error::Error>(())
//! ```

// Deny most of allowed by default lints from rustc.
#![deny(explicit_outlives_requirements)]
#![deny(keyword_idents)]
#![deny(macro_use_extern_crate)]
#![deny(missing_docs)]
#![deny(non_ascii_idents)]
#![deny(noop_method_call)]
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
// Allow some useless pedantic lints
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::range_plus_one)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::single_match_else)]
#![allow(clippy::struct_field_names)]
#![deny(clippy::cargo)]

// Parsing uses the [`nom`] crate, adapted for textual parsing.
//
// All of the parsing functions, unless otherwise indicated, depends on the
// following invariants:
// - The received input has already been left-trimmed
// - The returned input is right-trimmed
// The [`nom_recipes::rtrim`] function is provided to make this easier.

pub mod error;
pub mod expression;
pub mod file;
pub mod hex_string;
mod nom_recipes;
mod number;
pub mod regex;
pub mod rule;
mod string;
mod types;

/// Parse a YARA file.
///
/// # Errors
///
/// Returns an error if the parsing fails, or if there are
/// trailing data in the file that has not been parsed.
pub fn parse(input: &str) -> Result<file::YaraFile, error::Error> {
    use nom::Finish;

    let input = types::Input::new(input);
    let (_, rules) = file::parse_yara_file(input).finish()?;

    Ok(rules)
}

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_str() {
        assert!(parse("  global rule c { condition: false }").is_ok());
        assert!(parse("  global rule c { condtion: false }").is_err());
    }
}
