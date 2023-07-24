use std::ops::Range;

use boreal_parser::{VariableDeclaration, VariableDeclarationValue};

use crate::atoms::{atoms_rank, pick_atom_in_literal};
use crate::statistics;

use super::CompilationError;

mod analysis;
mod literals;
mod matcher;
mod only_literals;

// Maximum length against which a regex validator of a AC literal match will be run.
//
// For example, lets say you have the `{ AA [1-] BB CC DD [1-] FF }` hex string. The
// `\xbb\xcc\xdd` literal is extracted, with:
// - the pre validator `\xaa.{1,}?\xbb\xcc\xdd$`
// - the post validator `^\xbb\xcc\xdd.{1,}?\xff`
//
// Both the pre and post validator will be run against a slice which maximum length is
// limited by the constant. Which means that `\xaa0\xbb\xcc\xdd` + ('0' * MAX+1) + '\xff'
// will not match.
/// A compiled variable used in a rule.
#[derive(Debug)]
pub struct Variable {
    /// Name of the variable, without the '$'.
    ///
    /// Anonymous variables are just named "".
    pub name: String,

    /// Is the variable marked as private.
    pub is_private: bool,

    /// Matcher for the variable.
    pub(crate) matcher: matcher::Matcher,
}

/// State of an aho-corasick match on a [`Matcher`] literals.
#[derive(Clone, Debug)]
pub enum AcMatchStatus {
    /// The literal yields multiple matches (can be empty).
    Multiple(Vec<Range<usize>>),

    /// The literal yields a single match (None if invalid).
    ///
    /// This is an optim to avoid allocating a Vec for the very common case of returning a
    /// single match.
    Single(Range<usize>),

    /// The literal does not give any match.
    None,

    /// Unknown status for the match, will need to be confirmed on its own.
    Unknown,
}

pub(crate) fn compile_variable(
    decl: VariableDeclaration,
    parsed_contents: &str,
    compute_statistics: bool,
) -> Result<(Variable, Option<statistics::CompiledString>), CompilationError> {
    let VariableDeclaration {
        name,
        value,
        mut modifiers,
        span,
    } = decl;

    if !modifiers.wide {
        modifiers.ascii = true;
    }

    let res = match value {
        VariableDeclarationValue::Bytes(s) => {
            if s.is_empty() {
                Err(VariableCompilationError::Empty)
            } else {
                Ok(matcher::Matcher::new_bytes(s, &modifiers))
            }
        }
        VariableDeclarationValue::Regex(boreal_parser::Regex {
            ast,
            case_insensitive,
            dot_all,
            span: _,
        }) => {
            if case_insensitive {
                modifiers.nocase = true;
            }
            matcher::Matcher::new_regex(
                &ast.into(),
                matcher::Modifiers {
                    fullword: modifiers.fullword,
                    wide: modifiers.wide,
                    ascii: modifiers.ascii,
                    nocase: modifiers.nocase,
                    dot_all,
                },
            )
            .map_err(VariableCompilationError::Regex)
        }
        VariableDeclarationValue::HexString(hex_string) => matcher::Matcher::new_regex(
            &hex_string.into(),
            matcher::Modifiers {
                fullword: modifiers.fullword,
                wide: modifiers.wide,
                ascii: modifiers.ascii,
                nocase: modifiers.nocase,
                dot_all: true,
            },
        )
        .map_err(VariableCompilationError::Regex),
    };

    let res = match res {
        Ok(matcher) => Variable {
            name,
            is_private: modifiers.private,
            matcher,
        },
        Err(error) => {
            return Err(CompilationError::VariableCompilation {
                variable_name: name,
                span,
                error,
            })
        }
    };

    let stats = if compute_statistics {
        let atoms: Vec<_> = res
            .matcher
            .literals
            .iter()
            .map(|lit| {
                let (start_offset, end_offset) = pick_atom_in_literal(lit);
                lit[start_offset..(lit.len() - end_offset)].to_vec()
            })
            .collect();
        let atoms_quality = atoms_rank(&atoms);

        Some(statistics::CompiledString {
            name: res.name.clone(),
            expr: parsed_contents[span.start..span.end].to_owned(),
            literals: res.matcher.literals.clone(),
            atoms,
            atoms_quality,
            matching_algo: match res.matcher.kind {
                matcher::MatcherKind::Literals => "literals",
                matcher::MatcherKind::Atomized { .. } => "atomized",
                matcher::MatcherKind::Raw(_) => "raw",
            }
            .into(),
        })
    } else {
        None
    };

    Ok((res, stats))
}

/// Error during the compilation of a variable.
#[derive(Debug)]
pub enum VariableCompilationError {
    /// Variable is empty.
    Empty,

    /// Error when compiling a regex variable.
    Regex(crate::regex::Error),
}

impl std::fmt::Display for VariableCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "variable is empty"),
            Self::Regex(e) => e.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use boreal_parser::VariableModifiers;

    use super::*;
    use crate::{
        regex::Regex,
        test_helpers::{test_type_traits, test_type_traits_non_clonable},
    };

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(
            compile_variable(
                VariableDeclaration {
                    name: "a".to_owned(),
                    value: VariableDeclarationValue::Bytes(b"foo".to_vec()),
                    modifiers: VariableModifiers::default(),
                    span: 0..1,
                },
                "",
                false,
            )
            .unwrap()
            .0,
        );
        test_type_traits(AcMatchStatus::Unknown);

        test_type_traits_non_clonable(VariableCompilationError::Regex(
            Regex::from_string("{".to_owned(), true, true).unwrap_err(),
        ));
    }
}
