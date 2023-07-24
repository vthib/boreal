use std::ops::Range;

use boreal_parser::VariableModifiers;
use boreal_parser::{VariableDeclaration, VariableDeclarationValue};

use crate::atoms::{atoms_rank, pick_atom_in_literal};
use crate::statistics;

use super::base64::encode_base64;
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
        VariableDeclarationValue::Bytes(s) => compile_bytes(s, &modifiers),
        VariableDeclarationValue::Regex(boreal_parser::Regex {
            ast,
            case_insensitive,
            dot_all,
            span: _,
        }) => {
            if case_insensitive {
                modifiers.nocase = true;
            }
            matcher::Matcher::new(
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
        VariableDeclarationValue::HexString(hex_string) => matcher::Matcher::new(
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

fn compile_bytes(
    value: Vec<u8>,
    modifiers: &VariableModifiers,
) -> Result<matcher::Matcher, VariableCompilationError> {
    if value.is_empty() {
        return Err(VariableCompilationError::Empty);
    }

    let mut literals = Vec::with_capacity(2);
    if modifiers.wide {
        if modifiers.ascii {
            let wide = string_to_wide(&value);
            literals.push(value);
            literals.push(wide);
        } else {
            literals.push(string_to_wide(&value));
        }
    } else {
        literals.push(value);
    }

    if let Some(xor_range) = modifiers.xor {
        // For each literal, for each byte in the xor range, build a new literal
        let xor_range = xor_range.0..=xor_range.1;
        let xor_range_len = xor_range.len(); // modifiers.xor_range.1.saturating_sub(modifiers.xor_range.0) + 1;
        let mut new_literals: Vec<Vec<u8>> = Vec::with_capacity(literals.len() * xor_range_len);

        // Ascii literals must be first, then wide literals. Since the "literals" var
        // is the ascii literals then the wide ones, the order is preserved.
        for lit in literals {
            for xor_byte in xor_range.clone() {
                new_literals.push(lit.iter().map(|c| c ^ xor_byte).collect());
            }
        }
        return Ok(matcher::Matcher {
            literals: new_literals,
            kind: matcher::MatcherKind::Literals,
            modifiers: matcher::Modifiers {
                fullword: modifiers.fullword,
                wide: modifiers.wide,
                ascii: modifiers.ascii,
                nocase: modifiers.nocase,
                dot_all: false,
            },
        });
    }

    if let Some(base64) = &modifiers.base64 {
        let mut old_literals = Vec::with_capacity(literals.len() * 3);
        std::mem::swap(&mut old_literals, &mut literals);

        if base64.ascii {
            for lit in &old_literals {
                for offset in 0..=2 {
                    if let Some(lit) = encode_base64(lit, &base64.alphabet, offset) {
                        // Fullword is not compatible with base64 modifiers, hence ordering of
                        // literals is not required.
                        if base64.wide {
                            literals.push(string_to_wide(&lit));
                        }
                        literals.push(lit);
                    }
                }
            }
        } else {
            for lit in &old_literals {
                for offset in 0..=2 {
                    if let Some(lit) = encode_base64(lit, &base64.alphabet, offset) {
                        literals.push(string_to_wide(&lit));
                    }
                }
            }
        }
    }

    Ok(matcher::Matcher {
        literals,
        kind: matcher::MatcherKind::Literals,
        modifiers: matcher::Modifiers {
            fullword: modifiers.fullword,
            wide: modifiers.wide,
            ascii: modifiers.ascii,
            nocase: modifiers.nocase,
            dot_all: false,
        },
    })
}

/// Convert an ascii string to a wide string
fn string_to_wide(s: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(s.len() * 2);
    for b in s {
        res.push(*b);
        res.push(b'\0');
    }
    res
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
