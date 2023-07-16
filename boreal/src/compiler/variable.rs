use std::ops::Range;

use boreal_parser::VariableModifiers;
use boreal_parser::{VariableDeclaration, VariableDeclarationValue};

use crate::atoms::{atoms_rank, pick_atom_in_literal};
use crate::regex::Regex;
use crate::statistics::{self, MatchingKind};

use super::base64::encode_base64;
use super::CompilationError;

mod hex_string;
mod literals;
mod matcher;
mod regex;

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
    pub matcher: matcher::Matcher,
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
            regex::compile_regex(&ast.into(), dot_all, &modifiers)
        }
        VariableDeclarationValue::HexString(hex_string) => {
            // Nocase, fullword and wide is not compatible with hex strings
            modifiers.nocase = false;
            modifiers.fullword = false;
            modifiers.wide = false;

            if hex_string::can_use_only_literals(&hex_string) {
                Ok(CompiledVariable {
                    literals: hex_string::hex_string_to_only_literals(hex_string),
                    matcher_kind: matcher::MatcherKind::Literals,
                    non_wide_regex: None,
                })
            } else {
                let hir = hex_string.into();
                regex::compile_regex(&hir, true, &modifiers)
            }
        }
    };

    let res = match res {
        Ok(CompiledVariable {
            literals,
            matcher_kind,
            non_wide_regex,
        }) => Variable {
            name,
            is_private: modifiers.private,
            matcher: matcher::Matcher {
                literals,
                flags: matcher::Flags {
                    fullword: modifiers.fullword,
                    ascii: modifiers.ascii,
                    wide: modifiers.wide,
                    nocase: modifiers.nocase,
                },
                kind: matcher_kind,
                non_wide_regex,
            },
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
            matching_kind: match res.matcher.kind {
                matcher::MatcherKind::Literals => MatchingKind::Literals,
                matcher::MatcherKind::Atomized { .. } => MatchingKind::Atomized,
                matcher::MatcherKind::Raw(_) => MatchingKind::Regex,
            },
        })
    } else {
        None
    };

    Ok((res, stats))
}

struct CompiledVariable {
    literals: Vec<Vec<u8>>,
    matcher_kind: matcher::MatcherKind,
    non_wide_regex: Option<Regex>,
}

fn compile_bytes(
    value: Vec<u8>,
    modifiers: &VariableModifiers,
) -> Result<CompiledVariable, VariableCompilationError> {
    if value.is_empty() {
        return Err(VariableCompilationError::Empty);
    }

    let mut literals = Vec::with_capacity(2);
    if modifiers.wide {
        if modifiers.ascii {
            literals.push(string_to_wide(&value));
            literals.push(value);
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
        for lit in literals {
            for xor_byte in xor_range.clone() {
                new_literals.push(lit.iter().map(|c| c ^ xor_byte).collect());
            }
        }
        return Ok(CompiledVariable {
            literals: new_literals,
            matcher_kind: matcher::MatcherKind::Literals,
            non_wide_regex: None,
        });
    }

    if let Some(base64) = &modifiers.base64 {
        let mut old_literals = Vec::with_capacity(literals.len() * 3);
        std::mem::swap(&mut old_literals, &mut literals);

        if base64.ascii {
            for lit in &old_literals {
                for offset in 0..=2 {
                    if let Some(lit) = encode_base64(lit, &base64.alphabet, offset) {
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

    Ok(CompiledVariable {
        literals,
        matcher_kind: matcher::MatcherKind::Literals,
        non_wide_regex: None,
    })
}

impl Variable {
    /// Confirm that an AC match is a match on the given literal.
    ///
    /// This is needed because the AC might optimize literals and get false positive matches.
    /// This function is used to confirm the tentative match does match the literal with the given
    /// index.
    pub fn confirm_ac_literal(&self, mem: &[u8], mat: &Range<usize>, literal_index: usize) -> bool {
        self.matcher.confirm_ac_literal(mem, mat, literal_index)
    }

    pub fn process_ac_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
    ) -> AcMatchStatus {
        self.matcher.process_ac_match(mem, mat, start_position)
    }

    pub fn find_next_match_at(&self, mem: &[u8], offset: usize) -> Option<Range<usize>> {
        self.matcher.find_next_match_at(mem, offset)
    }
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
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

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
