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
mod regex;

/// A compiled variable used in a rule.
#[derive(Debug)]
pub struct Variable {
    /// Name of the variable, without the '$'.
    ///
    /// Anonymous variables are just named "".
    pub name: String,

    /// Is the variable marked as private.
    pub is_private: bool,

    /// Set of literals extracted from the variable.
    ///
    /// Will be used by the AC pass to scan for the variable.
    pub literals: Vec<Vec<u8>>,

    /// Flags related to variable modifiers.
    flags: Flags,

    /// Type of matching for the variable.
    matcher_type: MatcherType,

    /// Regex of the non wide version of the regex.
    ///
    /// This is only set for the specific case of a regex variable, with a wide modifier, that
    /// contains word boundaries.
    /// In this case, the regex expression cannot be "widened", and this regex is used to post
    /// check matches.
    non_wide_regex: Option<Regex>,
}

#[derive(Copy, Clone, Debug)]
// Completely useless lint
#[allow(clippy::struct_excessive_bools)]
struct Flags {
    fullword: bool,
    ascii: bool,
    wide: bool,
    nocase: bool,
}

#[derive(Debug)]
enum MatcherType {
    /// The literals cover entirely the variable.
    Literals,
    /// The regex can confirm matches from AC literal matches.
    Atomized {
        left_validator: Option<Regex>,
        right_validator: Option<Regex>,
    },

    /// The regex cannot confirm matches from AC literal matches.
    Raw(Regex),
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

pub(crate) fn compile_variable(decl: VariableDeclaration) -> Result<Variable, CompilationError> {
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
        VariableDeclarationValue::Bytes(s) => Ok(compile_bytes(s, &modifiers)),
        VariableDeclarationValue::Regex(boreal_parser::Regex {
            ast,
            case_insensitive,
            dot_all,
            span: _,
        }) => {
            if case_insensitive {
                modifiers.nocase = true;
            }
            regex::compile_regex(&ast, case_insensitive, dot_all, &modifiers)
        }
        VariableDeclarationValue::HexString(hex_string) => {
            // Fullword and wide is not compatible with hex strings
            modifiers.fullword = false;
            modifiers.wide = false;

            if hex_string::can_use_only_literals(&hex_string) {
                Ok(CompiledVariable {
                    literals: hex_string::hex_string_to_only_literals(hex_string),
                    matcher_type: MatcherType::Literals,
                    non_wide_regex: None,
                })
            } else {
                let ast = hex_string::hex_string_to_ast(hex_string);
                regex::compile_regex(&ast, false, true, &modifiers)
            }
        }
    };

    match res {
        Ok(CompiledVariable {
            literals,
            matcher_type,
            non_wide_regex,
        }) => Ok(Variable {
            name,
            is_private: modifiers.private,
            literals,
            flags: Flags {
                fullword: modifiers.fullword,
                ascii: modifiers.ascii,
                wide: modifiers.wide,
                nocase: modifiers.nocase,
            },
            matcher_type,
            non_wide_regex,
        }),
        Err(error) => Err(CompilationError::VariableCompilation {
            variable_name: name,
            span,
            error,
        }),
    }
}

struct CompiledVariable {
    literals: Vec<Vec<u8>>,
    matcher_type: MatcherType,
    non_wide_regex: Option<Regex>,
}

fn compile_bytes(value: Vec<u8>, modifiers: &VariableModifiers) -> CompiledVariable {
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
        return CompiledVariable {
            literals: new_literals,
            matcher_type: MatcherType::Literals,
            non_wide_regex: None,
        };
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

    CompiledVariable {
        literals,
        matcher_type: MatcherType::Literals,
        non_wide_regex: None,
    }
}

impl Variable {
    /// Confirm that an AC match is a match on the given literal.
    ///
    /// This is needed because the AC might optimize literals and get false positive matches.
    /// This function is used to confirm the tentative match does match the literal with the given
    /// index.
    pub fn confirm_ac_literal(&self, mem: &[u8], mat: &Range<usize>, literal_index: usize) -> bool {
        let literal = &self.literals[literal_index];

        if self.flags.nocase {
            if !literal.eq_ignore_ascii_case(&mem[mat.start..mat.end]) {
                return false;
            }
        } else if literal != &mem[mat.start..mat.end] {
            return false;
        }

        true
    }

    pub fn process_ac_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        mut start_position: usize,
    ) -> AcMatchStatus {
        match &self.matcher_type {
            MatcherType::Literals => match self.validate_and_update_match(mem, mat) {
                Some(m) => AcMatchStatus::Single(m),
                None => AcMatchStatus::None,
            },
            MatcherType::Atomized {
                left_validator,
                right_validator,
            } => {
                let end = match right_validator {
                    Some(validator) => match validator.as_regex().find(&mem[mat.start..]) {
                        Some(m) => mat.start + m.end(),
                        None => return AcMatchStatus::None,
                    },
                    None => mat.end,
                };

                match left_validator {
                    None => {
                        let mat = mat.start..end;
                        match self.validate_and_update_match(mem, mat) {
                            Some(m) => AcMatchStatus::Single(m),
                            None => AcMatchStatus::None,
                        }
                    }
                    Some(validator) => {
                        // The left validator can yield multiple matches.
                        // For example, `a.?bb`, with the `bb` atom, can match as many times as there are
                        // 'a' characters before the `bb` atom.
                        //
                        // XXX: This only works if the left validator does not contain any greedy repetitions!
                        let mut matches = Vec::new();
                        while let Some(m) = validator.as_regex().find(&mem[start_position..mat.end])
                        {
                            let m = (m.start() + start_position)..end;
                            start_position = m.start + 1;
                            if let Some(m) = self.validate_and_update_match(mem, m) {
                                matches.push(m);
                            }
                        }
                        AcMatchStatus::Multiple(matches)
                    }
                }
            }
            MatcherType::Raw(_) => AcMatchStatus::Unknown,
        }
    }

    pub fn find_next_match_at(&self, mem: &[u8], mut offset: usize) -> Option<Range<usize>> {
        let regex = match &self.matcher_type {
            MatcherType::Raw(r) => r,
            _ => {
                // This variable should have been covered by the AC pass, so we should
                // not be able to reach this code.
                debug_assert!(false);
                return None;
            }
        };

        while offset < mem.len() {
            let mat = regex.as_regex().find_at(mem, offset).map(|m| m.range())?;

            match self.validate_and_update_match(mem, mat.clone()) {
                Some(m) => return Some(m),
                None => {
                    offset = mat.start + 1;
                }
            }
        }
        None
    }

    fn validate_and_update_match(&self, mem: &[u8], mat: Range<usize>) -> Option<Range<usize>> {
        if self.flags.fullword && !check_fullword(mem, &mat, self.flags) {
            return None;
        }

        match self.non_wide_regex.as_ref() {
            Some(regex) => apply_wide_word_boundaries(mat, mem, regex),
            None => Some(mat),
        }
    }

    pub fn to_statistics(&self) -> statistics::CompiledString {
        let atoms: Vec<_> = self
            .literals
            .iter()
            .map(|lit| {
                let (start_offset, end_offset) = pick_atom_in_literal(lit);
                lit[start_offset..(lit.len() - end_offset)].to_vec()
            })
            .collect();
        let atoms_quality = atoms_rank(&atoms);

        statistics::CompiledString {
            string_name: self.name.clone(),
            literals: self.literals.clone(),
            atoms,
            atoms_quality,
            matching_kind: match self.matcher_type {
                MatcherType::Literals => MatchingKind::Literals,
                MatcherType::Atomized { .. } => MatchingKind::Atomized,
                MatcherType::Raw(_) => MatchingKind::Regex,
            },
        }
    }
}

/// Check the match respects a possible fullword modifier for the variable.
fn check_fullword(mem: &[u8], mat: &Range<usize>, flags: Flags) -> bool {
    // TODO: We need to know if the match is done on an ascii or wide string to properly check for
    // fullword constraints. This is done in a very ugly way, by going through the match.
    // A better way would be to know which alternation in the match was found.
    let mut match_is_wide = false;

    if flags.wide {
        match_is_wide = is_match_wide(mat, mem);
        if match_is_wide {
            if mat.start > 1
                && mem[mat.start - 1] == b'\0'
                && mem[mat.start - 2].is_ascii_alphanumeric()
            {
                return false;
            }
            if mat.end + 1 < mem.len()
                && mem[mat.end].is_ascii_alphanumeric()
                && mem[mat.end + 1] == b'\0'
            {
                return false;
            }
        }
    }
    if flags.ascii && !match_is_wide {
        if mat.start > 0 && mem[mat.start - 1].is_ascii_alphanumeric() {
            return false;
        }
        if mat.end < mem.len() && mem[mat.end].is_ascii_alphanumeric() {
            return false;
        }
    }

    true
}

/// Check the match respects the word boundaries inside the variable.
fn apply_wide_word_boundaries(
    mut mat: Range<usize>,
    mem: &[u8],
    regex: &Regex,
) -> Option<Range<usize>> {
    // The match can be on a non wide regex, if the variable was both ascii and wide. Make sure
    // the match is wide.
    if !is_match_wide(&mat, mem) {
        return Some(mat);
    }

    // Take the previous and next byte, so that word boundaries placed at the beginning or end of
    // the regex can be checked.
    // Note that we must check that the previous/next byte is "wide" as well, otherwise it is not
    // valid.
    let start = if mat.start >= 2 && mem[mat.start - 1] == b'\0' {
        mat.start - 2
    } else {
        mat.start
    };

    // Remove the wide bytes, and then use the non wide regex to check for word boundaries.
    // Since when checking word boundaries, we might match more than the initial match (because of
    // non greedy repetitions bounded by word boundaries), we need to add more data at the end.
    // How much? We cannot know, but including too much would be too much of a performance tank.
    // This is arbitrarily capped at 500 for the moment (or until the string is no longer wide)...
    let unwiden_mem = unwide(&mem[start..std::cmp::min(mem.len(), mat.end + 500)]);

    #[allow(clippy::bool_to_int_with_if)]
    let expected_start = if start < mat.start { 1 } else { 0 };
    match regex.as_regex().find(&unwiden_mem) {
        Some(m) if m.start() == expected_start => {
            // Modify the match end. This is needed because the application of word boundary
            // may modify the match. Since we matched on non wide mem though, double the size.
            mat.end = mat.start + 2 * (m.end() - m.start());
            Some(mat)
        }
        _ => None,
    }
}

fn unwide(mem: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();

    for b in mem.chunks_exact(2) {
        if b[1] != b'\0' {
            break;
        }
        res.push(b[0]);
    }

    res
}

// Is a match a wide string or an ascii one
fn is_match_wide(mat: &Range<usize>, mem: &[u8]) -> bool {
    if (mat.end - mat.start) % 2 != 0 {
        return false;
    }
    if mat.is_empty() {
        return true;
    }

    !mem[(mat.start + 1)..mat.end]
        .iter()
        .step_by(2)
        .any(|c| *c != b'\0')
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
    /// Error when compiling a regex variable.
    Regex(crate::regex::Error),
}

impl std::fmt::Display for VariableCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
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
        test_type_traits_non_clonable(compile_variable(VariableDeclaration {
            name: "a".to_owned(),
            value: VariableDeclarationValue::Bytes(Vec::new()),
            modifiers: VariableModifiers::default(),
            span: 0..1,
        }));
        test_type_traits_non_clonable(MatcherType::Literals);
        test_type_traits(AcMatchStatus::Unknown);

        test_type_traits_non_clonable(VariableCompilationError::Regex(
            Regex::from_str("{", true, true).unwrap_err(),
        ));
    }
}
