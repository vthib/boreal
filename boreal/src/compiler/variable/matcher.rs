use std::ops::Range;

use crate::regex::Regex;

use super::AcMatchStatus;

pub mod raw;
pub mod validator;
mod widener;

const MAX_SPLIT_MATCH_LENGTH: usize = 4096;

#[derive(Debug)]
pub struct Matcher {
    /// Set of literals extracted from the variable.
    ///
    /// Will be used by the AC pass to scan for the variable.
    ///
    /// If both ascii and wide are set in the flags, it is expected that the literals are
    /// composed of:
    /// - the ascii literals first
    /// - the wide literals second
    ///
    /// This is required in order to know which kind is a literal match, as checking its value
    /// would be buggy.
    pub literals: Vec<Vec<u8>>,

    /// Flags related to variable modifiers.
    pub flags: Flags,

    pub kind: MatcherKind,

    /// Regex of the non wide version of the regex.
    ///
    /// This is only set for the specific case of a regex variable, with a wide modifier, that
    /// contains word boundaries.
    /// In this case, the regex expression cannot be "widened", and this regex is used to post
    /// check matches.
    pub non_wide_regex: Option<Regex>,
}

#[derive(Copy, Clone, Debug)]
pub struct Flags {
    pub fullword: bool,
    pub ascii: bool,
    pub wide: bool,
    pub nocase: bool,
}

#[derive(Debug)]
pub enum MatcherKind {
    /// The literals cover entirely the variable.
    Literals,
    /// The regex can confirm matches from AC literal matches.
    Atomized {
        left_validator: Option<validator::Validator>,
        right_validator: Option<validator::Validator>,
    },

    /// The regex cannot confirm matches from AC literal matches.
    Raw(raw::RawMatcher),
}

/// Type of a match.
#[derive(Copy, Clone, Debug)]
pub enum MatchType {
    /// The match is on ascii versions of the literals
    Ascii,
    /// The match is on wide versions of the literals
    Wide,
}

impl Matcher {
    /// Confirm that an AC match is a match on the given literal.
    ///
    /// This is needed because the AC might optimize literals and get false positive matches.
    /// This function is used to confirm the tentative match does match the literal with the given
    /// index.
    pub fn confirm_ac_literal(
        &self,
        mem: &[u8],
        mat: &Range<usize>,
        literal_index: usize,
    ) -> Option<MatchType> {
        let literal = &self.literals[literal_index];

        if self.flags.nocase {
            if !literal.eq_ignore_ascii_case(&mem[mat.start..mat.end]) {
                return None;
            }
        } else if literal != &mem[mat.start..mat.end] {
            return None;
        }

        match (self.flags.ascii, self.flags.wide) {
            (false, true) => Some(MatchType::Wide),
            // If the variable has both ascii and wide, then the ascii literals are in the first
            // half, and the wide ones in the second half.
            (true, true) if literal_index >= self.literals.len() / 2 => Some(MatchType::Wide),
            _ => Some(MatchType::Ascii),
        }
    }

    pub fn process_ac_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
        match_type: MatchType,
    ) -> AcMatchStatus {
        match &self.kind {
            MatcherKind::Literals => match self.validate_and_update_match(mem, mat, match_type) {
                Some(m) => AcMatchStatus::Single(m),
                None => AcMatchStatus::None,
            },
            MatcherKind::Atomized {
                left_validator,
                right_validator,
            } => {
                let end = match right_validator {
                    Some(validator) => {
                        let end = std::cmp::min(
                            mem.len(),
                            mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH),
                        );
                        match validator.find_anchored_fwd(mem, mat.start, end) {
                            Some(m) => m.end,
                            None => return AcMatchStatus::None,
                        }
                    }
                    None => mat.end,
                };

                match left_validator {
                    None => {
                        let mat = mat.start..end;
                        match self.validate_and_update_match(mem, mat, match_type) {
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
                        let mut start = std::cmp::max(
                            start_position,
                            mat.end.saturating_sub(MAX_SPLIT_MATCH_LENGTH),
                        );
                        while let Some(m) = validator.find(&mem[start..mat.end]) {
                            let m = (m.start + start)..end;
                            start = m.start + 1;
                            if let Some(m) = self.validate_and_update_match(mem, m, match_type) {
                                matches.push(m);
                            }
                        }
                        AcMatchStatus::Multiple(matches)
                    }
                }
            }
            MatcherKind::Raw(_) => AcMatchStatus::Unknown,
        }
    }

    pub fn find_next_match_at(&self, mem: &[u8], mut offset: usize) -> Option<Range<usize>> {
        let regex = match &self.kind {
            MatcherKind::Raw(r) => r,
            _ => {
                // This variable should have been covered by the AC pass, so we should
                // not be able to reach this code.
                debug_assert!(false);
                return None;
            }
        };

        while offset < mem.len() {
            let (mat, match_type) = regex.find_next_match_at(mem, offset, self.flags)?;

            match self.validate_and_update_match(mem, mat.clone(), match_type) {
                Some(m) => return Some(m),
                None => {
                    offset = mat.start + 1;
                }
            }
        }
        None
    }

    fn validate_and_update_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        match_type: MatchType,
    ) -> Option<Range<usize>> {
        if self.flags.fullword && !check_fullword(mem, &mat, match_type) {
            return None;
        }

        match self.non_wide_regex.as_ref() {
            Some(regex) => apply_wide_word_boundaries(mat, mem, regex, match_type),
            None => Some(mat),
        }
    }
}

/// Check the match respects a possible fullword modifier for the variable.
fn check_fullword(mem: &[u8], mat: &Range<usize>, match_type: MatchType) -> bool {
    match match_type {
        MatchType::Wide => {
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
        MatchType::Ascii => {
            if mat.start > 0 && mem[mat.start - 1].is_ascii_alphanumeric() {
                return false;
            }
            if mat.end < mem.len() && mem[mat.end].is_ascii_alphanumeric() {
                return false;
            }
        }
    }

    true
}

/// Check the match respects the word boundaries inside the variable.
fn apply_wide_word_boundaries(
    mut mat: Range<usize>,
    mem: &[u8],
    regex: &Regex,
    match_type: MatchType,
) -> Option<Range<usize>> {
    if !matches!(match_type, MatchType::Wide) {
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
    match regex.find(&unwiden_mem) {
        Some(m) if m.start == expected_start => {
            // Modify the match end. This is needed because the application of word boundary
            // may modify the match. Since we matched on non wide mem though, double the size.
            mat.end = mat.start + 2 * (m.end - m.start);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(Matcher {
            literals: vec![],
            flags: Flags {
                fullword: false,
                ascii: false,
                wide: false,
                nocase: false,
            },
            kind: MatcherKind::Literals,
            non_wide_regex: None,
        });
        test_type_traits_non_clonable(MatcherKind::Literals);
        test_type_traits(Flags {
            fullword: false,
            ascii: false,
            wide: false,
            nocase: false,
        });
        test_type_traits(MatchType::Ascii);
    }
}
