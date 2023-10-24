//! Implement scanning for variables
use std::cmp::Ordering;

use crate::memory::Region;

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
#[derive(Debug)]
pub(crate) struct VarMatches<'a> {
    /// Matches per variable.
    ///
    /// This uses the same order as the variables vec in the scanner object.
    matches: &'a [Vec<StringMatch>],
}

impl<'a> VarMatches<'a> {
    /// Create a new `VarMatches` object from a list of variable matches.
    pub fn new(matches: &'a [Vec<StringMatch>]) -> Self {
        Self { matches }
    }

    /// Return true if the variable can be found in the scanned memory.
    pub fn find(&self, var_index: usize) -> bool {
        !self.matches[var_index].is_empty()
    }

    /// Get a specific match occurrence for the variable.
    ///
    /// This starts at 0, and not at 1 as in the yara file.
    pub fn find_match_occurence(
        &self,
        var_index: usize,
        occurence_number: usize,
    ) -> Option<&StringMatch> {
        self.matches[var_index].get(occurence_number)
    }

    /// Count number of matches.
    pub fn count_matches(&self, var_index: usize) -> u32 {
        // This is safe to allow because the number of matches is guaranteed to be capped by the
        // string_max_nb_matches parameter, which is a u32.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.matches[var_index].len() as u32
        }
    }

    /// Count number of matches in between two bounds.
    pub fn count_matches_in(&self, var_index: usize, from: usize, to: usize) -> u32 {
        // TODO: improve algorithm for searching in matches
        let mut count = 0;
        for mat in &self.matches[var_index] {
            if mat.offset > to {
                return count;
            } else if mat.offset >= from {
                count += 1;
            }
        }

        count
    }

    /// Search occurrence of a variable at a given offset
    pub fn find_at(&self, var_index: usize, offset: usize) -> bool {
        // TODO: improve algorithm for searching in matches
        for mat in &self.matches[var_index] {
            match mat.offset.cmp(&offset) {
                Ordering::Less => (),
                Ordering::Equal => return true,
                Ordering::Greater => return false,
            }
        }

        false
    }

    /// Search occurrence of a variable in between given offset
    pub fn find_in(&self, var_index: usize, from: usize, to: usize) -> bool {
        // TODO: improve algorithm for searching in matches
        for mat in &self.matches[var_index] {
            if mat.offset > to {
                return false;
            } else if mat.offset >= from {
                return true;
            }
        }

        false
    }
}

/// Details on a match on a string during a scan.
#[derive(Clone, Debug)]
pub struct StringMatch {
    /// Offset of the match
    pub offset: usize,

    /// Actual length of the match.
    ///
    /// This is the real length of the match, which might be bigger than the length of `data`.
    pub length: usize,

    /// The matched data.
    ///
    /// The length of this field is capped.
    pub data: Vec<u8>,
}

impl StringMatch {
    pub(crate) fn new(
        region: &Region,
        mat: std::ops::Range<usize>,
        match_max_length: usize,
    ) -> Self {
        let length = mat.end - mat.start;
        let capped_length = std::cmp::min(length, match_max_length);

        Self {
            data: region.mem[mat.start..]
                .iter()
                .take(capped_length)
                .copied()
                .collect(),
            offset: mat.start.saturating_add(region.start),
            length,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(VarMatches { matches: &[] });
        test_type_traits(StringMatch {
            offset: 0,
            length: 0,
            data: Vec::new(),
        });
    }
}
