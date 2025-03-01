//! Implement scanning for variables
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
        // Find the idx of the first match which starts after from
        let start_idx = match self.matches[var_index]
            .binary_search_by_key(&from, |mat| mat.offset.saturating_add(mat.base))
        {
            // the match at idx starts exactly at from
            Ok(idx) => idx,
            // the match at idx is the first that is > from
            Err(idx) => idx,
        };

        let mut count = 0;
        for mat in self.matches[var_index].iter().skip(start_idx) {
            let mat_offset = mat.offset.saturating_add(mat.base);
            if mat_offset > to {
                return count;
            }
            count += 1;
        }

        count
    }

    /// Search occurrence of a variable at a given offset
    pub fn find_at(&self, var_index: usize, offset: usize) -> bool {
        self.matches[var_index]
            .binary_search_by_key(&offset, |mat| mat.offset.saturating_add(mat.base))
            .is_ok()
    }

    /// Search occurrence of a variable in between given offset
    pub fn find_in(&self, var_index: usize, from: usize, to: usize) -> bool {
        // Find the idx of the first match which starts after from
        let start_idx = match self.matches[var_index]
            .binary_search_by_key(&from, |mat| mat.offset.saturating_add(mat.base))
        {
            // the match at idx starts exactly at from
            Ok(idx) => idx,
            // the match at idx is the first that is > from
            Err(idx) => idx,
        };

        self.matches[var_index].get(start_idx).is_some_and(|mat| {
            let mat_offset = mat.offset.saturating_add(mat.base);
            mat_offset <= to
        })
    }
}

/// Details on a match on a string during a scan.
#[derive(Clone, Debug)]
pub struct StringMatch {
    /// Base offset of the region containing the match.
    ///
    /// When scanning a file, this is 0. When scanning fragmented memory such as a process
    /// memory, this is the starting offset of the region containing the match.
    pub base: usize,

    /// Offset of the match.
    ///
    /// This is relative to the base offset. For example, on a match at address
    /// `0x7FFF_0050`, in a region that starts at offset `0x7FFF_0000`:
    /// - `base` is `0x7FFF_0000`.
    /// - `offset` is `0x50`.
    pub offset: usize,

    /// Actual length of the match.
    ///
    /// This is the real length of the match, which might be bigger than the length of `data`.
    pub length: usize,

    /// The matched data.
    ///
    /// The length of this field is capped.
    pub data: Box<[u8]>,

    /// The value of the xoring key that was used for the match.
    ///
    /// If the string had a xor modifier, this value indicates which value of the xory key
    /// generated the match.
    pub xor_key: u8,
}

impl StringMatch {
    pub(crate) fn new(
        region: &Region,
        mat: std::ops::Range<usize>,
        match_max_length: usize,
        xor_key: u8,
    ) -> Self {
        let length = mat.end - mat.start;
        let capped_length = std::cmp::min(length, match_max_length);

        Self {
            base: region.start,
            data: region.mem[mat.start..]
                .iter()
                .take(capped_length)
                .copied()
                .collect(),
            offset: mat.start,
            length,
            xor_key,
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
            base: 0,
            offset: 0,
            length: 0,
            data: Box::new([]),
            xor_key: 0,
        });
    }
}
