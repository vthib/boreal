//! Implement scanning for variables
use std::cmp::Ordering;

use super::{Params, ScanData};
use crate::compiler::variable::Variable;

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
#[derive(Debug)]
pub(crate) struct VariableEvaluation<'a> {
    /// Variable being evaluated.
    pub(crate) var: &'a Variable,

    /// Parameters for the evaluation.
    params: Params,

    /// Matches already done.
    ///
    /// This array is capped and matches are ignored once the limit is reached.
    pub(crate) matches: Vec<Match>,
}

type Match = std::ops::Range<usize>;

impl<'a> VariableEvaluation<'a> {
    /// Build a new variable evaluation context, from a variable.
    pub fn new(var: &'a Variable, params: Params, matches: Vec<Match>) -> Self {
        Self {
            var,
            params,
            matches,
        }
    }

    /// Return true if the variable can be found in the scanned memory.
    pub fn find(&mut self, scan_data: &mut ScanData) -> bool {
        !self.matches.is_empty()
    }

    /// Get a specific match occurrence for the variable.
    ///
    /// This starts at 0, and not at 1 as in the yara file.
    pub fn find_match_occurence(
        &mut self,
        scan_data: &mut ScanData,
        occurence_number: usize,
    ) -> Option<Match> {
        self.matches.get(occurence_number).cloned()
    }

    /// Count number of matches.
    pub fn count_matches(&mut self, scan_data: &mut ScanData) -> u32 {
        // This is safe to allow because the number of matches is guaranteed to be capped by the
        // string_max_nb_matches parameter, which is a u32.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.matches.len() as u32
        }
    }

    /// Count number of matches in between two bounds.
    pub fn count_matches_in(&mut self, scan_data: &mut ScanData, from: usize, to: usize) -> u32 {
        if from >= scan_data.mem.len() {
            return 0;
        }

        let mut count = 0;
        for mat in &self.matches {
            if mat.start > to {
                return count;
            } else if mat.start >= from {
                count += 1;
            }
        }

        count
    }

    /// Search occurrence of a variable at a given offset
    pub fn find_at(&mut self, scan_data: &mut ScanData, offset: usize) -> bool {
        if offset >= scan_data.mem.len() {
            return false;
        }

        for mat in &self.matches {
            match mat.start.cmp(&offset) {
                Ordering::Less => (),
                Ordering::Equal => return true,
                Ordering::Greater => return false,
            }
        }

        false
    }

    /// Search occurrence of a variable in between given offset
    pub fn find_in(&mut self, scan_data: &mut ScanData, from: usize, to: usize) -> bool {
        if from >= scan_data.mem.len() {
            return false;
        }

        for mat in &self.matches {
            if mat.start > to {
                return false;
            } else if mat.start >= from {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use boreal_parser::rule::VariableModifiers;

    use crate::matcher::Matcher;
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(VariableEvaluation {
            var: &Variable {
                name: "a".to_owned(),
                is_private: false,
                matcher: Matcher::new_bytes(Vec::new(), &VariableModifiers::default()),
            },
            params: Params {
                string_max_nb_matches: 100,
            },
            matches: Vec::new(),
        });
    }
}
