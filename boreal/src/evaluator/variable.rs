//! Implement scanning for variables
use std::cmp::Ordering;

use super::ac_scan::AcResult;
use super::Params;
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

    /// Offset for the next scan.
    ///
    /// Set to None once the whole mem has been scanned.
    next_offset: Option<usize>,

    /// The variable has been found in the scanned memory.
    ///
    /// If true, it indicates the variable has been found, although
    /// details on the matches are unknown. This provides a quick
    /// response if the only use of the variable is to check its presence.
    has_been_found: bool,
}

pub type Match = std::ops::Range<usize>;

impl<'a> VariableEvaluation<'a> {
    /// Build a new variable evaluation context, from a variable.
    pub fn new(var: &'a Variable, params: Params, ac_result: AcResult) -> Self {
        let mut this = Self {
            var,
            params,
            matches: Vec::new(),
            next_offset: Some(0),
            has_been_found: false,
        };
        match ac_result {
            AcResult::Unknown => this,
            AcResult::NotFound => {
                this.next_offset = None;
                this
            }
            AcResult::Matches(matches) => {
                this.matches = matches;
                this.next_offset = None;
                this.has_been_found = !this.matches.is_empty();
                this
            }
        }
    }

    /// Return true if the variable can be found in the scanned memory.
    pub fn find(&mut self, mem: &[u8]) -> bool {
        if self.has_been_found || !self.matches.is_empty() {
            true
        } else {
            self.get_next_match(mem).is_some()
        }
    }

    /// Get a specific match occurrence for the variable.
    ///
    /// This starts at 0, and not at 1 as in the yara file.
    pub fn find_match_occurence(&mut self, mem: &[u8], occurence_number: usize) -> Option<Match> {
        while self.matches.len() <= occurence_number {
            let _r = self.get_next_match(mem)?;
        }

        self.matches.get(occurence_number).cloned()
    }

    /// Count number of matches.
    pub fn count_matches(&mut self, mem: &[u8]) -> u32 {
        loop {
            if self.get_next_match(mem).is_none() {
                break;
            }
        }

        // This is safe to allow because the number of matches is guaranteed to be capped by the
        // string_max_nb_matches parameter, which is a u32.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.matches.len() as u32
        }
    }

    /// Count number of matches in between two bounds.
    pub fn count_matches_in(&mut self, mem: &[u8], from: usize, to: usize) -> u32 {
        if from >= mem.len() {
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

        while let Some(mat) = self.get_next_match(mem) {
            if mat.start > to {
                return count;
            } else if mat.start >= from {
                count += 1;
            }
        }

        count
    }

    /// Search occurrence of a variable at a given offset
    pub fn find_at(&mut self, mem: &[u8], offset: usize) -> bool {
        if offset >= mem.len() {
            return false;
        }

        for mat in &self.matches {
            match mat.start.cmp(&offset) {
                Ordering::Less => (),
                Ordering::Equal => return true,
                Ordering::Greater => return false,
            }
        }

        while let Some(mat) = self.get_next_match(mem) {
            match mat.start.cmp(&offset) {
                Ordering::Less => (),
                Ordering::Equal => return true,
                Ordering::Greater => return false,
            }
        }
        false
    }

    /// Search occurrence of a variable in between given offset
    pub fn find_in(&mut self, mem: &[u8], from: usize, to: usize) -> bool {
        if from >= mem.len() {
            return false;
        }

        for mat in &self.matches {
            if mat.start > to {
                return false;
            } else if mat.start >= from {
                return true;
            }
        }

        while let Some(mat) = self.get_next_match(mem) {
            if mat.start > to {
                return false;
            } else if mat.start >= from {
                return true;
            }
        }
        false
    }

    /// Force computation of all possible matches.
    pub fn compute_all_matches(&mut self, mem: &[u8]) {
        while self.get_next_match(mem).is_some() {}
    }

    /// Find next matches, save them, and call the given closure on each new one found.
    ///
    /// If the closure returns false, the search ends. Otherwise, the search continues.
    fn get_next_match(&mut self, mem: &[u8]) -> Option<Match> {
        // This is safe to allow because this is called on every iterator of self.matches, so once
        // it cannot overflow u32 before this condition is true.
        #[allow(clippy::cast_possible_truncation)]
        if (self.matches.len() as u32) >= self.params.string_max_nb_matches {
            return None;
        }

        let offset = match self.next_offset {
            None => return None,
            Some(v) => v,
        };

        let mat = self.var.find_next_match_at(mem, offset);
        match &mat {
            None => {
                // No match, nothing to scan anymore
                self.next_offset = None;
            }
            Some(mat) => {
                // Save the mat, and save the next offset
                self.matches.push(mat.clone());
                if mat.start + 1 < mem.len() {
                    self.next_offset = Some(mat.start + 1);
                } else {
                    self.next_offset = None;
                }
            }
        }
        mat
    }
}

#[cfg(test)]
mod tests {
    use boreal_parser::{VariableDeclaration, VariableDeclarationValue, VariableModifiers};

    use crate::compiler::variable::compile_variable;
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(VariableEvaluation {
            var: &compile_variable(
                VariableDeclaration {
                    name: "a".to_owned(),
                    value: VariableDeclarationValue::Bytes(Vec::new()),
                    modifiers: VariableModifiers::default(),
                    span: 0..1,
                },
                "",
                false,
            )
            .unwrap()
            .0,
            params: Params {
                string_max_nb_matches: 100,
            },
            matches: Vec::new(),
            next_offset: None,
            has_been_found: false,
        });
    }
}
