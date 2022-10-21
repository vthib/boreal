//! Implement scanning for variables
use std::cmp::Ordering;

use crate::{compiler::Variable, variable_set::SetResult};

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
#[derive(Debug)]
pub(crate) struct VariableEvaluation<'a> {
    pub(crate) var: &'a Variable,

    /// Matches already done
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
    pub fn new(var: &'a Variable, set_result: &SetResult) -> Self {
        let mut this = Self {
            var,
            matches: Vec::new(),
            next_offset: Some(0),
            has_been_found: false,
        };
        match set_result {
            SetResult::Unknown => this,
            SetResult::NotFound => {
                this.next_offset = None;
                this
            }
            SetResult::Matches(matches) => {
                this.matches = matches.to_vec();
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
    pub fn count_matches(&mut self, mem: &[u8]) -> u64 {
        loop {
            if self.get_next_match(mem).is_none() {
                break;
            }
        }

        self.matches.len() as u64
    }

    /// Count number of matches in between two bounds.
    pub fn count_matches_in(&mut self, mem: &[u8], from: usize, to: usize) -> u64 {
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
        // TODO: have a limit on the number of matches
        while self.get_next_match(mem).is_some() {}
    }

    /// Find next matches, save them, and call the given closure on each new one found.
    ///
    /// If the closure returns false, the search ends. Otherwise, the search continues.
    fn get_next_match(&mut self, mem: &[u8]) -> Option<Match> {
        let offset = match self.next_offset {
            None => return None,
            Some(v) => v,
        };

        let mat = self.var.matcher.find_next_match_at(mem, offset);
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
