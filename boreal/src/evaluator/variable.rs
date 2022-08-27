//! Implement scanning for variables
use std::cmp::Ordering;

use crate::compiler::Variable;

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
}

type Match = std::ops::Range<usize>;

impl<'a> VariableEvaluation<'a> {
    /// Build a new variable evaluation context, from a variable.
    pub fn new(var: &'a Variable) -> Self {
        Self {
            var,
            matches: Vec::new(),
            next_offset: Some(0),
        }
    }

    /// Search occurrence of a variable in bytes
    pub fn find(&mut self, mem: &[u8]) -> Option<Match> {
        self.matches
            .get(0)
            .cloned()
            .or_else(|| self.get_next_match(mem))
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
    // FIXME: this is really bad performance
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
    // FIXME: this is really bad performance
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

        // TODO: if would be better to have a method on the matcher to search between
        // from and to, or even to search with find_at(from), instead of searching from
        // the start of the mem.
        while let Some(mat) = self.get_next_match(mem) {
            if mat.start > to {
                return false;
            } else if mat.start >= from {
                return true;
            }
        }
        false
    }

    /// Find next matches, save them, and call the given closure on each new one found.
    ///
    /// If the closure returns false, the search ends. Otherwise, the search continues.
    fn get_next_match(&mut self, mem: &[u8]) -> Option<Match> {
        let offset = match self.next_offset {
            None => return None,
            Some(v) => v,
        };

        let mat = self.find_next_match_at(mem, offset);
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

    /// Run the variable matcher at the given offset until a match is found.
    fn find_next_match_at(&self, mem: &[u8], mut offset: usize) -> Option<Match> {
        while offset < mem.len() {
            let mat = self
                .var
                .regex
                .find_at(mem, offset)
                .map(|m| m.start()..m.end())?;

            // TODO: this works, but is probably not ideal performance-wise. benchmark/improve
            // this.
            if !check_fullword(&mat, mem, self.var) {
                offset = mat.start + 1;
                continue;
            }
            return Some(mat);
        }
        None
    }
}

/// Check the match respects a possible fullword modifier for the variable.
fn check_fullword(mat: &Match, mem: &[u8], var: &Variable) -> bool {
    if !var.is_fullword() {
        return true;
    }

    // TODO: We need to know if the match is done on an ascii or wide string to properly check for
    // fullword constraints. This is done in a very ugly way, by going through the match.
    // A better way would be to know which alternation in the match was found.
    let mut match_is_wide = false;

    if var.is_wide() {
        match_is_wide = is_match_wide(mat, mem);
        if match_is_wide {
            if mat.start > 1 && mem[mat.start - 1] == b'\0' && is_ascii_alnum(mem[mat.start - 2]) {
                return false;
            }
            if mat.end + 1 < mem.len() && is_ascii_alnum(mem[mat.end]) && mem[mat.end + 1] == b'\0'
            {
                return false;
            }
        }
    }
    if var.is_ascii() && !match_is_wide {
        if mat.start > 0 && is_ascii_alnum(mem[mat.start - 1]) {
            return false;
        }
        if mat.end < mem.len() && is_ascii_alnum(mem[mat.end]) {
            return false;
        }
    }

    true
}

// Is a match a wide string or an ascii one
fn is_match_wide(mat: &Match, mem: &[u8]) -> bool {
    if (mat.end - mat.start) % 2 != 0 {
        return false;
    }

    !mem[(mat.start + 1)..mat.end]
        .iter()
        .step_by(2)
        .any(|c| *c != b'\0')
}

fn is_ascii_alnum(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c)
}
