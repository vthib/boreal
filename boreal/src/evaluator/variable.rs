//! Implement scanning for variables
use std::cmp::Ordering;

use crate::{
    compiler::{Variable, VariableMatcher},
    variable_set::SetResult,
};

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
    pub fn new(var: &'a Variable, set_result: &SetResult, mem: &[u8]) -> Self {
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
            SetResult::Found => {
                this.has_been_found = !this.need_full_matches();
                this
            }
            SetResult::Matches(matches) => {
                if this.need_full_matches() {
                    this.matches = matches
                        .iter()
                        .filter_map(|mat| this.validate_and_update_match(mem, mat.clone()))
                        .collect();
                } else {
                    this.matches = matches.to_vec();
                }
                this.next_offset = None;
                this.has_been_found = !this.matches.is_empty();
                this
            }
        }
    }

    /// Does the variable need a full match details or not.
    ///
    /// When scanning, an optimization consists of running a ``RegexSet`` of all variables to find
    /// if variables match or not. This is however a "no match/had a match" boolean, and some
    /// variables require the details of the matches to validate it. Those variables must return
    /// true here.
    pub fn need_full_matches(&self) -> bool {
        self.var.is_fullword() || self.var.non_wide_regex.is_some()
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
            let mat = match &self.var.matcher {
                VariableMatcher::Regex(regex) => regex.find_at(mem, offset).map(|m| m.range()),
                VariableMatcher::AhoCorasick(aho) => aho.find(&mem[offset..]).map(|m| Match {
                    start: offset + m.start(),
                    end: offset + m.end(),
                }),
            }?;

            match self.validate_and_update_match(mem, mat.clone()) {
                Some(m) => return Some(m),
                None => {
                    offset = mat.start + 1;
                }
            }
        }
        None
    }

    fn validate_and_update_match(&self, mem: &[u8], mat: Match) -> Option<Match> {
        if self.var.is_fullword() && !check_fullword(&mat, mem, self.var) {
            return None;
        }

        match self.var.non_wide_regex.as_ref() {
            Some(regex) => apply_wide_word_boundaries(mat, mem, regex),
            None => Some(mat),
        }
    }
}

/// Check the match respects the word boundaries inside the variable.
fn apply_wide_word_boundaries(
    mut mat: Match,
    mem: &[u8],
    regex: &regex::bytes::Regex,
) -> Option<Match> {
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
    // TODO bench this
    let unwiden_mem = unwide(&mem[start..std::cmp::min(mem.len(), mat.end + 500)]);

    let expected_start = if start < mat.start { 1 } else { 0 };
    match regex.find(&unwiden_mem) {
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

/// Check the match respects a possible fullword modifier for the variable.
fn check_fullword(mat: &Match, mem: &[u8], var: &Variable) -> bool {
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
    if mat.is_empty() {
        return true;
    }

    !mem[(mat.start + 1)..mat.end]
        .iter()
        .step_by(2)
        .any(|c| *c != b'\0')
}

fn is_ascii_alnum(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c)
}
