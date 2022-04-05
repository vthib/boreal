//! Implement scanning for variables
use std::cmp::Ordering;

use grep_matcher::Matcher;

use crate::compiler::{Variable, VariableMatcher};

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
#[derive(Debug)]
pub(crate) struct VariableEvaluation<'a> {
    var: &'a Variable,

    /// Matches already done
    matches: Vec<Match>,
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
            // False positive, doing the suggest transformation brings a compilation error.
            #[allow(clippy::question_mark)]
            if self.get_next_match(mem).is_none() {
                return None;
            }
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
            let mat = match &self.var.matcher {
                VariableMatcher::Regex(matcher) => {
                    // The assignement is simply to typecheck that the error is "NoError",
                    // so we can unwrap it.
                    let res: Result<_, grep_matcher::NoError> = matcher.find_at(mem, offset);
                    res.unwrap().map(|m| m.start()..m.end())
                }
                VariableMatcher::AhoCorasick(matcher) => {
                    matcher.find(&mem[offset..]).map(|m| Match {
                        start: offset + m.start(),
                        end: offset + m.end(),
                    })
                }
            }?;

            // TODO: this works, but is probably not ideal performance-wise. benchmark/improve
            // this.
            if self.var.is_fullword {
                if mat.start > 0 && is_ascii_alnum(mem[mat.start - 1]) {
                    offset = mat.start + 1;
                    continue;
                }
                if mat.end < mem.len() && is_ascii_alnum(mem[mat.end]) {
                    offset = mat.start + 1;
                    continue;
                }
            }
            return Some(mat);
        }
        None
    }
}

fn is_ascii_alnum(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile_variable;
    use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue, VariableModifiers};

    fn build_var_string(s: &str) -> Variable {
        compile_variable(VariableDeclaration {
            name: "umbasa".to_owned(),
            value: VariableDeclarationValue::String(s.to_owned()),
            modifiers: VariableModifiers::default(),
        })
        .unwrap()
    }

    fn build_var_regex(s: &str, case_insensitive: bool, dot_all: bool) -> Variable {
        compile_variable(VariableDeclaration {
            name: "umbasa".to_owned(),
            value: VariableDeclarationValue::Regex(Regex {
                expr: s.to_owned(),
                case_insensitive,
                dot_all,
            }),
            modifiers: VariableModifiers::default(),
        })
        .unwrap()
    }

    #[test]
    fn test_variable_find() {
        let find = |var, input| {
            let mut eval_context = VariableEvaluation::new(var);
            eval_context.find(input)
        };

        let v = build_var_string("45");
        assert!(find(&v, b"12345678").is_some());
        assert!(find(&v, b"45678").is_some());
        assert!(find(&v, b"45").is_some());
        assert!(find(&v, b"345").is_some());
        assert!(!find(&v, b"1234678").is_some());
        assert!(!find(&v, b"465").is_some());

        let v = build_var_regex("4.5+", false, false);
        assert!(find(&v, b"445").is_some());
        assert!(find(&v, b"34\x3D555").is_some());
        assert!(!find(&v, b"123").is_some());
        assert!(!find(&v, b"44").is_some());
        assert!(!find(&v, "4\n5".as_bytes()).is_some());

        let v = build_var_regex("fo{2,}", true, false);
        assert!(find(&v, b"foo").is_some());
        assert!(find(&v, b"FoOoOoO").is_some());
        assert!(find(&v, b"barFOOObaz").is_some());
        assert!(!find(&v, b"fo").is_some());
        assert!(!find(&v, b"FO").is_some());

        let v = build_var_regex("a.*b", false, true);
        assert!(find(&v, b"ab").is_some());
        assert!(find(&v, b"ba\n\n  ba").is_some());
        assert!(!find(&v, b"AB").is_some());
        assert!(!find(&v, b"ec").is_some());
    }

    #[test]
    fn test_variable_find_at() {
        let find_at = |var, input, offset| {
            let mut eval_context = VariableEvaluation::new(var);
            eval_context.find_at(input, offset)
        };

        let v = build_var_string("34");
        assert!(find_at(&v, b"01234567", 3));
        assert!(find_at(&v, b"342342", 3));
        assert!(find_at(&v, b"34", 0));
        assert!(!find_at(&v, b"234", 2));
        assert!(!find_at(&v, b"234", 0));
        assert!(!find_at(&v, b"01234", 15));

        let v = build_var_regex("[a-z]{2}", false, false);
        assert!(find_at(&v, b"abc", 0));
        assert!(find_at(&v, b"abc", 1));
        assert!(!find_at(&v, b"abc", 2));
    }

    #[test]
    fn test_variable_find_in() {
        let find_in = |var, input, from, to| {
            let mut eval_context = VariableEvaluation::new(var);
            eval_context.find_in(input, from, to)
        };

        let v = build_var_string("345");
        assert!(find_in(&v, b"01234567", 0, 20));
        assert!(find_in(&v, b"01234567", 2, 6));
        assert!(find_in(&v, b"01234567", 3, 5));
        assert!(find_in(&v, b"01234567", 3, 4));
        assert!(find_in(&v, b"01234567", 3, 3));
        assert!(find_in(&v, b"01234567", 2, 3));
        assert!(!find_in(&v, b"01234567", 1, 2));
        assert!(!find_in(&v, b"34353435", 1, 6));
    }
}
