//! Provides the [`VariableSet`] object.
use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use crate::compiler::{AcMatchStatus, Variable};

/// Factorize regex expression of all the variables in the scanner.
///
/// Used to minimize the number of passes on the scanned memory.
#[derive(Debug)]
pub(crate) struct VariableSet {
    /// Aho Corasick for variables that are literals.
    aho: AhoCorasick,
    /// Number of literals in the
    /// Aho Corasick for variables that are literals, and are case insensitive.
    aho_ci: AhoCorasick,

    /// Map from a aho pattern index to a var set index.
    aho_index_to_var_index: Vec<usize>,

    /// Map from a aho ci pattern index to a var set index.
    aho_ci_index_to_var_index: Vec<usize>,

    /// List of indexes for vars that are not part of the aho corasick
    non_handled_var_indexes: Vec<usize>,
}

impl VariableSet {
    pub(crate) fn new(variables: &[Variable]) -> Self {
        let mut lits = Vec::new();
        let mut lits_ci = Vec::new();
        let mut aho_index_to_var_index = Vec::new();
        let mut aho_ci_index_to_var_index = Vec::new();
        let mut non_handled_var_indexes = Vec::new();

        for (var_index, var) in variables.iter().enumerate() {
            let literals = var.matcher.get_literals();

            if literals.is_empty() {
                non_handled_var_indexes.push(var_index);
            } else if var.matcher.is_case_insensitive() {
                aho_ci_index_to_var_index.extend(std::iter::repeat(var_index).take(literals.len()));
                lits_ci.extend(literals);
            } else {
                aho_index_to_var_index.extend(std::iter::repeat(var_index).take(literals.len()));
                lits.extend(literals);
            }
        }

        let aho = AhoCorasick::new_auto_configured(&lits);
        let aho_ci = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .auto_configure(&lits_ci)
            .build(&lits_ci);

        Self {
            aho,
            aho_ci,
            aho_index_to_var_index,
            aho_ci_index_to_var_index,
            non_handled_var_indexes,
        }
    }

    pub(crate) fn matches(&self, mem: &[u8], variables: &[Variable]) -> VariableSetMatches {
        let mut matches = vec![None; variables.len()];

        for mat in self.aho.find_overlapping_iter(mem) {
            let var_index = self.aho_index_to_var_index[mat.pattern()];
            let m = mat.start()..mat.end();

            match &variables[var_index].matcher.check_ac_match(mem, &m) {
                AcMatchStatus::Valid => match &mut matches[var_index] {
                    Some(MatchResult::Matches(v)) => v.push(m),
                    _ => matches[var_index] = Some(MatchResult::Matches(vec![m])),
                },
                AcMatchStatus::Unknown => matches[var_index] = Some(MatchResult::Unknown),
                AcMatchStatus::Invalid => (),
            };
        }
        for mat in self.aho_ci.find_overlapping_iter(mem) {
            let var_index = self.aho_ci_index_to_var_index[mat.pattern()];
            let m = mat.start()..mat.end();

            match &variables[var_index].matcher.check_ac_match(mem, &m) {
                AcMatchStatus::Valid => match &mut matches[var_index] {
                    Some(MatchResult::Matches(v)) => v.push(m),
                    _ => matches[var_index] = Some(MatchResult::Matches(vec![m])),
                },
                AcMatchStatus::Unknown => matches[var_index] = Some(MatchResult::Unknown),
                AcMatchStatus::Invalid => (),
            };
        }

        for i in &self.non_handled_var_indexes {
            matches[*i] = Some(MatchResult::Unknown);
        }

        VariableSetMatches { matches }
    }
}

#[derive(Clone, Debug)]
enum MatchResult {
    /// Unknown, must scan for the variable on its own.
    Unknown,
    /// List of matches.
    Matches(Vec<Range<usize>>),
}

#[derive(Debug)]
pub(crate) struct VariableSetMatches {
    matches: Vec<Option<MatchResult>>,
}

/// Result of a `VariableSet` scan for a given variable.
#[derive(Clone, Debug)]
pub(crate) enum SetResult<'a> {
    /// Variable has no match.
    NotFound,
    /// Unknown, must scan for the variable on its own.
    Unknown,
    /// List of matches.
    Matches(&'a [Range<usize>]),
}

impl VariableSetMatches {
    pub(crate) fn matched(&self, index: usize) -> SetResult {
        match &self.matches[index] {
            None => SetResult::NotFound,
            Some(MatchResult::Unknown) => SetResult::Unknown,
            Some(MatchResult::Matches(m)) => SetResult::Matches(m),
        }
    }
}
