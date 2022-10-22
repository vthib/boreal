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

    /// Map from a aho pattern index to details on the literals.
    aho_index_to_literal_info: Vec<LiteralInfo>,

    /// List of indexes for vars that are not part of the aho corasick.
    non_handled_var_indexes: Vec<usize>,
}

/// Details on a literal of a variable.
#[derive(Debug)]
struct LiteralInfo {
    /// Index of the variable in the variable array.
    variable_index: usize,

    /// Index of the literal for the variable.
    literal_index: usize,
}

impl VariableSet {
    pub(crate) fn new(variables: &[Variable]) -> Self {
        let mut lits = Vec::new();
        let mut aho_index_to_literal_info = Vec::new();
        let mut non_handled_var_indexes = Vec::new();

        for (variable_index, var) in variables.iter().enumerate() {
            let literals = var.matcher.get_literals();

            if literals.is_empty() {
                non_handled_var_indexes.push(variable_index);
            } else {
                aho_index_to_literal_info.extend((0..literals.len()).map(|literal_index| {
                    LiteralInfo {
                        variable_index,
                        literal_index,
                    }
                }));
                lits.extend(literals);
            }
        }

        // TODO: Should this AC be case insensitive or not? Redo some benches once other
        // optimizations are done.
        let aho = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .auto_configure(&lits)
            .build(&lits);

        Self {
            aho,
            aho_index_to_literal_info,
            non_handled_var_indexes,
        }
    }

    pub(crate) fn matches(&self, mem: &[u8], variables: &[Variable]) -> VariableSetMatches {
        let mut matches = vec![None; variables.len()];

        for mat in self.aho.find_overlapping_iter(mem) {
            let LiteralInfo {
                variable_index,
                literal_index,
            } = self.aho_index_to_literal_info[mat.pattern()];
            let m = mat.start()..mat.end();

            match variables[variable_index]
                .matcher
                .check_ac_match(mem, m, literal_index)
            {
                AcMatchStatus::Valid(m) => match &mut matches[variable_index] {
                    Some(MatchResult::Matches(v)) => v.push(m),
                    _ => matches[variable_index] = Some(MatchResult::Matches(vec![m])),
                },
                AcMatchStatus::Unknown => matches[variable_index] = Some(MatchResult::Unknown),
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
