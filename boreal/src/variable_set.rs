//! Provides the [`VariableSet`] object.
use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use crate::compiler::{literals_rank, AcMatchStatus, Variable};

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
#[derive(Clone, Debug)]
struct LiteralInfo {
    /// Index of the variable in the variable array.
    variable_index: usize,

    /// Index of the literal for the variable.
    literal_index: usize,

    /// Left and right offset for the slice picked in the Aho-Corasick.
    slice_offset: (usize, usize),
}

impl VariableSet {
    pub(crate) fn new(variables: &[Variable]) -> Self {
        let mut lits = Vec::new();
        let mut aho_index_to_literal_info = Vec::new();
        let mut non_handled_var_indexes = Vec::new();

        for (variable_index, var) in variables.iter().enumerate() {
            if var.literals.is_empty() {
                non_handled_var_indexes.push(variable_index);
            } else {
                for (literal_index, lit) in var.literals.iter().enumerate() {
                    let (start, end) = pick_best_atom_in_literal(lit);
                    aho_index_to_literal_info.push(LiteralInfo {
                        variable_index,
                        literal_index,
                        slice_offset: (start, end),
                    });
                    lits.push(lit[start..(lit.len() - end)].to_vec());
                }
            }
        }

        // TODO: Should this AC be case insensitive or not? Redo some benches once other
        // optimizations are done.
        let aho = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .dfa(true)
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
                slice_offset: (start_offset, end_offset),
            } = self.aho_index_to_literal_info[mat.pattern()];
            let var = &variables[variable_index];

            // Upscale to the original literal shape before feeding it to the matcher verification
            // function.
            let start = match mat.start().checked_sub(start_offset) {
                Some(v) => v,
                None => continue,
            };
            let end = match mat.end().checked_add(end_offset) {
                Some(v) if v > mem.len() => continue,
                Some(v) => v,
                None => continue,
            };
            let m = start..end;

            // Verify the literal is valid.
            if !var.confirm_ac_literal(mem, &m, literal_index) {
                continue;
            }

            // Shorten the mem to prevent new matches on the same starting byte.
            // For example, for `a.*?bb`, and input `abbb`, this can happen:
            // - extract atom `bb`
            // - get AC match on `a(bb)b`: call check_ac_match, this will return the
            //   match `(abb)b`.
            // - get AC match on `ab(bb)`: call check_ac_match, this will return the
            //   match `(abbb)`.
            // This is invalid, only one match per starting byte can happen.
            // To avoid this, ensure the mem given to check_ac_match starts one byte after the last
            // saved match.
            let start_position = match matches[variable_index].as_ref() {
                Some(MatchResult::Matches(v)) => match v.last() {
                    Some(m) => m.start + 1,
                    None => 0,
                },
                _ => 0,
            };

            match variables[variable_index]
                .matcher
                .check_ac_match(mem, m, start_position)
            {
                AcMatchStatus::Multiple(found_matches) => match &mut matches[variable_index] {
                    Some(MatchResult::Matches(v)) => v.extend(found_matches),
                    _ => matches[variable_index] = Some(MatchResult::Matches(found_matches)),
                },
                AcMatchStatus::Single(m) => match &mut matches[variable_index] {
                    Some(MatchResult::Matches(v)) => v.push(m),
                    _ => matches[variable_index] = Some(MatchResult::Matches(vec![m])),
                },
                AcMatchStatus::Unknown => matches[variable_index] = Some(MatchResult::Unknown),
                AcMatchStatus::None => (),
            };
        }

        for i in &self.non_handled_var_indexes {
            matches[*i] = Some(MatchResult::Unknown);
        }

        VariableSetMatches { matches }
    }
}

fn pick_best_atom_in_literal(lit: &[u8]) -> (usize, usize) {
    if lit.len() <= 4 {
        return (0, 0);
    }

    lit.windows(4)
        .enumerate()
        .max_by_key(|(_, s)| literals_rank(s))
        .map_or((0, 0), |(i, _)| (i, lit.len() - i - 4))
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
