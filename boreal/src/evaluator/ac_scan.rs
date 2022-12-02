//! Provides the [`AcScan`] object, used to scan for all variables in a single AC pass.
use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use super::Params;
use crate::compiler::variable::{atom_rank, AcMatchStatus, Variable};

/// Factorize atoms from all variables, to scan for them in a single pass.
///
/// For every variable, literals named atoms are extracted from the variables expressions. A single
/// Aho-Corasick object is built from all those literals, and a single pass on the scanned bytes
/// is done with this object. For every match on a literal, the match is then verified to see if
/// it matches the whole variable expression.
///
/// An exception to this is for variables that we either:
/// - cannot manage to extract atoms from
/// - need to or prefer scanning on their own
///
/// For those variables, the AC pass does not provide any result, and the variable will be scanned
/// on its own during evaluation of the rules.
#[derive(Debug)]
pub(crate) struct AcScan {
    /// Aho Corasick for variables that are literals.
    aho: ACVersion,

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

    /// Left and right offset for the slice picked in the Aho-Corasick.
    slice_offset: (usize, usize),
}

#[derive(Debug)]
enum ACVersion {
    Size32(AhoCorasick<u32>),
    Default(AhoCorasick),
}

impl AcScan {
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

        let mut builder = AhoCorasickBuilder::new();
        let builder = builder.ascii_case_insensitive(true).dfa(true);

        // First try with a smaller size to reduce memory use and improve performances, otherwise
        // use the default version.
        let aho = match builder.build_with_size::<u32, _, _>(&lits) {
            Ok(v) => ACVersion::Size32(v),
            Err(_) => ACVersion::Default(builder.build(&lits)),
        };

        Self {
            aho,
            aho_index_to_literal_info,
            non_handled_var_indexes,
        }
    }

    pub(crate) fn matches(
        &self,
        mem: &[u8],
        variables: &[Variable],
        params: Params,
    ) -> Vec<AcResult> {
        let mut matches = vec![AcResult::NotFound; variables.len()];

        match &self.aho {
            ACVersion::Size32(v) => {
                for mat in v.find_overlapping_iter(mem) {
                    self.handle_possible_match(mem, variables, &mat, params, &mut matches);
                }
            }
            ACVersion::Default(v) => {
                for mat in v.find_overlapping_iter(mem) {
                    self.handle_possible_match(mem, variables, &mat, params, &mut matches);
                }
            }
        }

        for i in &self.non_handled_var_indexes {
            matches[*i] = AcResult::Unknown;
        }

        matches
    }

    fn handle_possible_match(
        &self,
        mem: &[u8],
        variables: &[Variable],
        mat: &aho_corasick::Match,
        params: Params,
        matches: &mut [AcResult],
    ) {
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
            None => return,
        };
        let end = match mat.end().checked_add(end_offset) {
            Some(v) if v > mem.len() => return,
            Some(v) => v,
            None => return,
        };
        let m = start..end;

        // Verify the literal is valid.
        if !var.confirm_ac_literal(mem, &m, literal_index) {
            return;
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
        let start_position = match &matches[variable_index] {
            AcResult::Matches(v) => match v.last() {
                Some(m) => m.start + 1,
                None => 0,
            },
            _ => 0,
        };

        match variables[variable_index].process_ac_match(mem, m, start_position) {
            AcMatchStatus::Multiple(found_matches) => match &mut matches[variable_index] {
                AcResult::Matches(v) => v.extend(found_matches),
                _ => matches[variable_index] = AcResult::Matches(found_matches),
            },
            AcMatchStatus::Single(m) => match &mut matches[variable_index] {
                AcResult::Matches(v) => v.push(m),
                _ => matches[variable_index] = AcResult::Matches(vec![m]),
            },
            AcMatchStatus::Unknown => matches[variable_index] = AcResult::Unknown,
            AcMatchStatus::None => (),
        };

        if let AcResult::Matches(matches) = &mut matches[variable_index] {
            matches.truncate(params.string_max_nb_matches);
        }
    }
}

fn pick_best_atom_in_literal(lit: &[u8]) -> (usize, usize) {
    if lit.len() <= 4 {
        return (0, 0);
    }

    lit.windows(4)
        .enumerate()
        .max_by_key(|(_, s)| atom_rank(s))
        .map_or((0, 0), |(i, _)| (i, lit.len() - i - 4))
}

#[derive(Clone, Debug)]
pub(crate) enum AcResult {
    /// Variable was not found by the AC pass.
    NotFound,
    /// Unknown, must scan for the variable on its own.
    Unknown,
    /// List of matches for the variable.
    Matches(Vec<Range<usize>>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(AcScan::new(&[]));
        test_type_traits_non_clonable(LiteralInfo {
            variable_index: 0,
            literal_index: 0,
            slice_offset: (0, 0),
        });
        test_type_traits(AcResult::Unknown);
    }
}
