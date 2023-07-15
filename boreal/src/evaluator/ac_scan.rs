//! Provides the [`AcScan`] object, used to scan for all variables in a single AC pass.
use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};

use super::{EvalError, Params, ScanData};
use crate::atoms::pick_atom_in_literal;
use crate::compiler::variable::{AcMatchStatus, Variable};

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

    /// Left and right offset for the slice picked in the Aho-Corasick.
    slice_offset: (usize, usize),
}

impl AcScan {
    pub(crate) fn new(variables: &[Variable]) -> Self {
        let mut lits = Vec::new();
        let mut aho_index_to_literal_info = Vec::new();
        let mut non_handled_var_indexes = Vec::new();

        for (variable_index, var) in variables.iter().enumerate() {
            if var.matcher.literals.is_empty() {
                non_handled_var_indexes.push(variable_index);
            } else {
                for (literal_index, lit) in var.matcher.literals.iter().enumerate() {
                    let (start, end) = pick_atom_in_literal(lit);
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
        let builder = builder
            .ascii_case_insensitive(true)
            .kind(Some(AhoCorasickKind::DFA));

        // First try with a smaller size to reduce memory use and improve performances, otherwise
        // use the default version.
        let aho = builder.build(&lits).unwrap();

        Self {
            aho,
            aho_index_to_literal_info,
            non_handled_var_indexes,
        }
    }

    pub(crate) fn matches(
        &self,
        scan_data: &mut ScanData,
        variables: &[Variable],
        params: Params,
    ) -> Result<Vec<AcResult>, EvalError> {
        let mut matches = vec![AcResult::NotFound; variables.len()];
        let mem = scan_data.mem;

        for mat in self.aho.find_overlapping_iter(mem) {
            if scan_data.check_timeout() {
                return Err(EvalError::Timeout);
            }
            self.handle_possible_match(scan_data, variables, &mat, params, &mut matches);
        }

        for i in &self.non_handled_var_indexes {
            matches[*i] = AcResult::Unknown;
        }

        Ok(matches)
    }

    fn handle_possible_match(
        &self,
        scan_data: &mut ScanData,
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

        #[cfg(feature = "profiling")]
        if let Some(stats) = scan_data.statistics.as_mut() {
            stats.nb_ac_matches += 1;
        }
        #[cfg(feature = "profiling")]
        let start_instant = std::time::Instant::now();

        // Upscale to the original literal shape before feeding it to the matcher verification
        // function.
        let start = match mat.start().checked_sub(start_offset) {
            Some(v) => v,
            None => return,
        };
        let end = match mat.end().checked_add(end_offset) {
            Some(v) if v > scan_data.mem.len() => return,
            Some(v) => v,
            None => return,
        };
        let m = start..end;

        // Verify the literal is valid.
        if !var.confirm_ac_literal(scan_data.mem, &m, literal_index) {
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

        let res = variables[variable_index].process_ac_match(scan_data.mem, m, start_position);

        #[cfg(feature = "profiling")]
        {
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.ac_confirm_duration += start_instant.elapsed();
            }
        }

        match res {
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
            matches.truncate(params.string_max_nb_matches as usize);
        }
    }
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
