//! Provides the [`AcScan`] object, used to scan for all variables in a single AC pass.
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};

use super::{timeout, EvalError};
use crate::atoms::pick_atom_in_literal;
use crate::compiler::variable::Variable;
use crate::matcher::{AcMatchStatus, Matcher};
use crate::statistics;

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

    /// Map from a aho pattern index to a list details on the literals.
    aho_index_to_literal_info: Vec<Vec<LiteralInfo>>,

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

/// Context related to a scan.
///
/// Mostly used simply to factorize variables used during the AC scan.
#[derive(Debug)]
pub struct ScanContext<'a> {
    /// Object used to check if the scan times out.
    pub timeout_checker: Option<&'a mut timeout::TimeoutChecker>,

    /// Statistics related to the scan.
    pub statistics: Option<&'a mut statistics::Evaluation>,

    /// List of variables to scan.
    ///
    /// This is the same variables, in the same order, as when building the
    /// [`AcScan`] object.
    pub variables: &'a [Variable],

    /// Max number of matches for a given string.
    pub string_max_nb_matches: u32,

    /// Max length of the matches returned in matching rules.
    pub match_max_length: usize,
}

impl ScanContext<'_> {
    fn check_timeout(&mut self) -> bool {
        self.timeout_checker
            .as_mut()
            .map_or(false, |checker| checker.check_timeout())
    }
}

impl AcScan {
    pub(crate) fn new(variables: &[Variable]) -> Self {
        let mut lits = Vec::new();
        let mut known_lits = HashMap::new();
        let mut aho_index_to_literal_info = Vec::new();
        let mut non_handled_var_indexes = Vec::new();

        for (variable_index, var) in variables.iter().enumerate() {
            if var.matcher.literals.is_empty() {
                non_handled_var_indexes.push(variable_index);
            } else {
                for (literal_index, lit) in var.matcher.literals.iter().enumerate() {
                    let (start, end) = pick_atom_in_literal(lit);
                    let mut atom = lit[start..(lit.len() - end)].to_vec();
                    let literal_info = LiteralInfo {
                        variable_index,
                        literal_index,
                        slice_offset: (start, end),
                    };

                    // Ensure the literals provided to the aho corasick are not
                    // duplicated. If multiple variables uses the same atoms,
                    // we will iterate on every variable in this module, instead
                    // of going back into the aho-corasick just for it to
                    // iterate over the matching ids and return immediately
                    // to this code. This improves performances significantly.
                    //
                    // In addition, since the aho-corasick is case insensitive,
                    // normalize before de-duplicating.
                    atom.make_ascii_lowercase();

                    match known_lits.entry(atom.clone()) {
                        Entry::Vacant(v) => {
                            let _r = v.insert(lits.len());
                            aho_index_to_literal_info.push(vec![literal_info]);
                            lits.push(atom);
                        }
                        Entry::Occupied(o) => {
                            let index = o.get();
                            aho_index_to_literal_info[*index].push(literal_info);
                        }
                    }
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

    pub(crate) fn scan_mem(
        &self,
        mem: &[u8],
        scan_ctx: &mut ScanContext,
        matches: &mut [Vec<StringMatch>],
    ) -> Result<(), EvalError> {
        // Iterate over aho-corasick matches, validating those matches
        for mat in self.aho.find_overlapping_iter(mem) {
            if scan_ctx.check_timeout() {
                return Err(EvalError::Timeout);
            }
            self.handle_possible_match(mem, &mat, scan_ctx, matches);
        }

        if !self.non_handled_var_indexes.is_empty() {
            #[cfg(feature = "profiling")]
            let start = std::time::Instant::now();

            // For every "raw" variable, scan the memory for this variable.
            for variable_index in &self.non_handled_var_indexes {
                let var = &scan_ctx.variables[*variable_index].matcher;

                scan_single_variable(mem, var, scan_ctx, &mut matches[*variable_index]);
            }

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_ctx.statistics.as_mut() {
                stats.raw_regexes_eval_duration += start.elapsed();
            }
        }

        Ok(())
    }

    fn handle_possible_match(
        &self,
        mem: &[u8],
        mat: &aho_corasick::Match,
        scan_ctx: &mut ScanContext,
        matches: &mut [Vec<StringMatch>],
    ) {
        for literal_info in &self.aho_index_to_literal_info[mat.pattern()] {
            let LiteralInfo {
                variable_index,
                literal_index,
                slice_offset: (start_offset, end_offset),
            } = *literal_info;
            let var = &scan_ctx.variables[variable_index].matcher;

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_ctx.statistics.as_mut() {
                stats.nb_ac_matches += 1;
            }
            #[cfg(feature = "profiling")]
            let start_instant = std::time::Instant::now();

            // Upscale to the original literal shape before feeding it to the matcher verification
            // function.
            let Some(start) = mat.start().checked_sub(start_offset) else {
                continue;
            };
            let end = match mat.end().checked_add(end_offset) {
                Some(v) if v <= mem.len() => v,
                _ => continue,
            };
            let m = start..end;

            // Verify the literal is valid.
            let Some(match_type) = var.confirm_ac_literal(mem, &m, literal_index) else {
                continue;
            };

            let var_matches = &mut matches[variable_index];

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
            let start_position = var_matches.last().map_or(0, |mat| mat.offset + 1);

            let res = var.process_ac_match(mem, m, start_position, match_type);

            #[cfg(feature = "profiling")]
            {
                if let Some(stats) = scan_ctx.statistics.as_mut() {
                    stats.ac_confirm_duration += start_instant.elapsed();
                }
            }

            match res {
                AcMatchStatus::Multiple(v) if v.is_empty() => (),
                AcMatchStatus::Multiple(found_matches) => var_matches.extend(
                    found_matches
                        .into_iter()
                        .map(|m| StringMatch::new(mem, m, scan_ctx.match_max_length)),
                ),
                AcMatchStatus::Single(m) => {
                    var_matches.push(StringMatch::new(mem, m, scan_ctx.match_max_length));
                }
                AcMatchStatus::None => (),
            };

            if !var_matches.is_empty() {
                var_matches.truncate(scan_ctx.string_max_nb_matches as usize);
            }
        }
    }
}

fn scan_single_variable(
    mem: &[u8],
    matcher: &Matcher,
    scan_ctx: &mut ScanContext,
    string_matches: &mut Vec<StringMatch>,
) {
    let mut offset = 0;
    while offset < mem.len() {
        let mat = matcher.find_next_match_at(mem, offset);

        match mat {
            None => break,
            Some(mat) => {
                offset = mat.start + 1;
                string_matches.push(StringMatch::new(mem, mat, scan_ctx.match_max_length));

                // This is safe to allow because this is called on every iterator of self.matches, so once
                // it cannot overflow u32 before this condition is true.
                #[allow(clippy::cast_possible_truncation)]
                if (string_matches.len() as u32) >= scan_ctx.string_max_nb_matches {
                    break;
                }
            }
        }
    }
}

/// Details on a match on a string during a scan.
#[derive(Clone, Debug)]
pub struct StringMatch {
    /// Offset of the match
    pub offset: usize,

    /// Actual length of the match.
    ///
    /// This is the real length of the match, which might be bigger than the length of `data`.
    pub length: usize,

    /// The matched data.
    ///
    /// The length of this field is capped.
    pub data: Vec<u8>,
}

impl StringMatch {
    fn new(mem: &[u8], mat: std::ops::Range<usize>, match_max_length: usize) -> Self {
        let length = mat.end - mat.start;
        let capped_length = std::cmp::min(length, match_max_length);

        Self {
            data: mem[mat.start..]
                .iter()
                .take(capped_length)
                .copied()
                .collect(),
            offset: mat.start,
            length,
        }
    }
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
        test_type_traits(StringMatch {
            offset: 0,
            length: 0,
            data: Vec::new(),
        });
        test_type_traits_non_clonable(ScanContext {
            timeout_checker: None,
            statistics: None,
            variables: &[],
            string_max_nb_matches: 0,
            match_max_length: 0,
        });
    }
}
