//! Provides the [`AcScan`] object, used to scan for all variables in a single AC pass.
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};

use super::{
    CallbackEvents, ScanCallbackResult, ScanData, ScanError, ScanEvent, StringIdentifier,
    StringMatch,
};
use crate::atoms::pick_atom_in_literal;
use crate::compiler::variable::Variable;
use crate::compiler::CompilerProfile;
use crate::matcher::{AcMatchStatus, Matcher};
use crate::memory::Region;

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

impl AcScan {
    pub(crate) fn new(variables: &[Variable], profile: CompilerProfile) -> Self {
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
        let builder = builder.ascii_case_insensitive(true);
        let builder = builder.kind(Some(match profile {
            CompilerProfile::Speed => AhoCorasickKind::DFA,
            CompilerProfile::Memory => AhoCorasickKind::ContiguousNFA,
        }));

        // First try with a smaller size to reduce memory use and improve performances, otherwise
        // use the default version.
        let aho = builder.build(&lits).unwrap();

        Self {
            aho,
            aho_index_to_literal_info,
            non_handled_var_indexes,
        }
    }

    pub(super) fn scan_region<'scanner>(
        &self,
        region: &Region,
        scanner: &'scanner super::Inner,
        scan_data: &mut ScanData<'scanner, '_>,
        matches: &mut [Vec<StringMatch>],
    ) -> Result<(), ScanError> {
        #[cfg(feature = "profiling")]
        if let Some(stats) = scan_data.statistics.as_mut() {
            stats.nb_memory_chunks += 1;
            stats.memory_scanned_size += region.mem.len();
        }

        // Iterate over aho-corasick matches, validating those matches
        for mat in self.aho.find_overlapping_iter(region.mem) {
            if scan_data.check_timeout() {
                return Err(ScanError::Timeout);
            }
            self.handle_possible_match(region, scanner, &mat, scan_data, matches)?;
        }

        if !self.non_handled_var_indexes.is_empty() {
            #[cfg(feature = "profiling")]
            let start = std::time::Instant::now();

            // For every "raw" variable, scan the memory for this variable.
            for variable_index in &self.non_handled_var_indexes {
                let var = &scanner.variables[*variable_index].matcher;

                scan_single_variable(region, var, scan_data, &mut matches[*variable_index]);
            }

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.raw_regexes_eval_duration += start.elapsed();
            }
        }

        Ok(())
    }

    fn handle_possible_match<'scanner>(
        &self,
        region: &Region,
        scanner: &'scanner super::Inner,
        mat: &aho_corasick::Match,
        scan_data: &mut ScanData<'scanner, '_>,
        matches: &mut [Vec<StringMatch>],
    ) -> Result<(), ScanError> {
        for literal_info in &self.aho_index_to_literal_info[mat.pattern()] {
            let LiteralInfo {
                variable_index,
                literal_index,
                slice_offset: (start_offset, end_offset),
            } = *literal_info;
            let var = &scanner.variables[variable_index].matcher;

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
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
                Some(v) if v <= region.mem.len() => v,
                _ => continue,
            };
            let m = start..end;

            // Verify the literal is valid.
            let Some(match_type) = var.confirm_ac_literal(region.mem, &m, literal_index) else {
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
            //
            // This must only be done if the match is in the same region, otherwise the offset
            // of the previous match makes no sense for this match, and will falsify results.
            let start_position = match var_matches.last() {
                Some(mat) if mat.base == region.start => mat.offset + 1,
                _ => 0,
            };

            let res = var.process_ac_match(region.mem, m, start_position, match_type);

            #[cfg(feature = "profiling")]
            {
                if let Some(stats) = scan_data.statistics.as_mut() {
                    stats.ac_confirm_duration += start_instant.elapsed();
                }
            }

            match res {
                AcMatchStatus::None => (),
                AcMatchStatus::Multiple(v) if v.is_empty() => (),
                AcMatchStatus::Multiple(found_matches) => {
                    var_matches.extend(found_matches.into_iter().map(|m| {
                        StringMatch::new(region, m, scan_data.params.match_max_length, 0)
                    }));
                }
                AcMatchStatus::Single(m) => {
                    let xor_key = var.get_xor_key(literal_index);
                    var_matches.push(StringMatch::new(
                        region,
                        m,
                        scan_data.params.match_max_length,
                        xor_key,
                    ));
                }
            }

            if var_matches.len() > (scan_data.params.string_max_nb_matches as usize) {
                var_matches.truncate(scan_data.params.string_max_nb_matches as usize);
                if (scan_data.params.callback_events & CallbackEvents::STRING_REACHED_MATCH_LIMIT).0
                    != 0
                    && scan_data.string_reached_match_limit.insert(variable_index)
                {
                    if let Some(cb) = &mut scan_data.callback {
                        if let Some(string_identifier) =
                            build_string_identifier(scanner, variable_index)
                        {
                            match (cb)(ScanEvent::StringReachedMatchLimit(string_identifier)) {
                                ScanCallbackResult::Continue => (),
                                ScanCallbackResult::Abort => return Err(ScanError::CallbackAbort),
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn scan_single_variable(
    region: &Region,
    matcher: &Matcher,
    scan_data: &mut ScanData,
    string_matches: &mut Vec<StringMatch>,
) {
    let mut offset = 0;
    while offset < region.mem.len() {
        let mat = matcher.find_next_match_at(region.mem, offset);

        match mat {
            None => break,
            Some(mat) => {
                offset = mat.start + 1;
                string_matches.push(StringMatch::new(
                    region,
                    mat,
                    scan_data.params.match_max_length,
                    // No xor key, since this function is only used for regex variables
                    0,
                ));

                // This is safe to allow because this is called on every iterator of self.matches, so
                // it cannot overflow u32 before this condition is true.
                #[allow(clippy::cast_possible_truncation)]
                if (string_matches.len() as u32) >= scan_data.params.string_max_nb_matches {
                    break;
                }
            }
        }
    }
}

fn build_string_identifier(
    scanner: &super::Inner,
    variable_index: usize,
) -> Option<StringIdentifier> {
    let mut index = 0;
    // Go through all the rules of the scanner to find the right one.
    // This is O(n) on the rules, which isn't ideal. But this is only done
    // iff:
    // - the callback API is used
    // - the "string reaches match limit" event is enabled
    // - a string reaches the match limit
    // This thus should not be called frequently, and a O(n) search through
    // the rules should not take that long.
    //
    // A solution to improve this would be to store in each rule the index
    // of its first variable, which would make a binary search through
    // the rules possible. However, this means an additional word to store
    // with each rule, only to alleviate this very specific event. For
    // the moment, this is not considered to be worth the cost.
    for rule in scanner.global_rules.iter().chain(scanner.rules.iter()) {
        if index + rule.nb_variables > variable_index {
            return Some(StringIdentifier {
                rule_namespace: scanner.namespaces[rule.namespace_index].as_ref(),
                rule_name: &rule.name,
                string_name: &scanner.variables[variable_index].name,
                string_index: variable_index - index,
            });
        }
        index += rule.nb_variables;
    }
    // Should technically be impossible to reach.
    debug_assert!(false);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(AcScan::new(&[], CompilerProfile::Speed));
        test_type_traits_non_clonable(LiteralInfo {
            variable_index: 0,
            literal_index: 0,
            slice_offset: (0, 0),
        });
    }
}
