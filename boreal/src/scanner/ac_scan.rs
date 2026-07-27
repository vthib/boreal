//! Provides the [`AcScan`] object, used to scan for all variables in a single AC pass.
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};

use super::{
    CallbackEvents, ScanCallbackResult, ScanData, ScanError, ScanEvent, StringIdentifier,
    StringMatch,
};
use crate::atoms::pick_atom_in_literal;
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
    aho_index_to_literal_info: Box<[Box<[LiteralInfo]>]>,

    /// List of indexes for vars that are not part of the aho corasick.
    non_handled_var_indexes: Box<[usize]>,
}

/// Details on a literal of a matcher.
#[derive(Debug)]
struct LiteralInfo {
    /// Index of the matcher in the matcher array.
    matcher_index: usize,

    /// Index of the literal for the matcher.
    literal_index: usize,

    /// Left and right offset for the slice picked in the Aho-Corasick.
    slice_offset: (usize, usize),
}

impl AcScan {
    pub(crate) fn new(matchers: &[Matcher], profile: CompilerProfile) -> Self {
        let mut lits = Vec::new();
        let mut known_lits = HashMap::new();
        let mut aho_index_to_literal_info = Vec::new();
        let mut non_handled_var_indexes = Vec::new();

        for (matcher_index, matcher) in matchers.iter().enumerate() {
            if matcher.literals.is_empty() {
                non_handled_var_indexes.push(matcher_index);
            } else {
                let mut known_literals_of_var = HashSet::new();

                for (literal_index, lit) in matcher.literals.iter().enumerate() {
                    let (start, end) = pick_atom_in_literal(lit);
                    let mut atom = lit[start..(lit.len() - end)].to_vec();
                    let literal_info = LiteralInfo {
                        matcher_index,
                        literal_index,
                        slice_offset: (start, end),
                    };

                    // Sometimes, two literals of the same variable can provide the same atom.
                    // This can happen if the two literals are identical (for example, someone
                    // like me writing a test on `/(abc|abc)/`), or if the literals are
                    // different but contain the same atom (for example,
                    // `{ ( 00 AB CD | AB CD 00 ) }`).
                    //
                    // In those cases, we must *not* use the same atom twice in the Aho-Corasick,
                    // as this would result in two identical matches for the same variable.
                    // To prevent this, a set is used here. Both the atom itself and its position
                    // in the literal are important.
                    {
                        let mut dedup_atom = atom.clone();

                        // See `test_nocase_alternate_case` test. If the variable is "nocase",
                        // then make sure we don't add to the AC two different atoms that
                        // results in the same lowercase string. This shouldn't be done outside
                        // of the "nocase" scenario, since different cases will be validated
                        // properly against each literal.
                        if matcher.modifiers.nocase {
                            dedup_atom.make_ascii_lowercase();
                        }

                        if !known_literals_of_var.insert((dedup_atom, start)) {
                            continue;
                        }
                    }

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
            aho_index_to_literal_info: aho_index_to_literal_info
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect(),
            non_handled_var_indexes: non_handled_var_indexes.into_boxed_slice(),
        }
    }

    pub(super) fn scan_region<'scanner>(
        &self,
        region: &Region,
        scanner: &'scanner super::Inner,
        scan_data: &mut ScanData<'scanner, '_>,
        all_matches: &mut [Vec<StringMatch>],
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
            self.handle_possible_match(region, scanner, &mat, scan_data, all_matches)?;
        }

        if !self.non_handled_var_indexes.is_empty() {
            #[cfg(feature = "profiling")]
            let start = scan_data.statistics.is_some().then(std::time::Instant::now);

            // For every "raw" matcher, scan the memory for this matcher.
            for matcher_index in &self.non_handled_var_indexes {
                let matcher = &scanner.matchers[*matcher_index];

                scan_single_matcher(region, matcher, scan_data, &mut all_matches[*matcher_index]);
            }

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                if let Some(start) = start {
                    stats.raw_regexes_eval_duration += start.elapsed();
                }
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
        all_matches: &mut [Vec<StringMatch>],
    ) -> Result<(), ScanError> {
        for literal_info in &self.aho_index_to_literal_info[mat.pattern()] {
            let LiteralInfo {
                matcher_index,
                literal_index,
                slice_offset: (start_offset, end_offset),
            } = *literal_info;
            let matcher = &scanner.matchers[matcher_index];

            #[cfg(feature = "profiling")]
            if let Some(stats) = scan_data.statistics.as_mut() {
                stats.nb_ac_matches += 1;
            }
            #[cfg(feature = "profiling")]
            let start_instant = scan_data.statistics.is_some().then(std::time::Instant::now);

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
            let Some(match_type) = matcher.confirm_ac_literal(region.mem, &m, literal_index) else {
                continue;
            };

            let var_matches = &mut all_matches[matcher_index];

            // Shorten the mem to prevent new matches on the same starting byte.
            // For example, for `a.*?bb`, and input `abbb`, this can happen:
            //
            // - extract atom `bb`
            // - get AC match on `a(bb)b`: call check_ac_match, this will return the
            //   match `(abb)b`.
            // - get AC match on `ab(bb)`: call check_ac_match, this will return the
            //   match `(abbb)`.
            //
            // This is invalid, only one match per starting byte can happen.
            // To avoid this, ensure the mem given to check_ac_match starts one byte after the last
            // saved match.
            //
            // Do not do so if the reverse validator is greedy however: in that case,
            // we actually want to replace previous matches with new, longer ones, if they
            // share the same start.
            let mut start_position = 0;
            if let Some(mat) = var_matches.last() {
                if mat.base == region.start && !matcher.has_greedy_reverse_validator() {
                    start_position = mat.offset + 1;
                }
            }

            let res = matcher.process_ac_match(region.mem, m, start_position, match_type);

            #[cfg(feature = "profiling")]
            {
                if let Some(stats) = scan_data.statistics.as_mut() {
                    if let Some(start_instant) = start_instant {
                        stats.ac_confirm_duration += start_instant.elapsed();
                    }
                }
            }

            match res {
                AcMatchStatus::None => (),
                AcMatchStatus::Multiple(found_matches) => {
                    for new_match in found_matches {
                        let new_match = StringMatch::new(
                            region,
                            new_match,
                            scan_data.params.match_max_length,
                            0,
                        );
                        add_match(matcher, new_match, var_matches);
                    }
                }
                AcMatchStatus::Single(m) => {
                    let xor_key = matcher.get_xor_key(literal_index);
                    let new_match =
                        StringMatch::new(region, m, scan_data.params.match_max_length, xor_key);
                    add_match(matcher, new_match, var_matches);
                }
            }

            if var_matches.len() > (scan_data.params.string_max_nb_matches as usize) {
                var_matches.truncate(scan_data.params.string_max_nb_matches as usize);
                if (scan_data.params.callback_events & CallbackEvents::STRING_REACHED_MATCH_LIMIT).0
                    != 0
                    && scan_data.string_reached_match_limit.insert(matcher_index)
                {
                    if let Some(cb) = &mut scan_data.callback {
                        if let Some(string_identifier) =
                            build_string_identifier(scanner, matcher_index)
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

fn add_match(matcher: &Matcher, new_match: StringMatch, var_matches: &mut Vec<StringMatch>) {
    // XXX: If the left HIR has greedy repetitions, then the reverse validator
    // may give matches that replaces existing matches.
    //
    // For example, a regex that looks like: `a.+foo.b` will extract the literal foo,
    // but against the string `aafoobbaafoobb`, the only match should be the
    // entire string. A first `foo` AC match will result in `aafoobb` being found,
    // but the second `foo` AC match should then replace the first match.
    //
    // To handle this, we search into the existing matches if there are existing matches
    // at the same offset. If there are, we replace them, since the longest match always
    // wins.
    if matcher.has_greedy_reverse_validator() {
        match var_matches
            .binary_search_by_key(&(new_match.base + new_match.offset), |m| m.base + m.offset)
        {
            Ok(position) => var_matches[position] = new_match,
            Err(_) => var_matches.push(new_match),
        }
    } else {
        var_matches.push(new_match);
    }
}

fn scan_single_matcher(
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
                    // No xor key, since this function is only used for regex matchers
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
    matcher_index: usize,
) -> Option<StringIdentifier<'_>> {
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
    // of its first matcher, which would make a binary search through
    // the rules possible. However, this means an additional word to store
    // with each rule, only to alleviate this very specific event. For
    // the moment, this is not considered to be worth the cost.
    for rule in scanner.global_rules.iter().chain(scanner.rules.iter()) {
        if index + rule.variables.len() > matcher_index {
            let string_index = matcher_index - index;
            return Some(StringIdentifier {
                rule_namespace: scanner.namespaces[rule.namespace_index].as_ref(),
                rule_name: &rule.name,
                string_name: scanner
                    .bytes_pool
                    .get_str(rule.variables[string_index].name),
                string_index,
            });
        }
        index += rule.variables.len();
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
            matcher_index: 0,
            literal_index: 0,
            slice_offset: (0, 0),
        });
    }
}
