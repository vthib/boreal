use std::ops::Range;
use std::sync::Arc;

use regex_automata::hybrid::dfa::{Builder, Cache, DFA};
use regex_automata::nfa::thompson;
use regex_automata::util::pool::Pool;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind, PatternID};

use crate::regex::{regex_hir_to_string, Hir};

use super::analysis::{analyze_hir, HirAnalysis};
use super::widener::widen_hir;
use super::{MatchType, Matches, Modifiers};

type PoolCreateFn = Box<dyn Fn() -> Cache + Send + Sync>;

// Maximum length against which a regex validator of a AC literal match will be run.
//
// For example, lets say you have the `{ AA [1-] BB CC DD [1-] FF }` hex string. The
// `\xbb\xcc\xdd` literal is extracted, with:
// - the pre validator `\xaa.{1,}?\xbb\xcc\xdd$`
// - the post validator `^\xbb\xcc\xdd.{1,}?\xff`
//
// Both the pre and post validator will be run against a slice which maximum length is
// limited by the constant. Which means that `\xaa0\xbb\xcc\xdd` + ('0' * MAX+1) + '\xff'
// will not match.
const MAX_SPLIT_MATCH_LENGTH: usize = 4096;

#[derive(Debug)]
pub(super) enum Validator {
    NonGreedy {
        forward: Option<DfaValidator>,
        reverse: Option<DfaValidator>,
    },
    Greedy {
        reverse: DfaValidator,
        full: DfaValidator,
    },
}

impl Validator {
    pub(super) fn new(
        pre: Option<&Hir>,
        post: Option<&Hir>,
        full: &Hir,
        modifiers: Modifiers,
    ) -> Result<Self, crate::regex::Error> {
        let reverse = match pre {
            Some(pre) => {
                let left_analysis = analyze_hir(pre, modifiers.dot_all);

                // XXX: If the left HIR has greedy repetitions, then the HIR cannot be split into a
                // (left, literals, right) triplet. This is because the greedy repetitions can
                // "eat" the literals, leading to incorrect matches.
                //
                // For example, a regex that looks like: `a.+foo.b` will extract the literal foo,
                // but against the string `aafoobbaafoobb`, it will match on the entire string,
                // while a (pre, post) matching would match twice.
                if left_analysis.has_greedy_repetitions {
                    let reverse = DfaValidator::new(pre, &left_analysis, modifiers, true)?;

                    let full_analysis = analyze_hir(full, modifiers.dot_all);
                    let full = DfaValidator::new(full, &full_analysis, modifiers, false)?;

                    return Ok(Self::Greedy { reverse, full });
                }

                Some(DfaValidator::new(pre, &left_analysis, modifiers, true)?)
            }
            None => None,
        };

        let forward = match post {
            Some(hir) => {
                let analysis = analyze_hir(hir, modifiers.dot_all);
                Some(DfaValidator::new(hir, &analysis, modifiers, false)?)
            }
            None => None,
        };

        Ok(Self::NonGreedy { forward, reverse })
    }

    pub(super) fn validate_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
        match_type: MatchType,
    ) -> Matches {
        match self {
            Self::NonGreedy { forward, reverse } => {
                let end = match forward {
                    Some(validator) => {
                        let end = std::cmp::min(
                            mem.len(),
                            mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH),
                        );
                        match validator.find_anchored_fwd(mem, mat.start, end, match_type) {
                            Some(end) => end,
                            None => return Matches::None,
                        }
                    }
                    None => mat.end,
                };

                match reverse {
                    None => Matches::Single(mat.start..end),
                    Some(validator) => {
                        // The left validator can yield multiple matches.
                        // For example, `a.?bb`, with the `bb` atom, can match as many times as there are
                        // 'a' characters before the `bb` atom.
                        let mut matches = Vec::new();
                        let mut start = std::cmp::max(
                            start_position,
                            mat.end.saturating_sub(MAX_SPLIT_MATCH_LENGTH),
                        );
                        while let Some(s) =
                            validator.find_anchored_rev(mem, start, mat.end, match_type)
                        {
                            matches.push(s..end);
                            start = s + 1;
                            if start > mat.end {
                                break;
                            }
                        }
                        Matches::Multiple(matches)
                    }
                }
            }
            Self::Greedy { reverse, full } => {
                let mut matches = Vec::new();

                let mut start = std::cmp::max(
                    start_position,
                    mat.end.saturating_sub(MAX_SPLIT_MATCH_LENGTH),
                );
                let end =
                    std::cmp::min(mem.len(), mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH));

                while let Some(s) = reverse.find_anchored_rev(mem, start, mat.end, match_type) {
                    if let Some(e) = full.find_anchored_fwd(mem, s, end, match_type) {
                        matches.push(s..e);
                    }
                    start = s + 1;
                    if start > mat.end {
                        break;
                    }
                }

                Matches::Multiple(matches)
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct DfaValidator {
    /// Anchored lazy DFA, used to validate an AC match.
    dfa: Arc<DFA>,
    // TODO: Taking the cache out of the pool when starting scanning (and putting them in the scan
    // data) would avoid the get/drop on every validation, and only do it once per scan.
    // Not sure how much improvements this would be, to test.
    pool: Pool<Cache, PoolCreateFn>,

    /// Use the custom wide routine to validate wide matches.
    ///
    /// If true, a custom routine is used to run the dfa (with the ascii pattern) step by step on
    /// "unwidened" input.
    ///
    /// This is only used when the regex contains word boundaries, which cannot be translated into
    /// a corresponding "widened" HIR.
    use_custom_wide_runner: bool,
}

impl DfaValidator {
    pub(super) fn new(
        hir: &Hir,
        analysis: &HirAnalysis,
        mut modifiers: Modifiers,
        reverse: bool,
    ) -> Result<Self, crate::regex::Error> {
        let mut use_custom_wide_runner = false;

        if analysis.has_word_boundaries && modifiers.wide {
            use_custom_wide_runner = true;
            // Do not built the wide version of the regex, since it will not be used, only
            // the ascii version will be, either normally for ascii matches (if modifiers.ascii
            // is also true), or with the custom routine for wide matches.
            modifiers.wide = false;
        }

        let dfa = Arc::new(build_dfa(hir, modifiers, reverse).map_err(crate::regex::Error::from)?);
        let pool = {
            let dfa = Arc::clone(&dfa);
            let create: PoolCreateFn = Box::new(move || dfa.create_cache());
            Pool::new(create)
        };

        Ok(Self {
            dfa,
            pool,
            use_custom_wide_runner,
        })
    }

    pub(super) fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        match_type: MatchType,
    ) -> Option<usize> {
        let mut cache = self.pool.get();

        if self.use_custom_wide_runner && match_type.is_wide() {
            self.find_wide_anchored_fwd(&mut cache, haystack, start, end)
        } else {
            let pattern_index = match_type_to_pattern_index(match_type);
            self.dfa
                .try_search_fwd(
                    &mut cache,
                    &Input::new(haystack)
                        .span(start..end)
                        .anchored(Anchored::Pattern(pattern_index)),
                )
                .ok()
                .flatten()
                .map(|m| m.offset())
        }
    }

    pub(super) fn find_anchored_rev(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        match_type: MatchType,
    ) -> Option<usize> {
        let mut cache = self.pool.get();

        if self.use_custom_wide_runner && match_type.is_wide() {
            self.find_wide_anchored_rev(&mut cache, haystack, start, end)
        } else {
            let pattern_index = match_type_to_pattern_index(match_type);
            self.dfa
                .try_search_rev(
                    &mut cache,
                    &Input::new(haystack)
                        .span(start..end)
                        .anchored(Anchored::Pattern(pattern_index)),
                )
                .ok()
                .flatten()
                .map(|m| m.offset())
        }
    }

    // Custom runner that steps through the DFA automaton, skipping the nul bytes of
    // the wide input.
    //
    // XXX: this uses the example seen in
    // <https://docs.rs/regex-automata/latest/regex_automata/dfa/trait.Automaton.html#tymethod.is_special_state>
    // to run the automaton correctly.
    fn find_wide_anchored_fwd(
        &self,
        cache: &mut Cache,
        mem: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let start_input = get_unwidened_start(mem, start);
        let input = match start_input.as_ref() {
            None => Input::new("").anchored(Anchored::Yes),
            Some(v) => Input::new(v).span(1..2).anchored(Anchored::Yes),
        };
        let mut state = self.dfa.start_state_forward(cache, &input).ok()?;

        let mut last_match = None;
        let mut i = start;
        while i < end {
            // Ensure the current byte is a wide byte, otherwise is input is no longer wide,
            // and we must end the search.
            if i + 1 < end && mem[i + 1] != b'\0' {
                break;
            }
            let b = mem[i];
            state = self.dfa.next_state(cache, state, b).ok()?;
            if state.is_tagged() {
                if state.is_match() {
                    last_match = Some(i);
                } else if state.is_dead() {
                    return last_match;
                }
            }

            i += 2;
        }
        // Matches are always delayed by 1 byte, so we must explicitly walk
        // the special "EOI" transition at the end of the search.
        state = self.dfa.next_eoi_state(cache, state).ok()?;
        if state.is_match() {
            last_match = Some(end);
        }

        last_match
    }

    // Custom runner that steps through the DFA automaton, skipping the nul bytes of
    // the wide input.
    //
    // XXX: this uses the example seen in
    // <https://docs.rs/regex-automata/latest/regex_automata/dfa/trait.Automaton.html#tymethod.is_special_state>
    // to run the automaton correctly.
    fn find_wide_anchored_rev(
        &self,
        cache: &mut Cache,
        mem: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let end_input = get_unwidened_end(mem, end);
        let input = match end_input.as_ref() {
            None => Input::new("").anchored(Anchored::Yes),
            Some(v) => Input::new(v).anchored(Anchored::Yes),
        };
        let mut state = self.dfa.start_state_reverse(cache, &input).ok()?;

        if end - start < 2 {
            state = self.dfa.next_eoi_state(cache, state).ok()?;
            return state.is_match().then_some(end);
        }

        let mut last_match = None;
        let mut i = end;
        loop {
            // Ensure the current byte is a wide byte, otherwise is input is no longer wide,
            // and we must end the search.
            if i - start < 2 || mem[i - 1] != b'\0' {
                break;
            }
            i -= 2;

            let b = mem[i];
            state = self.dfa.next_state(cache, state, b).ok()?;
            if state.is_tagged() {
                if state.is_match() {
                    // We need to add 2, since the match state is 1 byte past the real match.
                    last_match = Some(i + 2);
                } else if state.is_dead() {
                    return last_match;
                }
            }
        }
        // Matches are always delayed by 1 byte, so we must explicitly walk
        // the special "EOI" transition at the end of the search.
        state = self.dfa.next_eoi_state(cache, state).ok()?;
        if state.is_match() {
            last_match = Some(i);
        }

        last_match
    }
}

// Return an input that can be used to start the DFA on wide input.
//
// To handle word boundaries, the input must be created to reflect the previous byte.
fn get_unwidened_start(mem: &[u8], start: usize) -> Option<[u8; 2]> {
    if start < 2 || mem[start - 1] != b'\0' {
        None
    } else {
        Some([mem[start - 2], mem[start]])
    }
}

fn get_unwidened_end(mem: &[u8], end: usize) -> Option<[u8; 2]> {
    if end + 2 >= mem.len() || mem[end + 1] != b'\0' {
        None
    } else {
        Some([mem[end], mem[end + 2]])
    }
}

fn match_type_to_pattern_index(match_type: MatchType) -> PatternID {
    PatternID::new_unchecked(match match_type {
        MatchType::Ascii | MatchType::WideStandard => 0,
        MatchType::WideAlternate => 1,
    })
}

fn build_dfa(hir: &Hir, modifiers: Modifiers, reverse: bool) -> Result<DFA, crate::regex::Error> {
    let mut builder = Builder::new();
    let _b = builder
        .configure(
            DFA::config()
                .prefilter(None)
                .starts_for_each_pattern(true)
                .match_kind(if reverse {
                    MatchKind::All
                } else {
                    MatchKind::LeftmostFirst
                }),
        )
        .thompson(
            thompson::Config::new()
                .utf8(false)
                .reverse(reverse)
                .nfa_size_limit(Some(10 * (1 << 20))),
        )
        .syntax(
            syntax::Config::new()
                .octal(false)
                .unicode(false)
                .utf8(false)
                .multi_line(false)
                .case_insensitive(modifiers.nocase)
                .dot_matches_new_line(modifiers.dot_all),
        );

    if modifiers.wide {
        let wide_hir = widen_hir(hir);

        if modifiers.ascii {
            builder.build_many(&[regex_hir_to_string(hir), regex_hir_to_string(&wide_hir)])
        } else {
            builder.build(&regex_hir_to_string(&wide_hir))
        }
    } else {
        builder.build(&regex_hir_to_string(hir))
    }
    .map_err(crate::regex::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{parse_regex_string, test_type_traits_non_clonable};

    #[test]
    fn test_types_traits() {
        let analysis = analyze_hir(&Hir::Empty, false);
        test_type_traits_non_clonable(
            DfaValidator::new(&Hir::Empty, &analysis, Modifiers::default(), false).unwrap(),
        );
        test_type_traits_non_clonable(
            Validator::new(None, None, &Hir::Empty, Modifiers::default()).unwrap(),
        );
    }

    #[test]
    fn test_find_wide_anchored_fwd() {
        fn build(expr: &str, ascii: bool) -> DfaValidator {
            let regex = parse_regex_string(expr);
            let hir = regex.ast.into();
            let analysis = analyze_hir(&hir, false);
            DfaValidator::new(
                &hir,
                &analysis,
                Modifiers {
                    ascii,
                    wide: true,
                    ..Default::default()
                },
                false,
            )
            .unwrap()
        }

        let validator = build(r"a\b", false);
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b\0.\0a\0.\0", 0, 10, MatchType::WideStandard),
            None
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b\0.\0a\0.\0", 6, 10, MatchType::WideStandard),
            Some(8)
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0", 0, 2, MatchType::WideStandard),
            Some(2)
        );
        assert_eq!(
            validator.find_anchored_fwd(b"aa\0", 0, 3, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_fwd(b"aa\0", 1, 3, MatchType::WideStandard),
            Some(3)
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b\0.\0", 4, 4, MatchType::WideStandard),
            None
        );

        let validator = build(r"\bb", false);
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b\0", 0, 4, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_fwd(b"b\0b\0", 0, 4, MatchType::WideStandard),
            Some(2),
        );
        assert_eq!(
            validator.find_anchored_fwd(b"b\0b\0", 2, 4, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_fwd(b".\0b\0", 2, 4, MatchType::WideStandard),
            Some(4),
        );
        assert_eq!(
            validator.find_anchored_fwd(b"\0b\0", 1, 3, MatchType::WideStandard),
            Some(3),
        );

        // Ensure the validator does not confuse ascii and wide
        let validator = build(r"a\x00b\b", true);
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b", 0, 3, MatchType::Ascii),
            Some(3)
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b\0", 0, 4, MatchType::Ascii),
            Some(3)
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b\0b\0", 0, 6, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0\0\0b\0", 0, 6, MatchType::WideStandard),
            Some(6),
        );

        let validator = build(r"\b", false);
        assert_eq!(
            validator.find_anchored_fwd(b"", 0, 0, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0", 0, 2, MatchType::WideStandard),
            Some(0),
        );
    }

    #[test]
    fn test_find_wide_anchored_rev() {
        fn build(expr: &str, ascii: bool) -> DfaValidator {
            let regex = parse_regex_string(expr);
            let hir = regex.ast.into();
            let analysis = analyze_hir(&hir, false);
            DfaValidator::new(
                &hir,
                &analysis,
                Modifiers {
                    ascii,
                    wide: true,
                    ..Default::default()
                },
                true,
            )
            .unwrap()
        }

        let validator = build(r"a\b", false);
        assert_eq!(
            validator.find_anchored_rev(b"a\0b\0.\0a\0.\0", 0, 10, MatchType::WideStandard),
            None
        );
        assert_eq!(
            validator.find_anchored_rev(b"a\0b\0.\0a\0.\0", 0, 9, MatchType::WideStandard),
            None
        );
        assert_eq!(
            validator.find_anchored_rev(b"a\0b\0.\0a\0.\0", 0, 8, MatchType::WideStandard),
            Some(6)
        );
        assert_eq!(
            validator.find_anchored_rev(b"a\0", 0, 2, MatchType::WideStandard),
            Some(0)
        );
        assert_eq!(
            validator.find_anchored_rev(b"aa\0", 0, 3, MatchType::WideStandard),
            Some(1),
        );
        assert_eq!(
            validator.find_anchored_rev(b"aa\0", 0, 2, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_rev(b"aa\0", 0, 1, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_rev(b"", 0, 0, MatchType::WideStandard),
            None,
        );

        let validator = build(r"\bb", false);
        assert_eq!(
            validator.find_anchored_rev(b"a\0b\0", 0, 4, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_rev(b".\0b\0", 0, 4, MatchType::WideStandard),
            Some(2),
        );
        assert_eq!(
            validator.find_anchored_rev(b"b\0b\0", 0, 4, MatchType::WideStandard),
            None,
        );
        assert_eq!(
            validator.find_anchored_rev(b"b\0b\0", 2, 4, MatchType::WideStandard),
            Some(2),
        );
        assert_eq!(
            validator.find_anchored_rev(b"b\0b\0", 0, 2, MatchType::WideStandard),
            Some(0),
        );
        assert_eq!(
            validator.find_anchored_rev(b"\0b\0", 0, 3, MatchType::WideStandard),
            Some(1),
        );
        assert_eq!(
            validator.find_anchored_rev(b"b\0", 0, 2, MatchType::WideStandard),
            Some(0),
        );
        assert_eq!(
            validator.find_anchored_rev(b"b", 0, 1, MatchType::WideStandard),
            None,
        );
    }
}
