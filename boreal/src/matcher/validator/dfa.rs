use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use regex_automata::hybrid::dfa::{Builder, Cache, DFA};
use regex_automata::nfa::thompson;
use regex_automata::util::pool::Pool;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind, PatternID};

use crate::matcher::analysis::HirAnalysis;
use crate::matcher::widener::widen_hir;
use crate::matcher::{MatchType, Modifiers};
use crate::regex::{regex_hir_to_string, Hir};

type PoolCreateFn = Box<dyn Fn() -> Cache + Send + Sync + UnwindSafe + RefUnwindSafe>;

#[derive(Debug)]
pub(crate) struct DfaValidator {
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

    /// Saved expressions of the regex.
    ///
    /// Only used for serialization.
    #[cfg(feature = "serialize")]
    exprs: [Box<str>; 2],
}

#[cfg(feature = "serialize")]
impl PartialEq for DfaValidator {
    fn eq(&self, other: &Self) -> bool {
        self.use_custom_wide_runner == other.use_custom_wide_runner && self.exprs == other.exprs
    }
}

impl DfaValidator {
    pub(crate) fn new(
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

        let (expr1, expr2) = if modifiers.wide {
            let wide_hir = widen_hir(hir);

            if modifiers.ascii {
                (regex_hir_to_string(hir), regex_hir_to_string(&wide_hir))
            } else {
                (regex_hir_to_string(&wide_hir), String::new())
            }
        } else {
            (regex_hir_to_string(hir), String::new())
        };
        let dfa = Arc::new(build_dfa(&expr1, &expr2, modifiers, reverse)?);
        let pool = {
            let dfa = Arc::clone(&dfa);
            let create: PoolCreateFn = Box::new(move || dfa.create_cache());
            Pool::new(create)
        };

        Ok(Self {
            dfa,
            pool,
            use_custom_wide_runner,
            #[cfg(feature = "serialize")]
            exprs: [expr1.into_boxed_str(), expr2.into_boxed_str()],
        })
    }

    #[cfg(feature = "serialize")]
    pub(super) fn deserialize<R: std::io::Read>(
        modifiers: Modifiers,
        reverse: bool,
        reader: &mut R,
    ) -> std::io::Result<Self> {
        wire::deserialize_dfa_validator(modifiers, reverse, reader)
    }

    pub(crate) fn find_anchored_fwd(
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

    pub(crate) fn find_anchored_rev(
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
            if i + 1 >= end || mem[i + 1] != b'\0' {
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
            last_match = Some(i);
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

fn build_dfa(
    expr1: &str,
    expr2: &str,
    modifiers: Modifiers,
    reverse: bool,
) -> Result<DFA, crate::regex::Error> {
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

    if expr2.is_empty() {
        builder.build(expr1)
    } else {
        builder.build_many(&[expr1, expr2])
    }
    .map_err(crate::regex::Error::from)
}

#[cfg(feature = "serialize")]
mod wire {
    use std::{io, sync::Arc};

    use crate::wire::{Deserialize, Serialize};
    use regex_automata::util::pool::Pool;

    use crate::matcher::Modifiers;

    use super::{build_dfa, DfaValidator, PoolCreateFn};

    impl Serialize for DfaValidator {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.exprs[0].serialize(writer)?;
            self.exprs[1].serialize(writer)?;
            self.use_custom_wide_runner.serialize(writer)?;
            Ok(())
        }
    }

    pub(super) fn deserialize_dfa_validator<R: io::Read>(
        modifiers: Modifiers,
        reverse: bool,
        reader: &mut R,
    ) -> io::Result<DfaValidator> {
        let expr1 = String::deserialize_reader(reader)?;
        let expr2 = String::deserialize_reader(reader)?;
        let use_custom_wide_runner = bool::deserialize_reader(reader)?;

        let dfa = Arc::new(
            build_dfa(&expr1, &expr2, modifiers, reverse).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unable to compile dfa with expressions \
                            `{expr1}`, `{expr2}`: {err:?}",
                    ),
                )
            })?,
        );
        let pool = {
            let dfa = Arc::clone(&dfa);
            let create: PoolCreateFn = Box::new(move || dfa.create_cache());
            Pool::new(create)
        };

        Ok(DfaValidator {
            dfa,
            pool,
            use_custom_wide_runner,
            exprs: [expr1.into_boxed_str(), expr2.into_boxed_str()],
        })
    }

    #[cfg(test)]
    mod tests {
        use crate::matcher::analysis::analyze_hir;
        use crate::regex::Hir;
        use crate::wire::tests::test_round_trip_custom_deser;

        use super::*;

        #[test]
        fn test_wire_dfa_validator() {
            let hir = Hir::Dot;
            let analysis = analyze_hir(&hir, true);
            let modifiers = Modifiers::default();
            test_round_trip_custom_deser(
                &DfaValidator::new(&hir, &analysis, modifiers, true).unwrap(),
                |reader| deserialize_dfa_validator(modifiers, true, reader),
                &[0, 7, 9],
            );

            // Test failure when compiling expressions.
            let mut reader = io::Cursor::new(b"\x01\x00\x00\x00[\x00\x00\x00\x00\x01");
            assert!(deserialize_dfa_validator(modifiers, true, &mut reader).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        matcher::analysis::analyze_hir,
        test_helpers::{expr_to_hir, test_type_traits_non_clonable},
    };

    #[test]
    fn test_types_traits() {
        let analysis = analyze_hir(&Hir::Empty, false);
        test_type_traits_non_clonable(
            DfaValidator::new(&Hir::Empty, &analysis, Modifiers::default(), false).unwrap(),
        );
    }

    #[test]
    fn test_find_wide_anchored_fwd() {
        fn build(expr: &str, ascii: bool) -> DfaValidator {
            let hir = expr_to_hir(expr);
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
            validator.find_anchored_fwd(b"a\0bb", 0, 4, MatchType::WideStandard),
            Some(2)
        );
        assert_eq!(
            validator.find_anchored_fwd(b"a\0b", 0, 3, MatchType::WideStandard),
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
            validator.find_anchored_fwd(b"b\0b", 0, 3, MatchType::WideStandard),
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
            let hir = expr_to_hir(expr);
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
            validator.find_anchored_rev(b"\0a\0", 0, 3, MatchType::WideStandard),
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
