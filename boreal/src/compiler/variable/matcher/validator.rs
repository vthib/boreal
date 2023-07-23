use std::ops::Range;
use std::sync::Arc;

use boreal_parser::VariableModifiers;
use regex_automata::hybrid::dfa::{Builder, Cache, DFA};
use regex_automata::nfa::thompson;
use regex_automata::util::pool::Pool;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind, PatternID};

use crate::regex::{regex_hir_to_string, Hir};

use super::widener::widen_hir;
use super::{MatchType, Matches};

type PoolCreateFn = Box<dyn Fn() -> Cache + Send + Sync>;

const MAX_SPLIT_MATCH_LENGTH: usize = 4096;

#[derive(Debug)]
pub struct Validator {
    forward: Option<ForwardValidator>,
    reverse: Option<ReverseValidator>,
}

impl Validator {
    pub fn new(
        pre: Option<&Hir>,
        post: Option<&Hir>,
        modifiers: &VariableModifiers,
        dot_all: bool,
    ) -> Result<Self, crate::regex::Error> {
        Ok(Self {
            forward: match post {
                Some(hir) => Some(ForwardValidator::new(hir, modifiers, dot_all)?),
                None => None,
            },
            reverse: match pre {
                Some(hir) => Some(ReverseValidator::new(hir, modifiers, dot_all)?),
                None => None,
            },
        })
    }

    pub fn validate_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
        match_type: MatchType,
    ) -> Matches {
        let pattern_index = match_type_to_pattern_index(match_type);

        let end = match &self.forward {
            Some(validator) => {
                let end =
                    std::cmp::min(mem.len(), mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH));
                match validator.find_anchored_fwd(mem, mat.start, end, pattern_index) {
                    Some(end) => end,
                    None => return Matches::None,
                }
            }
            None => mat.end,
        };

        match &self.reverse {
            None => Matches::Single(mat.start..end),
            Some(validator) => {
                // The left validator can yield multiple matches.
                // For example, `a.?bb`, with the `bb` atom, can match as many times as there are
                // 'a' characters before the `bb` atom.
                //
                // XXX: This only works if the left validator does not contain any greedy repetitions!
                let mut matches = Vec::new();
                let mut start = std::cmp::max(
                    start_position,
                    mat.end.saturating_sub(MAX_SPLIT_MATCH_LENGTH),
                );
                while let Some(s) = validator.find_anchored_rev(mem, start, mat.end, pattern_index)
                {
                    matches.push(s..end);
                    start = s + 1;
                }
                Matches::Multiple(matches)
            }
        }
    }
}

#[derive(Debug)]
struct ForwardValidator {
    dfa: Arc<DFA>,
    // TODO: Taking the cache out of the pool when starting scanning (and putting them in the scan
    // data) would avoid the get/drop on every validation, and only do it once per scan.
    // Not sure how much improvements this would be, to test.
    pool: Pool<Cache, PoolCreateFn>,
}

impl ForwardValidator {
    pub fn new(
        hir: &Hir,
        modifiers: &VariableModifiers,
        dot_all: bool,
    ) -> Result<Self, crate::regex::Error> {
        let dfa =
            Arc::new(build_dfa(hir, modifiers, dot_all, false).map_err(crate::regex::Error::from)?);
        let pool = {
            let dfa = Arc::clone(&dfa);
            let create: PoolCreateFn = Box::new(move || dfa.create_cache());
            Pool::new(create)
        };

        Ok(Self { dfa, pool })
    }

    pub fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        pattern_index: PatternID,
    ) -> Option<usize> {
        let mut cache = self.pool.get();
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

fn match_type_to_pattern_index(match_type: MatchType) -> PatternID {
    PatternID::new_unchecked(match match_type {
        MatchType::Ascii | MatchType::WideStandard => 0,
        MatchType::WideAlternate => 1,
    })
}

#[derive(Debug)]
struct ReverseValidator {
    dfa: Arc<DFA>,
    pool: Pool<Cache, PoolCreateFn>,
}

impl ReverseValidator {
    pub fn new(
        hir: &Hir,
        modifiers: &VariableModifiers,
        dot_all: bool,
    ) -> Result<Self, crate::regex::Error> {
        let dfa =
            Arc::new(build_dfa(hir, modifiers, dot_all, true).map_err(crate::regex::Error::from)?);
        let pool = {
            let dfa = Arc::clone(&dfa);
            let create: PoolCreateFn = Box::new(move || dfa.create_cache());
            Pool::new(create)
        };

        Ok(Self { dfa, pool })
    }

    pub fn find_anchored_rev(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        pattern_index: PatternID,
    ) -> Option<usize> {
        let mut cache = self.pool.get();
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

fn build_dfa(
    hir: &Hir,
    modifiers: &VariableModifiers,
    dot_all: bool,
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
                .dot_matches_new_line(dot_all),
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
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(
            ForwardValidator::new(&Hir::Empty, &VariableModifiers::default(), true).unwrap(),
        );
        test_type_traits_non_clonable(
            ReverseValidator::new(&Hir::Empty, &VariableModifiers::default(), true).unwrap(),
        );
    }
}
