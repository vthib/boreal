use std::sync::Arc;

use boreal_parser::VariableModifiers;
use regex_automata::hybrid::dfa::{Builder, Cache, DFA};
use regex_automata::nfa::thompson;
use regex_automata::util::pool::Pool;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind, PatternID};

use crate::regex::{regex_hir_to_string, Hir};

use super::widener::widen_hir;
use super::MatchType;

type PoolCreateFn = Box<dyn Fn() -> Cache + Send + Sync>;

#[derive(Debug)]
pub struct ForwardValidator {
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
        match_type: MatchType,
    ) -> Option<usize> {
        let pattern_index = match_type_to_pattern_index(match_type);

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
pub struct ReverseValidator {
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
        match_type: MatchType,
    ) -> Option<usize> {
        let pattern_index = match_type_to_pattern_index(match_type);

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
