use std::ops::Range;

use boreal_parser::VariableModifiers;
use regex_automata::Input;

use crate::regex::{regex_hir_to_string, Hir, Regex};

use super::{widener::widen_hir, Flags, MatchType};

#[derive(Debug)]
pub struct RawMatcher {
    regex: regex_automata::meta::Regex,
}

impl RawMatcher {
    pub fn new(
        hir: &Hir,
        modifiers: &VariableModifiers,
        dot_all: bool,
    ) -> Result<Self, crate::regex::Error> {
        let builder = Regex::builder(modifiers.nocase, dot_all);

        let res = match (modifiers.ascii, modifiers.wide) {
            (true, true) => {
                // Build a regex with 2 patterns: one for the ascii version,
                // one for the wide version.
                let expr = regex_hir_to_string(hir);
                let wide_expr = regex_hir_to_string(&widen_hir(hir));

                builder.build_many(&[expr, wide_expr])
            }
            (false, true) => {
                let wide_hir = widen_hir(hir);
                builder.build(&regex_hir_to_string(&wide_hir))
            }
            _ => builder.build(&regex_hir_to_string(hir)),
        };

        Ok(Self {
            regex: res.map_err(crate::regex::Error::from)?,
        })
    }

    pub(super) fn find_next_match_at(
        &self,
        mem: &[u8],
        offset: usize,
        flags: Flags,
    ) -> Option<(Range<usize>, MatchType)> {
        self.regex
            .find(Input::new(mem).span(offset..mem.len()))
            .map(|m| {
                let match_type = match (flags.ascii, flags.wide, m.pattern().as_u32()) {
                    (false, true, _) => MatchType::WideStandard,
                    // First pattern is ascii, Second one is wide
                    (true, true, 0) => MatchType::Ascii,
                    (true, true, _) => MatchType::WideAlternate,
                    _ => MatchType::Ascii,
                };

                (m.range(), match_type)
            })
    }
}
