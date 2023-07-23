use std::ops::Range;

use regex_automata::Input;

use crate::{
    compiler::variable::RegexModifiers,
    regex::{regex_hir_to_string, Hir, Regex},
};

use super::{widener::widen_hir, Flags, MatchType};

#[derive(Debug)]
pub(crate) struct RawMatcher {
    regex: regex_automata::meta::Regex,
}

impl RawMatcher {
    pub(crate) fn new(hir: &Hir, modifiers: RegexModifiers) -> Result<Self, crate::regex::Error> {
        let builder = Regex::builder(modifiers.nocase, modifiers.dot_all);

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

    pub(crate) fn find_next_match_at(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(
            RawMatcher::new(&Hir::Empty, RegexModifiers::default()).unwrap(),
        );
    }
}
