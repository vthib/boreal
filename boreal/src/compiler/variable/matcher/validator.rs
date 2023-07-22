use std::ops::Range;

use boreal_parser::VariableModifiers;
use regex_automata::{meta, Anchored, Input};

use crate::regex::{regex_hir_to_string, Hir, Regex};

use super::widener::widen_hir;

#[derive(Debug)]
pub struct Validator {
    regex: meta::Regex,
}

impl Validator {
    pub fn new(
        hir: &Hir,
        modifiers: &VariableModifiers,
        dot_all: bool,
    ) -> Result<Self, crate::regex::Error> {
        let expr = convert_hir_to_string_with_flags(hir, modifiers);
        let builder = Regex::builder(modifiers.nocase, dot_all);

        Ok(Self {
            regex: builder.build(&expr).map_err(crate::regex::Error::from)?,
        })
    }

    pub fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<Range<usize>> {
        self.regex
            .find(
                Input::new(haystack)
                    .span(start..end)
                    .anchored(Anchored::Yes),
            )
            .map(|m| m.range())
    }

    pub fn find(&self, mem: &[u8]) -> Option<Range<usize>> {
        self.regex.find(mem).map(|m| m.range())
    }
}

/// Convert the AST of a regex variable to a string, taking into account variable modifiers.
fn convert_hir_to_string_with_flags(hir: &Hir, modifiers: &VariableModifiers) -> String {
    if modifiers.wide {
        let wide_hir = widen_hir(hir);

        if modifiers.ascii {
            format!(
                "{}|{}",
                regex_hir_to_string(hir),
                regex_hir_to_string(&wide_hir),
            )
        } else {
            regex_hir_to_string(&wide_hir)
        }
    } else {
        regex_hir_to_string(hir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(Validator {
            regex: meta::Regex::new("a").unwrap(),
        });
    }
}
