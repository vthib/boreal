//! Implement scanning for variables
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{Searcher, SearcherBuilder, Sink, SinkMatch};

use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue};

pub(crate) struct Variable {
    pub name: String,
    matcher: RegexMatcher,
}

impl From<VariableDeclaration> for Variable {
    fn from(decl: VariableDeclaration) -> Self {
        let mut builder = RegexMatcherBuilder::new();
        let builder = builder.unicode(false).octal(false);

        let matcher = match decl.value {
            VariableDeclarationValue::String(s) => builder.build_literals(&[s]).unwrap(),
            VariableDeclarationValue::Regex(Regex {
                expr,
                case_insensitive,
                dot_all,
            }) => builder
                .case_insensitive(case_insensitive)
                .multi_line(dot_all)
                .dot_matches_new_line(dot_all)
                .build(&expr)
                .unwrap(),
            VariableDeclarationValue::HexString(_) => todo!(),
        };
        // TODO: handle modifiers
        Self {
            name: decl.name,
            matcher,
        }
    }
}

impl Variable {
    /// Search occurrence of a variable in bytes
    pub fn find(&self, mem: &[u8]) -> Result<bool, std::io::Error> {
        let mut searcher = SearcherBuilder::new()
            .line_number(false)
            .multi_line(true)
            .bom_sniffing(false)
            .build();

        let mut found = false;
        searcher.search_slice(
            &self.matcher,
            mem,
            VariableSink(|_| {
                found = true;
                false
            }),
        )?;
        Ok(found)
    }
}

/// A custom [`Sink`] implementation.
/// TODO: improve doc
#[derive(Clone, Debug)]
pub struct VariableSink<F>(pub F)
where
    F: FnMut(&SinkMatch) -> bool;

impl<F> Sink for VariableSink<F>
where
    F: FnMut(&SinkMatch) -> bool,
{
    type Error = std::io::Error;

    fn matched(
        &mut self,
        _searcher: &Searcher,
        mat: &SinkMatch<'_>,
    ) -> Result<bool, std::io::Error> {
        Ok((self.0)(mat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreal_parser::VariableModifiers;

    fn build_var_string(s: &str) -> Variable {
        Variable::from(VariableDeclaration {
            name: "umbasa".to_owned(),
            value: VariableDeclarationValue::String(s.to_owned()),
            modifiers: VariableModifiers::default(),
        })
    }

    fn build_var_regex(s: &str, case_insensitive: bool, dot_all: bool) -> Variable {
        Variable::from(VariableDeclaration {
            name: "umbasa".to_owned(),
            value: VariableDeclarationValue::Regex(Regex {
                expr: s.to_owned(),
                case_insensitive,
                dot_all,
            }),
            modifiers: VariableModifiers::default(),
        })
    }

    #[test]
    fn test_variable_find() {
        let v = build_var_string("45");
        assert!(v.find(b"12345678").unwrap());
        assert!(v.find(b"45678").unwrap());
        assert!(v.find(b"45").unwrap());
        assert!(v.find(b"345").unwrap());
        assert!(!v.find(b"1234678").unwrap());
        assert!(!v.find(b"465").unwrap());

        let v = build_var_regex("4.5+", false, false);
        assert!(v.find(b"445").unwrap());
        assert!(v.find(b"34\x3D555").unwrap());
        assert!(!v.find(b"123").unwrap());
        assert!(!v.find(b"44").unwrap());
        assert!(!v.find("4\n5".as_bytes()).unwrap());

        let v = build_var_regex("fo{2,}", true, false);
        assert!(v.find(b"foo").unwrap());
        assert!(v.find(b"FoOoOoO").unwrap());
        assert!(v.find(b"barFOOObaz").unwrap());
        assert!(!v.find(b"fo").unwrap());
        assert!(!v.find(b"FO").unwrap());

        let v = build_var_regex("a.*b", false, true);
        assert!(v.find(b"ab").unwrap());
        assert!(v.find(b"ba\n\n  ba").unwrap());
        assert!(!v.find(b"AB").unwrap());
        assert!(!v.find(b"ec").unwrap());
    }
}
