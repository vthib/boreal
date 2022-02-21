//! Implement scanning for variables
use grep_matcher::Matcher;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};

use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue};

pub(crate) struct Variable {
    matcher: RegexMatcher,
}

impl From<VariableDeclaration> for Variable {
    fn from(decl: VariableDeclaration) -> Self {
        // TODO: handle modifiers
        let mut matcher = RegexMatcherBuilder::new();
        let matcher = matcher.unicode(false).octal(false);

        match decl.value {
            VariableDeclarationValue::String(s) => Self {
                matcher: matcher.build_literals(&[s]).unwrap(),
            },
            VariableDeclarationValue::Regex(Regex {
                expr,
                case_insensitive,
                dot_all,
            }) => Self {
                matcher: matcher
                    .case_insensitive(case_insensitive)
                    .multi_line(dot_all)
                    .dot_matches_new_line(dot_all)
                    .build(&expr)
                    .unwrap(),
            },
            VariableDeclarationValue::HexString(_) => todo!(),
        }
    }
}

impl Variable {
    /// Search occurrence of a variable in bytes
    pub fn find(&self, mem: &[u8]) -> Result<bool, std::io::Error> {
        Ok(self.matcher.find(mem)?.is_some())
    }

    /// Search occurrence of a variable at a given
    pub fn find_at(&self, mem: &[u8], offset: usize) -> Result<bool, std::io::Error> {
        if offset < mem.len() {
            Ok(self.matcher.find_at(mem, offset)?.is_some())
        } else {
            Ok(false)
        }
    }

    /// Search occurrence of a variable in between given offset
    pub fn find_in(&self, mem: &[u8], from: usize, to: usize) -> Result<bool, std::io::Error> {
        if from < mem.len() {
            // TODO: would be great to give a subslice of mem, so that the matcher does not run
            // over the whole mem well past the "to" offset.
            // How to make it work with regexes is not trivial though, may need a PR on
            // grep-matcher for this.
            match self.matcher.find_at(mem, from)? {
                Some(mat) => Ok(mat.start() <= to),
                None => Ok(false),
            }
        } else {
            Ok(false)
        }
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

    #[test]
    fn test_variable_find_at() {
        let v = build_var_string("34");
        assert!(v.find_at(b"01234567", 3).unwrap());
        assert!(v.find_at(b"342342", 3).unwrap());
        assert!(v.find_at(b"34", 0).unwrap());
        assert!(!v.find_at(b"234", 2).unwrap());
        assert!(!v.find_at(b"01234", 15).unwrap());

        let v = build_var_regex("[a-z]{2}", false, false);
        assert!(v.find_at(b"abc", 0).unwrap());
        assert!(v.find_at(b"abc", 1).unwrap());
        assert!(!v.find_at(b"abc", 2).unwrap());
    }

    #[test]
    fn test_variable_find_in() {
        let v = build_var_string("345");
        assert!(v.find_in(b"01234567", 0, 20).unwrap());
        assert!(v.find_in(b"01234567", 2, 6).unwrap());
        assert!(v.find_in(b"01234567", 3, 5).unwrap());
        assert!(v.find_in(b"01234567", 3, 4).unwrap());
        assert!(v.find_in(b"01234567", 3, 3).unwrap());
        assert!(v.find_in(b"01234567", 2, 3).unwrap());
        assert!(!v.find_in(b"01234567", 1, 2).unwrap());
        assert!(!v.find_in(b"34353435", 1, 6).unwrap());
    }
}
