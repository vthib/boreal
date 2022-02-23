//! Implement scanning for variables
use grep_matcher::Matcher;

use crate::compiler::Variable;

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
pub(crate) struct VariableEvaluation<'a> {
    var: &'a Variable,
}

impl<'a> VariableEvaluation<'a> {
    /// Build a new variable evaluation context, from a variable.
    pub fn new(var: &'a Variable) -> Self {
        Self { var }
    }

    /// Search occurrence of a variable in bytes
    pub fn find(&self, mem: &[u8]) -> Result<bool, std::io::Error> {
        Ok(self.var.matcher.find(mem)?.is_some())
    }

    /// Search occurrence of a variable at a given
    pub fn find_at(&self, mem: &[u8], offset: usize) -> Result<bool, std::io::Error> {
        if offset < mem.len() {
            Ok(self.var.matcher.find_at(mem, offset)?.is_some())
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
            match self.var.matcher.find_at(mem, from)? {
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
    use crate::compiler::compile_variable;
    use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue, VariableModifiers};

    fn build_var_string(s: &str) -> Variable {
        compile_variable(VariableDeclaration {
            name: "umbasa".to_owned(),
            value: VariableDeclarationValue::String(s.to_owned()),
            modifiers: VariableModifiers::default(),
        })
        .unwrap()
    }

    fn build_var_regex(s: &str, case_insensitive: bool, dot_all: bool) -> Variable {
        compile_variable(VariableDeclaration {
            name: "umbasa".to_owned(),
            value: VariableDeclarationValue::Regex(Regex {
                expr: s.to_owned(),
                case_insensitive,
                dot_all,
            }),
            modifiers: VariableModifiers::default(),
        })
        .unwrap()
    }

    #[test]
    fn test_variable_find() {
        let find = |var, input| {
            let eval_context = VariableEvaluation::new(var);
            eval_context.find(input)
        };

        let v = build_var_string("45");
        assert!(find(&v, b"12345678").unwrap());
        assert!(find(&v, b"45678").unwrap());
        assert!(find(&v, b"45").unwrap());
        assert!(find(&v, b"345").unwrap());
        assert!(!find(&v, b"1234678").unwrap());
        assert!(!find(&v, b"465").unwrap());

        let v = build_var_regex("4.5+", false, false);
        assert!(find(&v, b"445").unwrap());
        assert!(find(&v, b"34\x3D555").unwrap());
        assert!(!find(&v, b"123").unwrap());
        assert!(!find(&v, b"44").unwrap());
        assert!(!find(&v, "4\n5".as_bytes()).unwrap());

        let v = build_var_regex("fo{2,}", true, false);
        assert!(find(&v, b"foo").unwrap());
        assert!(find(&v, b"FoOoOoO").unwrap());
        assert!(find(&v, b"barFOOObaz").unwrap());
        assert!(!find(&v, b"fo").unwrap());
        assert!(!find(&v, b"FO").unwrap());

        let v = build_var_regex("a.*b", false, true);
        assert!(find(&v, b"ab").unwrap());
        assert!(find(&v, b"ba\n\n  ba").unwrap());
        assert!(!find(&v, b"AB").unwrap());
        assert!(!find(&v, b"ec").unwrap());
    }

    #[test]
    fn test_variable_find_at() {
        let find_at = |var, input, offset| {
            let eval_context = VariableEvaluation::new(var);
            eval_context.find_at(input, offset)
        };

        let v = build_var_string("34");
        assert!(find_at(&v, b"01234567", 3).unwrap());
        assert!(find_at(&v, b"342342", 3).unwrap());
        assert!(find_at(&v, b"34", 0).unwrap());
        assert!(!find_at(&v, b"234", 2).unwrap());
        assert!(!find_at(&v, b"01234", 15).unwrap());

        let v = build_var_regex("[a-z]{2}", false, false);
        assert!(find_at(&v, b"abc", 0).unwrap());
        assert!(find_at(&v, b"abc", 1).unwrap());
        assert!(!find_at(&v, b"abc", 2).unwrap());
    }

    #[test]
    fn test_variable_find_in() {
        let find_in = |var, input, from, to| {
            let eval_context = VariableEvaluation::new(var);
            eval_context.find_in(input, from, to)
        };

        let v = build_var_string("345");
        assert!(find_in(&v, b"01234567", 0, 20).unwrap());
        assert!(find_in(&v, b"01234567", 2, 6).unwrap());
        assert!(find_in(&v, b"01234567", 3, 5).unwrap());
        assert!(find_in(&v, b"01234567", 3, 4).unwrap());
        assert!(find_in(&v, b"01234567", 3, 3).unwrap());
        assert!(find_in(&v, b"01234567", 2, 3).unwrap());
        assert!(!find_in(&v, b"01234567", 1, 2).unwrap());
        assert!(!find_in(&v, b"34353435", 1, 6).unwrap());
    }
}
