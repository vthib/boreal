use std::ops::Range;

use regex::bytes::Regex;

use super::{atom::AtomizedExpressions, VariableCompilationError};

#[derive(Debug)]
pub struct AtomizedRegex {
    /// Literals extracted from the regex.
    literals: Vec<Vec<u8>>,

    /// Validators of matches on literals.
    left_validator: Regex,
    right_validator: Regex,
}

impl AtomizedRegex {
    pub fn new(
        exprs: AtomizedExpressions,
        case_insensitive: bool,
        dot_all: bool,
    ) -> Result<Self, VariableCompilationError> {
        let AtomizedExpressions {
            literals,
            pre,
            post,
        } = exprs;

        Ok(Self {
            literals,
            left_validator: super::compile_regex_expr(&pre, case_insensitive, dot_all)?,
            right_validator: super::compile_regex_expr(&post, case_insensitive, dot_all)?,
        })
    }

    pub fn literals(&self) -> &[Vec<u8>] {
        &self.literals
    }

    pub fn check_literal_match(
        &self,
        mem: &[u8],
        mut start_pos: usize,
        mat: Range<usize>,
    ) -> Vec<Range<usize>> {
        match self.right_validator.find(&mem[mat.start..]) {
            Some(post_match) => {
                let end = mat.start + post_match.end();

                // The left validator can yield multiple matches.
                // For example, `a.?bb`, with the `bb` atom, can match as many times as there are
                // 'a' characters before the `bb` atom.
                //
                // XXX: This only works if the left validator does not contain any greedy repetitions!
                let mut matches = Vec::new();
                while let Some(m) = self.left_validator.find(&mem[start_pos..mat.end]) {
                    let m = (m.start() + start_pos)..end;
                    start_pos = m.start + 1;
                    matches.push(m);
                }
                matches
            }
            None => Vec::new(),
        }
    }
}
