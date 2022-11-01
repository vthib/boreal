use std::ops::Range;

use boreal_parser::VariableFlags;
use regex::bytes::Regex;

use super::atom::AtomizedExpressions;
use super::{check_literal_with_flags, AcMatchStatus, VariableCompilationError};

#[derive(Debug)]
pub struct AtomizedRegex {
    /// Literals extracted from the regex.
    literals: Vec<Vec<u8>>,

    /// Validators of matches on literals.
    left_validator: Option<Regex>,
    right_validator: Option<Regex>,
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
            left_validator: compile_validator(pre, case_insensitive, dot_all)?,
            right_validator: compile_validator(post, case_insensitive, dot_all)?,
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
        literal_index: usize,
        flags: VariableFlags,
    ) -> AcMatchStatus {
        if self.left_validator.is_none() && self.right_validator.is_none() {
            return check_literal_with_flags(mem, mat, &self.literals[literal_index], flags);
        }

        let end = match &self.right_validator {
            Some(validator) => match validator.find(&mem[mat.start..]) {
                Some(m) => mat.start + m.end(),
                None => return AcMatchStatus::None,
            },
            None => mat.end,
        };

        match &self.left_validator {
            None => AcMatchStatus::Multiple(vec![mat.start..end]),
            Some(validator) => {
                // The left validator can yield multiple matches.
                // For example, `a.?bb`, with the `bb` atom, can match as many times as there are
                // 'a' characters before the `bb` atom.
                //
                // XXX: This only works if the left validator does not contain any greedy repetitions!
                let mut matches = Vec::new();
                while let Some(m) = validator.find(&mem[start_pos..mat.end]) {
                    let m = (m.start() + start_pos)..end;
                    start_pos = m.start + 1;
                    matches.push(m);
                }
                AcMatchStatus::Multiple(matches)
            }
        }
    }
}

fn compile_validator(
    expr: Option<String>,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Option<Regex>, VariableCompilationError> {
    match expr {
        Some(expr) => Ok(Some(super::compile_regex_expr(
            &expr,
            case_insensitive,
            dot_all,
        )?)),
        None => Ok(None),
    }
}
