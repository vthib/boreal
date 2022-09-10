//! Provides the [`VariableSet`] object.
use regex::bytes::{RegexSet, RegexSetBuilder, SetMatches};

use crate::compiler::CompilationError;

/// Factorize regex expression of all the variables in the scanner.
///
/// Used to minimize the number of passes on the scanned memory.
#[derive(Debug)]
pub(crate) struct VariableSet {
    sets: Vec<RegexSet>,
}

impl VariableSet {
    pub(crate) fn new(exprs: &[&str]) -> Result<Self, CompilationError> {
        Ok(Self {
            // Build RegexSet containing max 200 expressions. This is attempting to strike a
            // balance between grouping expressions in a single mem scan, and not having the set
            // grow too big or scan too slowly.
            sets: exprs
                .chunks(200)
                .map(|exprs| {
                    RegexSetBuilder::new(exprs)
                        .unicode(false)
                        .octal(false)
                        .build()
                        .map_err(|error| CompilationError::VariableSetError(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub(crate) fn matches(&self, mem: &[u8]) -> VariableSetMatches {
        // For very small mem, it's not worth it to use a regex set.
        // TODO: find the right size for this
        // TODO: this basically bypasses this optim for all the integration tests, find a way
        // to improve this.
        let matches = if mem.len() < 4096 {
            None
        } else {
            Some(self.sets.iter().map(|v| v.matches(mem)).collect())
        };

        VariableSetMatches { matches }
    }
}

#[derive(Debug)]
pub(crate) struct VariableSetMatches {
    matches: Option<Vec<SetMatches>>,
}

/// Result of a `VariableSet` scan for a given variable.
pub(crate) enum SetResult {
    /// Variable has no match.
    NotFound,
    /// Unknown, must scan for the variable on its own.
    Unknown,
    /// Found at least one match.
    Found,
}

impl VariableSetMatches {
    pub(crate) fn matched(&self, mut index: usize) -> SetResult {
        match self.matches.as_ref() {
            None => SetResult::Unknown,
            Some(vec) => {
                for matches in vec {
                    if index < matches.len() {
                        if matches.matched(index) {
                            return SetResult::Found;
                        }
                        return SetResult::NotFound;
                    }
                    index -= matches.len();
                }
                debug_assert!(false);
                SetResult::Unknown
            }
        }
    }
}
