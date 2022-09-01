//! Provides the [`VariableSet`] object.
use regex::bytes::{RegexSet, RegexSetBuilder, SetMatches};

use crate::compiler::CompilationError;

/// Factorize regex expression of all the variables in the scanner.
///
/// Used to minimize the number of passes on the scanned memory.
#[derive(Debug)]
pub(crate) struct VariableSet {
    set: RegexSet,
}

impl VariableSet {
    pub(crate) fn new(exprs: &[&str]) -> Result<Self, CompilationError> {
        let set = RegexSetBuilder::new(exprs)
            .unicode(false)
            .octal(false)
            .size_limit(50 * 1024 * 1024)
            .build()
            .map_err(|error| CompilationError::VariableSetError { error })?;

        Ok(Self { set })
    }

    pub(crate) fn matches(&self, mem: &[u8]) -> VariableSetMatches {
        // For very small mem, it's not worth it to use a regex set.
        // TODO: find the right size for this
        // TODO: this basically bypasses this optim for all the integration tests, find a way
        // to improve this.
        let matches = if mem.len() < 4096 {
            None
        } else {
            Some(self.set.matches(mem))
        };

        VariableSetMatches { matches }
    }
}

pub(crate) struct VariableSetMatches {
    matches: Option<SetMatches>,
}

impl VariableSetMatches {
    pub(crate) fn matched(&self, index: usize) -> Option<bool> {
        self.matches.as_ref().map(|m| m.matched(index))
    }
}
