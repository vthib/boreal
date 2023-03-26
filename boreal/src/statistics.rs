//! Statistics used to investigate performance of rules.

use std::{path::PathBuf, time::Duration};

/// Compilation statistics for a rule.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    /// Path to the file containing the rule.
    ///
    /// None if the rule was added directly as a string.
    pub filepath: Option<PathBuf>,

    /// Namespace containing the rule.
    ///
    /// None for the default namespace.
    pub namespace: Option<String>,

    /// Name of the rule.
    pub name: String,

    /// Statistics on the compiled strings.
    ///
    /// The order in which the strings are declared in the rule is preserved in this array.
    pub strings: Vec<CompiledString>,
}

/// Details on the compilation of a string.
#[derive(Clone, Debug)]
pub struct CompiledString {
    /// Name of the string in the rule, without the leading `$`.
    pub name: String,

    /// Expression of the string, as it is declared in the rule.
    pub expr: String,

    /// Literals extracted from the string.
    pub literals: Vec<Vec<u8>>,

    /// Atoms picked out of those literals.
    pub atoms: Vec<Vec<u8>>,

    /// Quality of the atoms.
    pub atoms_quality: u32,

    /// Matching kind for the string.
    pub matching_kind: MatchingKind,
}

/// Kind of matching for a string.
#[derive(Clone, Debug)]
pub enum MatchingKind {
    /// Literals cover the entire string.
    ///
    /// AC hits from atoms are confirmed using the literals.
    Literals,

    /// Atoms are used in AC pass and confirmed by left and right regexes.
    Atomized,

    /// The AC hits are not confirmed, and the regex is run on its own.
    ///
    /// If the string has atoms, those are used to detect whether the string is certain to
    /// hits or not. If a single atom hits during the AC pass (or if there are no atoms), the
    /// regex will have to be run on its own.
    Regex,
}

/// Statistics on the evaluation of a byte string.
#[derive(Clone, Debug, Default)]
pub struct Evaluation {
    /// Time spent evaluating rules before any scanning.
    ///
    /// This is used for the no-scan optimization.
    pub no_scan_eval_duration: Duration,

    /// Time spent running the Aho-Corasick algorithm.
    pub ac_duration: Duration,

    /// Time spent evaluation rules.
    pub rules_eval_duration: Duration,

    /// Time spent evaluating singled regexes.
    ///
    /// This is an aggregation of the time spent evaluating "raw" variables regexes.
    pub raw_regexes_eval_duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits;

    #[test]
    fn test_types_traits() {
        test_type_traits(CompiledRule {
            filepath: Some(PathBuf::new()),
            namespace: Some(String::new()),
            name: String::new(),
            strings: Vec::new(),
        });
        test_type_traits(CompiledString {
            name: String::new(),
            expr: String::new(),
            literals: Vec::new(),
            atoms: Vec::new(),
            atoms_quality: 0,
            matching_kind: MatchingKind::Literals,
        });
        test_type_traits(MatchingKind::Atomized);
        test_type_traits(Evaluation::default());
    }
}
