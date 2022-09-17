//! Provides the [`VariableSet`] object.
use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::bytes::{RegexSet, RegexSetBuilder};

use crate::{
    compiler::{CompilationError, VariableExpr},
    scan_params::EarlyScanConfiguration,
};

/// Factorize regex expression of all the variables in the scanner.
///
/// Used to minimize the number of passes on the scanned memory.
#[derive(Debug)]
pub(crate) struct VariableSet {
    /// Aho Corasick for variables that are literals.
    aho: AhoCorasick,
    /// Number of literals in the
    /// Aho Corasick for variables that are literals, and are case insensitive.
    aho_ci: AhoCorasick,
    /// Regex sets for regexes.
    regex_sets: Vec<RegexSet>,

    /// Number of variables in the set.
    nb_vars: usize,

    /// Map from a aho pattern index to a var set index.
    aho_index_to_var_index: Vec<usize>,

    /// Map from a aho ci pattern index to a var set index.
    aho_ci_index_to_var_index: Vec<usize>,

    /// Map from a regex set index to a var set index.
    regex_sets_index_to_var_index: Vec<usize>,
}

impl VariableSet {
    pub(crate) fn new(exprs: &[&VariableExpr]) -> Result<Self, CompilationError> {
        let mut lits = Vec::new();
        let mut lits_ci = Vec::new();
        let mut regex_exprs = Vec::new();
        let mut aho_index_to_var_index = Vec::new();
        let mut aho_ci_index_to_var_index = Vec::new();
        let mut regex_sets_index_to_var_index = Vec::new();

        for (var_index, expr) in exprs.iter().enumerate() {
            match expr {
                VariableExpr::Regex(e) => {
                    regex_sets_index_to_var_index.push(var_index);
                    regex_exprs.push(e);
                }
                VariableExpr::Literals {
                    literals,
                    case_insensitive,
                } => {
                    if *case_insensitive {
                        aho_ci_index_to_var_index
                            .extend(std::iter::repeat(var_index).take(literals.len()));
                        lits_ci.extend(literals);
                    } else {
                        aho_index_to_var_index
                            .extend(std::iter::repeat(var_index).take(literals.len()));
                        lits.extend(literals);
                    }
                }
            }
        }

        let aho = AhoCorasick::new_auto_configured(&lits);
        let aho_ci = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .auto_configure(&lits_ci)
            .build(&lits_ci);

        // Build RegexSet containing max 200 expressions. This is attempting to strike a
        // balance between grouping expressions in a single mem scan, and not having the set
        // grow too big or scan too slowly.
        let regex_sets = regex_exprs
            .chunks(200)
            .map(|exprs| {
                RegexSetBuilder::new(exprs)
                    .unicode(false)
                    .octal(false)
                    .build()
                    .map_err(|error| CompilationError::VariableSetError(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            aho,
            aho_ci,
            regex_sets,
            nb_vars: exprs.len(),
            aho_index_to_var_index,
            aho_ci_index_to_var_index,
            regex_sets_index_to_var_index,
        })
    }

    pub(crate) fn matches(&self, mem: &[u8], cfg: &EarlyScanConfiguration) -> VariableSetMatches {
        let matches = match cfg {
            EarlyScanConfiguration::Disable => None,
            // For very small mem, it's not worth it to use a regex set.
            // TODO: find the right size for this
            EarlyScanConfiguration::AutoConfigure if mem.len() < 4096 => None,
            EarlyScanConfiguration::AutoConfigure | EarlyScanConfiguration::Enable => {
                let mut matches = vec![None; self.nb_vars];

                for mat in self.aho.find_overlapping_iter(mem) {
                    let var_index = self.aho_index_to_var_index[mat.pattern()];
                    matches[var_index]
                        .get_or_insert_with(Vec::new)
                        .push(mat.start()..mat.end());
                }
                for mat in self.aho_ci.find_overlapping_iter(mem) {
                    let var_index = self.aho_ci_index_to_var_index[mat.pattern()];
                    matches[var_index]
                        .get_or_insert_with(Vec::new)
                        .push(mat.start()..mat.end());
                }

                let mut offset = 0;
                for set in &self.regex_sets {
                    let set_matches = set.matches(mem);
                    for idx in set_matches {
                        let var_index = self.regex_sets_index_to_var_index[offset + idx];
                        matches[var_index] = Some(Vec::new());
                    }
                    offset += set.len();
                }

                Some(matches)
            }
        };

        VariableSetMatches { matches }
    }
}

// Result of a match for a variable.
// - None means not found
// - Some(vec![]) means found, but no details on the matches are available
// - Some(vec![..]) means found and matches details are available.
type MatchResult = Option<Vec<Range<usize>>>;

#[derive(Debug)]
pub(crate) struct VariableSetMatches {
    matches: Option<Vec<MatchResult>>,
}

/// Result of a `VariableSet` scan for a given variable.
#[derive(Clone, Debug)]
pub(crate) enum SetResult<'a> {
    /// Variable has no match.
    NotFound,
    /// Unknown, must scan for the variable on its own.
    Unknown,
    /// Found at least one match.
    Found,
    /// List of matches.
    Matches(&'a [Range<usize>]),
}

impl VariableSetMatches {
    pub(crate) fn matched(&self, index: usize) -> SetResult {
        match self.matches.as_ref() {
            None => SetResult::Unknown,
            Some(vec) => match &vec[index] {
                None => SetResult::NotFound,
                Some(v) if v.is_empty() => SetResult::Found,
                Some(v) => SetResult::Matches(v),
            },
        }
    }
}
