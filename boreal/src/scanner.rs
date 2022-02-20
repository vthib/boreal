//! Provides the [`Scanner`] object which provides methods to scan
//! files or memory on a set of rules.
use boreal_parser::{parse_str, Expression, Metadata};

use crate::variable::Variable;
use crate::{evaluator, ScanError};

/// Holds a list of rules, and provides methods to
/// run them on files or bytes.
#[derive(Default)]
pub struct Scanner {
    pub(crate) rules: Vec<Rule>,
}

impl Scanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add rules to the scanner from a string.
    ///
    /// # Errors
    ///
    /// If parsing of the rules fails, an error is returned.
    pub fn add_rules_from_str(&mut self, s: &str) -> Result<(), boreal_parser::Error> {
        let rules = parse_str(s)?;
        self.add_rules(rules);
        Ok(())
    }

    /// Add rules in the scanner.
    fn add_rules(&mut self, rules: Vec<boreal_parser::Rule>) {
        self.rules.extend(rules.into_iter().map(Rule::from));
    }

    /// Scan a byte slice.
    ///
    /// Returns a list of rules that matched on the given
    /// byte slice.
    #[must_use]
    pub fn scan_mem(&self, mem: &[u8]) -> ScanResults {
        // FIXME: this is pretty bad performance wise
        let mut results = ScanResults::default();
        for rule in &self.rules {
            // TODO: handle errors
            match evaluator::evaluate_rule(rule, mem) {
                Ok(true) => results.matching_rules.push(rule),
                Ok(false) => (),
                Err(error) => results.scan_errors.push(RuleScanError { rule, error }),
            }
        }
        results
    }
}

/// A scanning rule.
///
pub struct Rule {
    /// Name of the rule.
    pub name: String,

    /// Tags associated with the rule.
    pub tags: Vec<String>,

    /// Metadata associated with the rule.
    pub metadatas: Vec<Metadata>,

    /// Variable associated with the rule
    pub(crate) variables: Vec<Variable>,

    /// Condition of the rule.
    pub(crate) condition: Expression,
}

impl From<boreal_parser::Rule> for Rule {
    fn from(rule: boreal_parser::Rule) -> Self {
        Self {
            name: rule.name,
            tags: rule.tags,
            metadatas: rule.metadatas,
            variables: rule.variables.into_iter().map(Variable::from).collect(),
            condition: rule.condition,
        }
    }
}

#[derive(Default)]
pub struct ScanResults<'a> {
    pub matching_rules: Vec<&'a Rule>,

    pub scan_errors: Vec<RuleScanError<'a>>,
}

pub struct RuleScanError<'a> {
    pub rule: &'a Rule,
    pub error: ScanError,
}
