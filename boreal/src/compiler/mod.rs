//! Compilation of a parsed expression into an optimized one.
use std::collections::HashMap;
use std::ops::Range;

use boreal_parser as parser;

mod error;
pub use error::CompilationError;
mod expression;
pub use expression::*;
mod variable;
pub use variable::*;

/// A compiled scanning rule.
pub struct Rule {
    /// Name of the rule.
    pub name: String,

    /// Tags associated with the rule.
    pub tags: Vec<String>,

    /// Metadata associated with the rule.
    pub metadatas: Vec<parser::Metadata>,

    /// Variable associated with the rule
    pub(crate) variables: Vec<Variable>,

    /// Condition of the rule.
    pub(crate) condition: Expression,
}

struct Compiler {
    /// Map of variable name to index in the compiled rule variables vec.
    ///
    /// This only stores named variables. Anonymous ones are still stored
    /// (and thus have an index), but cannot be referred by name.
    variables_map: HashMap<String, usize>,
    // TODO: hashset of used variables per index, to indicate which ones
    // are unused.
}

impl Compiler {
    fn from_rule(rule: &parser::Rule) -> Result<Self, CompilationError> {
        let mut variables_map = HashMap::new();
        for (idx, var) in rule.variables.iter().enumerate() {
            if var.name.is_empty() {
                continue;
            }
            if variables_map.insert(var.name.clone(), idx).is_some() {
                return Err(CompilationError::DuplicatedVariable(var.name.clone()));
            }
        }

        Ok(Self { variables_map })
    }

    /// Find a variable used in a rule by name.
    ///
    /// The provided span is the one of the expression using the variable, and is
    /// used for the error if the find fails.
    fn find_variable(&self, name: &str, span: &Range<usize>) -> Result<usize, CompilationError> {
        self.variables_map
            .get(name)
            .copied()
            .ok_or_else(|| CompilationError::UnknownVariable {
                variable_name: name.to_owned(),
                span: span.clone(),
            })
    }
}

pub fn compile_rule(rule: parser::Rule) -> Result<Rule, CompilationError> {
    let compiler = Compiler::from_rule(&rule)?;
    let condition = compile_expression(&compiler, rule.condition)?;

    Ok(Rule {
        name: rule.name,
        tags: rule.tags,
        metadatas: rule.metadatas,
        variables: rule
            .variables
            .into_iter()
            .map(compile_variable)
            .collect::<Result<Vec<_>, _>>()?,
        condition: condition.expr,
    })
}

#[cfg(test)]
mod tests;
