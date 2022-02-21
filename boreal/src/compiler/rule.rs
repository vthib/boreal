use boreal_parser as parser;

use super::{expression::compile_expression, CompilationError, Compiler, Expression};
use crate::variable::Variable;

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

pub fn compile(compiler: &Compiler, rule: parser::Rule) -> Result<Rule, CompilationError> {
    Ok(Rule {
        name: rule.name,
        tags: rule.tags,
        metadatas: rule.metadatas,
        variables: rule.variables.into_iter().map(Variable::from).collect(),
        condition: compile_expression(compiler, rule.condition)?.expr,
    })
}
