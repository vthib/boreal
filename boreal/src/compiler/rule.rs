use std::collections::HashMap;
use std::ops::Range;

use boreal_parser as parser;

use super::{
    compile_expression, compile_variable, CompilationError, Expression, Namespace, Variable,
    VariableIndex,
};

/// A compiled scanning rule.
#[derive(Debug)]
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

/// Object used to compile a rule.
pub(super) struct RuleCompiler<'a> {
    /// Namespace in which the rule is built and added to.
    pub namespace: &'a Namespace,

    /// Map of variable name to index in the compiled rule variables vec.
    ///
    /// This only stores named variables. Anonymous ones are still stored
    /// (and thus have an index), but cannot be referred by name.
    // TODO: hashset of used variables per index, to indicate which ones
    // are unused.
    pub variables_map: HashMap<String, usize>,
}

impl<'a> RuleCompiler<'a> {
    pub(super) fn new(
        rule: &parser::Rule,
        namespace: &'a Namespace,
    ) -> Result<Self, CompilationError> {
        let mut variables_map = HashMap::new();
        for (idx, var) in rule.variables.iter().enumerate() {
            if var.name.is_empty() {
                continue;
            }
            if variables_map.insert(var.name.clone(), idx).is_some() {
                return Err(CompilationError::DuplicatedVariable(var.name.clone()));
            }
        }

        Ok(Self {
            namespace,
            variables_map,
        })
    }

    /// Find a variable used in a rule by name.
    ///
    /// The provided span is the one of the expression using the variable, and is
    /// used for the error if the find fails.
    ///
    /// This function allows anonymous variables. To only allow named variable, use
    /// [`self.find_named_variable`] instead.
    pub(super) fn find_variable(
        &self,
        name: &str,
        span: &Range<usize>,
    ) -> Result<VariableIndex, CompilationError> {
        if name.is_empty() {
            Ok(VariableIndex(None))
        } else {
            Ok(VariableIndex(Some(self.find_named_variable(name, span)?)))
        }
    }

    /// Find a variable used in a rule by name, without accepting anonymous variables.
    pub(super) fn find_named_variable(
        &self,
        name: &str,
        span: &Range<usize>,
    ) -> Result<usize, CompilationError> {
        match self.variables_map.get(name) {
            Some(index) => Ok(*index),
            None => Err(CompilationError::UnknownVariable {
                variable_name: name.to_owned(),
                span: span.clone(),
            }),
        }
    }
}

pub(super) fn compile_rule(
    rule: parser::Rule,
    namespace: &Namespace,
) -> Result<Rule, CompilationError> {
    let compiler = RuleCompiler::new(&rule, namespace)?;
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

    // TODO: check for unused variables
}
