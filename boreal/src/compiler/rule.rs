use std::collections::HashSet;
use std::ops::Range;
use std::{collections::HashMap, sync::Arc};

use boreal_parser as parser;

use super::{
    compile_expression, compile_variable, BoundedIdentifierType, CompilationError, Expression,
    Namespace, Variable, VariableIndex,
};

/// A compiled scanning rule.
#[derive(Debug)]
pub struct Rule {
    /// Name of the rule.
    pub name: String,

    /// Namespace containing the rule.
    ///
    /// `None` if in the default namespace.
    pub namespace: Option<String>,

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
#[derive(Debug)]
pub(super) struct RuleCompiler<'a> {
    /// Namespace in which the rule is built and added to.
    pub namespace: &'a Namespace,

    /// Names of variables declared in this rule.
    ///
    /// The index of the name in this vector will match the index of the variable
    /// in the compiled rules's variable vec. It can thus be used to compile
    /// access to the variable.
    // TODO: detect which ones are unused.
    pub variable_names: Vec<String>,

    /// Map of the name of a bounded identifier to its type and index in the bounded identifier
    /// stack.
    pub bounded_identifiers: HashMap<String, Arc<(BoundedIdentifierType, usize)>>,
}

impl<'a> RuleCompiler<'a> {
    pub(super) fn new(
        rule: &parser::Rule,
        namespace: &'a Namespace,
    ) -> Result<Self, CompilationError> {
        let mut names_set = HashSet::new();
        let mut variable_names = Vec::with_capacity(rule.variables.len());
        for var in &rule.variables {
            // Check duplicated names, but only for non anonymous strings
            if !var.name.is_empty() && !names_set.insert(var.name.clone()) {
                return Err(CompilationError::DuplicatedVariable(var.name.clone()));
            }

            variable_names.push(var.name.clone());
        }

        Ok(Self {
            namespace,
            variable_names,
            bounded_identifiers: HashMap::new(),
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
        for (index, var_name) in self.variable_names.iter().enumerate() {
            if var_name == name {
                return Ok(index);
            }
        }
        Err(CompilationError::UnknownVariable {
            variable_name: name.to_owned(),
            span: span.clone(),
        })
    }

    /// Add a bounded identifier.
    pub(super) fn add_bounded_identifier(
        &mut self,
        name: &str,
        typ: BoundedIdentifierType,
        span: &Range<usize>,
    ) -> Result<(), CompilationError> {
        let index = self.bounded_identifiers.len();
        match self
            .bounded_identifiers
            .insert(name.to_string(), Arc::new((typ, index)))
        {
            Some(_) => Err(CompilationError::DuplicatedIdentifierBinding {
                identifier: name.to_string(),
                span: span.clone(),
            }),
            None => Ok(()),
        }
    }

    /// Remove a bounded identifier.
    pub(super) fn remove_bounded_identifier(&mut self, name: &str) {
        drop(self.bounded_identifiers.remove(name));
    }
}

pub(super) fn compile_rule(
    rule: parser::Rule,
    namespace: &Namespace,
) -> Result<Rule, CompilationError> {
    let mut compiler = RuleCompiler::new(&rule, namespace)?;
    let condition = compile_expression(&mut compiler, rule.condition)?;

    Ok(Rule {
        name: rule.name,
        namespace: namespace.name.clone(),
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
