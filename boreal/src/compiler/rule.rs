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

    /// Variables declared in this rule.
    ///
    /// The index of the variable in this vector will match the index of the variable
    /// in the compiled rules's variable vec. It can thus be used to compile
    /// access to the variable.
    pub variables: Vec<RuleCompilerVariable>,

    /// Map of the name of a bounded identifier to its type and index in the bounded identifier
    /// stack.
    pub bounded_identifiers: HashMap<String, Arc<(BoundedIdentifierType, usize)>>,

    /// List of rules wildcard used in for expressions.
    ///
    /// This will be added to the compiler if the rule is successfully compiled,
    /// and used to ensure no rules matching those wildcard can be declared anymore
    /// in the namespace.
    pub rule_wildcard_uses: Vec<String>,
}

/// Helper struct used to track variables being compiled in a rule.
#[derive(Debug)]
pub(super) struct RuleCompilerVariable {
    /// Name of the variable.
    pub name: String,

    /// Span of the variable declaration.
    pub span: Range<usize>,

    /// Has the variable been used.
    ///
    /// If by the end of the compilation of the rule, the variable is unused, a compilation
    /// error is raised.
    pub used: bool,
}

impl<'a> RuleCompiler<'a> {
    pub(super) fn new(
        rule: &parser::Rule,
        namespace: &'a Namespace,
    ) -> Result<Self, CompilationError> {
        let mut names_set = HashSet::new();
        let mut variables = Vec::with_capacity(rule.variables.len());
        for var in &rule.variables {
            // Check duplicated names, but only for non anonymous strings
            if !var.name.is_empty() && !names_set.insert(var.name.clone()) {
                return Err(CompilationError::DuplicatedVariable {
                    name: var.name.clone(),
                    span: var.span.clone(),
                });
            }

            variables.push(RuleCompilerVariable {
                name: var.name.clone(),
                used: false,
                span: var.span.clone(),
            });
        }

        Ok(Self {
            namespace,
            variables,
            bounded_identifiers: HashMap::new(),
            rule_wildcard_uses: Vec::new(),
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
        &mut self,
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
        &mut self,
        name: &str,
        span: &Range<usize>,
    ) -> Result<usize, CompilationError> {
        for (index, var) in self.variables.iter_mut().enumerate() {
            if var.name == name {
                var.used = true;
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
    namespace: &mut Namespace,
) -> Result<Rule, CompilationError> {
    let (condition, wildcards, vars) = {
        let mut compiler = RuleCompiler::new(&rule, namespace)?;
        let condition = compile_expression(&mut compiler, rule.condition)?;

        (condition, compiler.rule_wildcard_uses, compiler.variables)
    };
    if !wildcards.is_empty() {
        namespace.forbidden_rule_prefixes.extend(wildcards);
    }

    // Check duplication of tags
    let mut tags_set = HashSet::new();
    for tag in &rule.tags {
        if !tags_set.insert(tag) {
            return Err(CompilationError::DuplicatedRuleTag(tag.to_string()));
        }
    }

    // Check whether some variables were not used.
    for var in vars {
        if !var.used {
            return Err(CompilationError::UnusedVariable {
                name: var.name,
                span: var.span,
            });
        }
    }

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
