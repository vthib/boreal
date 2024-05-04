use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use boreal_parser::rule::Metadata;
use boreal_parser::rule::VariableDeclaration;

use super::expression::{compile_bool_expression, Expression, VariableIndex};
use super::external_symbol::ExternalSymbol;
use super::{variable, CompilationError, CompilerParams, Namespace};
use crate::module::Type as ModuleType;
use crate::statistics;

/// A compiled scanning rule.
#[derive(Debug)]
pub(crate) struct Rule {
    /// Name of the rule.
    pub(crate) name: String,

    /// Index of the namespace containing the rule.
    ///
    /// This refers to the [`super::Compiler::namespaces`] or
    /// [`crate::Scanner::namespaces`] list.
    pub(crate) namespace_index: usize,

    /// Tags associated with the rule.
    pub(crate) tags: Vec<String>,

    /// Metadata associated with the rule.
    pub(crate) metadatas: Vec<Metadata>,

    /// Number of variables used by the rule.
    pub(crate) nb_variables: usize,

    /// Condition of the rule.
    pub(crate) condition: Expression,

    /// Is the rule marked as private.
    pub(crate) is_private: bool,
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
    pub bounded_identifiers: HashMap<String, Arc<(ModuleType, usize)>>,

    /// List of rules wildcard used in for expressions.
    ///
    /// This will be added to the compiler if the rule is successfully compiled,
    /// and used to ensure no rules matching those wildcard can be declared anymore
    /// in the namespace.
    pub rule_wildcard_uses: Vec<String>,

    /// List of external symbols defined in the compiler.
    pub external_symbols: &'a Vec<ExternalSymbol>,

    /// Compilation parameters
    pub params: &'a CompilerParams,

    /// Current depth in the rule's condition AST.
    ///
    /// As evaluation of a rule condition involves recursion, this is used to limit the
    /// depth of this recursion and prevent stack overflows.
    pub condition_depth: u32,

    /// Warnings emitted while compiling the rule.
    pub warnings: Vec<CompilationError>,
}

/// Helper struct used to track variables being compiled in a rule.
#[derive(Debug)]
pub(super) struct RuleCompilerVariable {
    /// Name of the variable.
    pub name: String,

    /// Has the variable been used.
    ///
    /// If by the end of the compilation of the rule, the variable is unused, a compilation
    /// error is raised.
    pub used: bool,
}

impl<'a> RuleCompiler<'a> {
    pub(super) fn new(
        rule_variables: &[VariableDeclaration],
        namespace: &'a Namespace,
        external_symbols: &'a Vec<ExternalSymbol>,
        params: &'a CompilerParams,
    ) -> Result<Self, CompilationError> {
        let mut names_set = HashSet::new();
        let mut variables = Vec::with_capacity(rule_variables.len());
        for var in rule_variables {
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
            });
        }

        Ok(Self {
            namespace,
            variables,
            bounded_identifiers: HashMap::new(),
            rule_wildcard_uses: Vec::new(),
            external_symbols,
            params,
            condition_depth: 0,
            warnings: Vec::new(),
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
        typ: ModuleType,
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

    pub(super) fn add_warning(&mut self, err: CompilationError) -> Result<(), CompilationError> {
        if self.params.fail_on_warnings {
            Err(err)
        } else {
            self.warnings.push(err);
            Ok(())
        }
    }
}

pub(super) fn compile_rule(
    rule: boreal_parser::rule::Rule,
    namespace: &Namespace,
    namespace_index: usize,
    external_symbols: &Vec<ExternalSymbol>,
    params: &CompilerParams,
    parsed_contents: &str,
) -> Result<CompiledRule, CompilationError> {
    // Check duplication of tags
    let mut tags_spans = HashMap::with_capacity(rule.tags.len());
    for v in &rule.tags {
        if let Some(span1) = tags_spans.insert(&v.tag, v.span.clone()) {
            return Err(CompilationError::DuplicatedRuleTag {
                tag: v.tag.clone(),
                span1,
                span2: v.span.clone(),
            });
        }
    }

    let mut compiler = RuleCompiler::new(&rule.variables, namespace, external_symbols, params)?;
    let condition = compile_bool_expression(&mut compiler, rule.condition)?;

    let mut variables = Vec::with_capacity(rule.variables.len());
    let mut variables_statistics = Vec::new();

    for (i, var) in rule.variables.into_iter().enumerate() {
        if !compiler.variables[i].used && !var.name.starts_with('_') {
            return Err(CompilationError::UnusedVariable {
                name: var.name,
                span: var.span,
            });
        }

        let (var, stats) = variable::compile_variable(&mut compiler, var, parsed_contents)?;
        if let Some(stats) = stats {
            variables_statistics.push(stats);
        }
        variables.push(var);
    }

    Ok(CompiledRule {
        rule: Rule {
            name: rule.name,
            namespace_index,
            tags: rule.tags.into_iter().map(|v| v.tag).collect(),
            metadatas: rule.metadatas,
            nb_variables: variables.len(),
            condition,
            is_private: rule.is_private,
        },
        variables,
        variables_statistics,
        warnings: compiler.warnings,
        rule_wildcard_uses: compiler.rule_wildcard_uses,
    })
}

#[derive(Debug)]
pub(super) struct CompiledRule {
    pub rule: Rule,
    pub variables: Vec<variable::Variable>,
    pub variables_statistics: Vec<statistics::CompiledString>,
    pub warnings: Vec<CompilationError>,
    pub rule_wildcard_uses: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(RuleCompiler {
            namespace: &Namespace::default(),
            variables: Vec::new(),
            bounded_identifiers: HashMap::new(),
            rule_wildcard_uses: Vec::new(),
            external_symbols: &vec![],
            params: &CompilerParams::default(),
            condition_depth: 0,
            warnings: Vec::new(),
        });
        let build_rule = || Rule {
            name: "a".to_owned(),
            namespace_index: 0,
            tags: Vec::new(),
            metadatas: Vec::new(),
            nb_variables: 0,
            condition: Expression::Filesize,
            is_private: false,
        };
        test_type_traits_non_clonable(build_rule());
        test_type_traits_non_clonable(CompiledRule {
            rule: build_rule(),
            variables: Vec::new(),
            variables_statistics: Vec::new(),
            warnings: Vec::new(),
            rule_wildcard_uses: Vec::new(),
        });
        test_type_traits_non_clonable(RuleCompilerVariable {
            name: "a".to_owned(),
            used: false,
        });
    }
}
