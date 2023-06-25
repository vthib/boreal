use std::collections::HashSet;
use std::ops::Range;
use std::{collections::HashMap, sync::Arc};

use boreal_parser as parser;

use super::expression::{compile_bool_expression, Expression, VariableIndex};
use super::external_symbol::ExternalSymbol;
use super::{variable, CompilationError, CompilerParams, Namespace};
use crate::module::Type as ModuleType;
use crate::statistics;

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

    /// Number of variables used by the rule.
    pub(crate) nb_variables: usize,

    /// Condition of the rule.
    pub(crate) condition: Expression,

    pub is_private: bool,
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

    /// Whether the anonymous var requires full matches or not
    pub anonymous_var_usage: RuleVariableUsage,
}

/// Helper struct used to track variables being compiled in a rule.
#[derive(Debug)]
pub(super) struct RuleCompilerVariable {
    /// Name of the variable.
    pub name: String,

    /// How the variable is used.
    pub usage: RuleVariableUsage,
}

/// Describes how a variable is used inside of a rule condition.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RuleVariableUsage {
    /// Variable has not been used yet.
    Unused,

    /// Variable is used and only its presence or not is required.
    Presence,

    /// Variable is used and full details on its matches are required.
    FullMatches,
}

impl RuleVariableUsage {
    pub fn merge(&mut self, other: Self) {
        *self = std::cmp::max(*self, other);
    }
}

impl<'a> RuleCompiler<'a> {
    pub(super) fn new(
        rule: &parser::Rule,
        namespace: &'a Namespace,
        external_symbols: &'a Vec<ExternalSymbol>,
        params: &'a CompilerParams,
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
                usage: RuleVariableUsage::Unused,
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
            anonymous_var_usage: RuleVariableUsage::Unused,
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
        usage: RuleVariableUsage,
    ) -> Result<VariableIndex, CompilationError> {
        if name.is_empty() {
            self.anonymous_var_usage.merge(usage);
            Ok(VariableIndex(None))
        } else {
            Ok(VariableIndex(Some(
                self.find_named_variable(name, span, usage)?,
            )))
        }
    }

    /// Find a variable used in a rule by name, without accepting anonymous variables.
    pub(super) fn find_named_variable(
        &mut self,
        name: &str,
        span: &Range<usize>,
        usage: RuleVariableUsage,
    ) -> Result<usize, CompilationError> {
        for (index, var) in self.variables.iter_mut().enumerate() {
            if var.name == name {
                var.usage.merge(usage);
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
    rule: parser::Rule,
    namespace: &mut Namespace,
    external_symbols: &Vec<ExternalSymbol>,
    params: &CompilerParams,
    parsed_contents: &str,
) -> Result<CompiledRule, CompilationError> {
    let (condition, wildcards, vars, warnings) = {
        let mut compiler = RuleCompiler::new(&rule, namespace, external_symbols, params)?;
        let condition = compile_bool_expression(&mut compiler, rule.condition)?;

        (
            condition,
            compiler.rule_wildcard_uses,
            compiler.variables,
            compiler.warnings,
        )
    };
    if !wildcards.is_empty() {
        namespace.forbidden_rule_prefixes.extend(wildcards);
    }

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

    let mut variables = Vec::with_capacity(rule.variables.len());
    let mut variables_statistics = Vec::new();

    for (var_declaration, usage) in rule
        .variables
        .into_iter()
        .zip(vars.into_iter().map(|v| v.usage))
    {
        let need_full_matches = match usage {
            RuleVariableUsage::Unused => {
                return Err(CompilationError::UnusedVariable {
                    name: var_declaration.name,
                    span: var_declaration.span,
                })
            }
            RuleVariableUsage::Presence => false,
            RuleVariableUsage::FullMatches => true,
        };

        let (var, stats) = variable::compile_variable(
            var_declaration,
            parsed_contents,
            need_full_matches,
            params.compute_statistics,
        )?;
        if let Some(stats) = stats {
            variables_statistics.push(stats);
        }
        variables.push(var);
    }

    Ok(CompiledRule {
        rule: Rule {
            name: rule.name,
            namespace: namespace.name.clone(),
            tags: rule.tags.into_iter().map(|v| v.tag).collect(),
            metadatas: rule.metadatas,
            nb_variables: variables.len(),
            condition,
            is_private: rule.is_private,
        },
        variables,
        variables_statistics,
        warnings,
    })
}

#[derive(Debug)]
pub(super) struct CompiledRule {
    pub rule: Rule,
    pub variables: Vec<variable::Variable>,
    pub variables_statistics: Vec<statistics::CompiledString>,
    pub warnings: Vec<CompilationError>,
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

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
            anonymous_var_usage: RuleVariableUsage::Unused,
        });
        let build_rule = || Rule {
            name: "a".to_owned(),
            namespace: None,
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
        });
        test_type_traits_non_clonable(RuleCompilerVariable {
            name: "a".to_owned(),
            usage: RuleVariableUsage::Unused,
        });
        test_type_traits(RuleVariableUsage::Unused);
    }
}
