use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use boreal_parser::rule;

use super::expression::{compile_bool_expression, Expression, VariableIndex};
use super::external_symbol::ExternalSymbol;
use super::{variable, CompilationError, CompilerParams, Namespace};
use crate::bytes_pool::{BytesPoolBuilder, BytesSymbol, StringSymbol};
use crate::module::Type as ModuleType;
use crate::statistics;

/// A compiled scanning rule.
#[derive(Debug)]
#[cfg_attr(all(test, feature = "serialize"), derive(PartialEq))]
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

impl Rule {
    #[cfg(feature = "serialize")]
    pub(crate) fn deserialize<R: std::io::Read>(
        ctx: &crate::wire::DeserializeContext,
        reader: &mut R,
    ) -> std::io::Result<Self> {
        wire::deserialize_rule(ctx, reader)
    }
}

/// A metadata associated with a rule.
#[derive(Debug, PartialEq)]
pub struct Metadata {
    /// Name of the metadata.
    ///
    /// Use [`crate::Scanner::get_string_symbol`] to retrieve the string.
    pub name: StringSymbol,

    /// The value of the metadata.
    pub value: MetadataValue,
}

/// Value of a rule metadata.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MetadataValue {
    /// Bytestring variant.
    ///
    /// Use [`crate::Scanner::get_bytes_symbol`] to retrieve the string.
    Bytes(BytesSymbol),
    /// Integer variant.
    Integer(i64),
    /// Boolean variant.
    Boolean(bool),
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

    /// Bytes intern pool.
    pub bytes_pool: &'a mut BytesPoolBuilder,
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
        rule_variables: &[rule::VariableDeclaration],
        namespace: &'a Namespace,
        external_symbols: &'a Vec<ExternalSymbol>,
        params: &'a CompilerParams,
        bytes_pool: &'a mut BytesPoolBuilder,
    ) -> Result<Self, CompilationError> {
        if rule_variables.len() > params.max_strings_per_rule {
            return Err(CompilationError::TooManyStrings {
                span: rule_variables[params.max_strings_per_rule].span.clone(),
                limit: params.max_strings_per_rule,
            });
        }

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
            bytes_pool,
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
        if matches!(err, CompilationError::RegexUnknownEscape { .. })
            && self.params.disable_unknown_escape_warning
        {
            return Ok(());
        }

        if self.params.fail_on_warnings {
            Err(err)
        } else {
            self.warnings.push(err);
            Ok(())
        }
    }
}

pub(super) fn compile_rule(
    rule: rule::Rule,
    namespace: &Namespace,
    namespace_index: usize,
    external_symbols: &Vec<ExternalSymbol>,
    params: &CompilerParams,
    parsed_contents: &str,
    bytes_pool: &mut BytesPoolBuilder,
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

    let metadatas: Vec<_> = rule
        .metadatas
        .into_iter()
        .map(|rule::Metadata { name, value }| Metadata {
            name: bytes_pool.insert_str(&name),
            value: match value {
                rule::MetadataValue::Bytes(v) => MetadataValue::Bytes(bytes_pool.insert(&v)),
                rule::MetadataValue::Integer(v) => MetadataValue::Integer(v),
                rule::MetadataValue::Boolean(v) => MetadataValue::Boolean(v),
            },
        })
        .collect();

    let mut compiler = RuleCompiler::new(
        &rule.variables,
        namespace,
        external_symbols,
        params,
        bytes_pool,
    )?;
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
            metadatas,
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

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use crate::compiler::expression::Expression;
    use crate::wire::DeserializeContext;
    use crate::{BytesSymbol, StringSymbol};

    use super::{Metadata, MetadataValue, Rule};

    impl Serialize for Rule {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.name.serialize(writer)?;
            self.namespace_index.serialize(writer)?;
            self.nb_variables.serialize(writer)?;
            self.is_private.serialize(writer)?;
            self.tags.serialize(writer)?;
            self.metadatas.serialize(writer)?;
            self.condition.serialize(writer)?;
            Ok(())
        }
    }

    pub(super) fn deserialize_rule<R: io::Read>(
        ctx: &DeserializeContext,
        reader: &mut R,
    ) -> io::Result<Rule> {
        let name = String::deserialize_reader(reader)?;
        let namespace_index = usize::deserialize_reader(reader)?;
        let nb_variables = usize::deserialize_reader(reader)?;
        let is_private = bool::deserialize_reader(reader)?;
        let tags = <Vec<String>>::deserialize_reader(reader)?;
        let metadatas = <Vec<Metadata>>::deserialize_reader(reader)?;
        let condition = Expression::deserialize(ctx, reader)?;
        Ok(Rule {
            name,
            namespace_index,
            tags,
            metadatas,
            nb_variables,
            condition,
            is_private,
        })
    }

    impl Serialize for Metadata {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.name.serialize(writer)?;
            self.value.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for Metadata {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let name = StringSymbol::deserialize_reader(reader)?;
            let value = MetadataValue::deserialize_reader(reader)?;
            Ok(Self { name, value })
        }
    }

    impl Serialize for MetadataValue {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Self::Bytes(s) => {
                    0_u8.serialize(writer)?;
                    s.serialize(writer)?;
                }
                Self::Integer(v) => {
                    1_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
                Self::Boolean(v) => {
                    2_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
            }
            Ok(())
        }
    }

    impl Deserialize for MetadataValue {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let discriminant = u8::deserialize_reader(reader)?;
            match discriminant {
                0 => Ok(Self::Bytes(BytesSymbol::deserialize_reader(reader)?)),
                1 => Ok(Self::Integer(i64::deserialize_reader(reader)?)),
                2 => Ok(Self::Boolean(bool::deserialize_reader(reader)?)),
                v => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid discriminant when deserializing a metadata value: {v}"),
                )),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::compiler::BytesPoolBuilder;
        use crate::wire::tests::{
            test_invalid_deserialization, test_round_trip, test_round_trip_custom_deser,
        };

        use super::*;

        #[test]
        fn test_wire_rule() {
            let ctx = DeserializeContext::default();

            test_round_trip_custom_deser(
                &Rule {
                    name: "a".to_owned(),
                    namespace_index: 0,
                    nb_variables: 0,
                    is_private: false,
                    tags: Vec::new(),
                    metadatas: Vec::new(),
                    condition: Expression::Filesize,
                },
                |reader| deserialize_rule(&ctx, reader),
                &[0, 5, 13, 21, 22, 26, 30],
            );
        }

        #[test]
        fn test_wire_metadata() {
            let mut pool = BytesPoolBuilder::default();

            test_round_trip(
                &Metadata {
                    name: pool.insert_str("ab"),
                    value: MetadataValue::Boolean(true),
                },
                &[0, 16],
            );

            test_invalid_deserialization::<MetadataValue>(b"\x05");
        }

        #[test]
        fn test_wire_metadata_value() {
            let mut pool = BytesPoolBuilder::default();

            test_round_trip(&MetadataValue::Bytes(pool.insert(b"a")), &[0, 1]);
            test_round_trip(&MetadataValue::Integer(23), &[0, 1]);
            test_round_trip(&MetadataValue::Boolean(true), &[0, 1]);

            test_invalid_deserialization::<MetadataValue>(b"\x05");
        }
    }
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
            bytes_pool: &mut BytesPoolBuilder::default(),
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
        let mut pool = BytesPoolBuilder::default();
        test_type_traits_non_clonable(Metadata {
            name: pool.insert_str(""),
            value: MetadataValue::Boolean(true),
        });
        test_type_traits(MetadataValue::Boolean(true));
    }
}
