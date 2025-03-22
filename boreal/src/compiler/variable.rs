use boreal_parser::rule::{VariableDeclaration, VariableDeclarationValue};

use crate::atoms::{atoms_rank, pick_atom_in_literal};
use crate::matcher::{Matcher, Modifiers};
use crate::regex::regex_ast_to_hir;
use crate::statistics;

use super::rule::RuleCompiler;
use super::CompilationError;

/// A compiled variable used in a rule.
#[derive(Debug)]
#[cfg_attr(all(test, feature = "serialize"), derive(PartialEq))]
pub struct Variable {
    /// Name of the variable, without the '$'.
    ///
    /// Anonymous variables are just named "".
    pub name: String,

    /// Is the variable marked as private.
    pub is_private: bool,

    /// Matcher for the variable.
    pub(crate) matcher: Matcher,
}

pub(super) fn compile_variable(
    compiler: &mut RuleCompiler,
    decl: VariableDeclaration,
    parsed_contents: &str,
) -> Result<(Variable, Option<statistics::CompiledString>), CompilationError> {
    let VariableDeclaration {
        name,
        value,
        mut modifiers,
        span,
    } = decl;

    if !modifiers.wide {
        modifiers.ascii = true;
    }

    let res = match value {
        VariableDeclarationValue::Bytes(s) => {
            if s.is_empty() {
                Err(VariableCompilationError::Empty)
            } else {
                Ok(Matcher::new_bytes(s, &modifiers))
            }
        }
        VariableDeclarationValue::Regex(boreal_parser::regex::Regex {
            ast,
            case_insensitive,
            dot_all,
            span: _,
        }) => {
            if case_insensitive {
                modifiers.nocase = true;
            }
            let mut warnings = Vec::new();
            let hir = regex_ast_to_hir(ast, &mut warnings);
            for warn in warnings {
                compiler.add_warning(warn.into())?;
            }
            Matcher::new_regex(
                &hir,
                Modifiers {
                    fullword: modifiers.fullword,
                    wide: modifiers.wide,
                    ascii: modifiers.ascii,
                    nocase: modifiers.nocase,
                    dot_all,
                    xor_start: None,
                },
            )
            .map_err(VariableCompilationError::Regex)
        }
        VariableDeclarationValue::HexString(hex_string) => Matcher::new_regex(
            &hex_string.into(),
            Modifiers {
                fullword: modifiers.fullword,
                wide: modifiers.wide,
                ascii: modifiers.ascii,
                nocase: modifiers.nocase,
                dot_all: true,
                xor_start: None,
            },
        )
        .map_err(VariableCompilationError::Regex),
    };

    let res = match res {
        Ok(matcher) => Variable {
            name,
            is_private: modifiers.private,
            matcher,
        },
        Err(error) => {
            return Err(CompilationError::VariableCompilation {
                variable_name: name,
                span,
                error,
            })
        }
    };

    let stats = if compiler.params.compute_statistics {
        let atoms: Vec<_> = res
            .matcher
            .literals
            .iter()
            .map(|lit| {
                let (start_offset, end_offset) = pick_atom_in_literal(lit);
                lit[start_offset..(lit.len() - end_offset)].to_vec()
            })
            .collect();
        let atoms_quality = atoms_rank(&atoms);

        Some(statistics::CompiledString {
            name: res.name.clone(),
            expr: parsed_contents[span.start..span.end].to_owned(),
            literals: res.matcher.literals.clone(),
            atoms,
            atoms_quality,
            matching_algo: res.matcher.to_desc(),
        })
    } else {
        None
    };

    Ok((res, stats))
}

/// Error during the compilation of a variable.
#[derive(Debug)]
pub enum VariableCompilationError {
    /// Variable is empty.
    Empty,

    /// Error when compiling a regex variable.
    Regex(crate::regex::Error),
}

impl std::fmt::Display for VariableCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "variable is empty"),
            Self::Regex(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use super::{Matcher, Variable};

    impl Serialize for Variable {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.name.serialize(writer)?;
            self.is_private.serialize(writer)?;
            self.matcher.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for Variable {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let name = String::deserialize_reader(reader)?;
            let is_private = bool::deserialize_reader(reader)?;
            let matcher = Matcher::deserialize_reader(reader)?;
            Ok(Self {
                name,
                is_private,
                matcher,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use boreal_parser::rule::VariableModifiers;

        use crate::matcher::Matcher;
        use crate::wire::tests::test_round_trip;

        use super::*;

        #[test]
        fn test_wire_variable() {
            test_round_trip(
                &Variable {
                    name: "abc".to_owned(),
                    is_private: true,
                    matcher: Matcher::new_bytes(Vec::new(), &VariableModifiers::default()),
                },
                &[0, 7, 8],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use boreal_parser::rule::VariableModifiers;

    use super::*;
    use crate::bytes_pool::BytesPoolBuilder;
    use crate::compiler::{CompilerParams, Namespace};
    use crate::regex::Regex;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        let mut compiler = RuleCompiler {
            namespace: &Namespace::default(),
            variables: Vec::new(),
            bounded_identifiers: HashMap::new(),
            rule_wildcard_uses: Vec::new(),
            external_symbols: &vec![],
            params: &CompilerParams::default(),
            condition_depth: 0,
            warnings: Vec::new(),
            bytes_pool: &mut BytesPoolBuilder::default(),
        };
        test_type_traits_non_clonable(
            compile_variable(
                &mut compiler,
                VariableDeclaration {
                    name: "a".to_owned(),
                    value: VariableDeclarationValue::Bytes(b"foo".to_vec()),
                    modifiers: VariableModifiers::default(),
                    span: 0..1,
                },
                "",
            )
            .unwrap()
            .0,
        );

        test_type_traits_non_clonable(VariableCompilationError::Regex(
            Regex::from_string("{".to_owned(), true, true).unwrap_err(),
        ));
    }
}
