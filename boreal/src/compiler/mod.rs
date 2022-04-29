//! Compilation of a parsed expression into an optimized one.
use std::collections::HashMap;
use std::ops::Range;

use boreal_parser as parser;

mod base64;
mod error;
pub use error::CompilationError;
mod expression;
pub use expression::*;
mod variable;
pub use variable::*;
mod module;
pub use module::*;

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

/// Object used to compile a rule.
struct RuleCompiler<'a> {
    /// Symbols available to use in the rule.
    ///
    /// Those symbols come from two sources:
    /// - imported modules in the file
    /// - rules included, or rules declared earlier in the file.
    symbols: &'a HashMap<String, &'a Module>,

    /// Map of variable name to index in the compiled rule variables vec.
    ///
    /// This only stores named variables. Anonymous ones are still stored
    /// (and thus have an index), but cannot be referred by name.
    // TODO: hashset of used variables per index, to indicate which ones
    // are unused.
    variables_map: HashMap<String, usize>,
}

impl<'a> RuleCompiler<'a> {
    fn new(
        rule: &parser::Rule,
        symbols: &'a HashMap<String, &'a Module>,
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
            symbols,
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
    fn find_variable(
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
    fn find_named_variable(
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

pub fn compile_file(
    file: parser::YaraFile,
    available_modules: &HashMap<String, Module>,
    rules: &mut Vec<Rule>,
) -> Result<(), CompilationError> {
    let mut symbols = HashMap::new();

    for component in file.components {
        match component {
            parser::YaraFileComponent::Include(_) => todo!(),
            parser::YaraFileComponent::Import(import) => {
                match available_modules.get(&import) {
                    Some(module) => {
                        // Ignore result: if the import was already done, it's fine.
                        let _r = symbols.insert(import.clone(), module);
                    }
                    None => return Err(CompilationError::UnknownImport(import.clone())),
                };
            }
            parser::YaraFileComponent::Rule(rule) => {
                rules.push(compile_rule(*rule, &symbols)?);
            }
        }
    }

    Ok(())
}

fn compile_rule<'a>(
    rule: parser::Rule,
    symbols: &'a HashMap<String, &'a Module>,
) -> Result<Rule, CompilationError> {
    let compiler = RuleCompiler::new(&rule, symbols)?;
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

#[cfg(test)]
mod tests;
