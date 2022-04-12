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

/// Context linked to compilation of a yara file.
struct FileContext<'a> {
    /// Symbols available to use in the file.
    ///
    /// Those symbols come from two sources:
    /// - imported modules in the file
    /// - rules included, or rules declared earlier in the file.
    symbols: HashMap<String, &'a Module>,
}

impl<'a> FileContext<'a> {
    fn new(
        file: &parser::YaraFile,
        available_modules: &'a HashMap<String, Module>,
    ) -> Result<Self, CompilationError> {
        let mut symbols = HashMap::with_capacity(file.imports.len());

        for import in &file.imports {
            match available_modules.get(import) {
                Some(module) => {
                    // Ignore result: if the import was already done, it's fine.
                    let _r = symbols.insert(import.clone(), module);
                }
                None => return Err(CompilationError::UnknownImport(import.clone())),
            };
        }

        Ok(Self { symbols })
    }
}

/// Object used to compile a rule.
struct RuleCompiler<'a> {
    /// Context linked to the file containing the rule.
    file: &'a FileContext<'a>,

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
        file_context: &'a FileContext<'a>,
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
            file: file_context,
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
) -> Result<Vec<Rule>, CompilationError> {
    let file_context = FileContext::new(&file, available_modules)?;

    let mut compiled_rules = Vec::with_capacity(file.rules.len());
    for rule in file.rules {
        compiled_rules.push(compile_rule(rule, &file_context)?);
    }

    Ok(compiled_rules)
}

fn compile_rule(
    rule: parser::Rule,
    file_context: &FileContext<'_>,
) -> Result<Rule, CompilationError> {
    let compiler = RuleCompiler::new(&rule, file_context)?;
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
