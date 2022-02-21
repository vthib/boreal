//! Compilation of a parsed expression into an optimized one.
use boreal_parser as parser;

mod error;
pub use error::CompilationError;
mod expression;
pub use expression::*;
mod rule;
pub use rule::Rule;

pub struct Compiler;

impl Compiler {
    pub fn compile_rule(&self, rule: parser::Rule) -> Result<Rule, CompilationError> {
        rule::compile(self, rule)
    }
}
