//! Errors related to compilation of rules.

/// Error while compiling a rule.
#[derive(Debug)]
pub enum CompilationError {
    /// Error compiling a regex
    RegexError(regex::Error),
}
