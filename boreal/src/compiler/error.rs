//! Errors related to compilation of rules.
use codespan_reporting::diagnostic::Diagnostic;

/// Error while compiling a rule.
#[derive(Debug)]
pub enum CompilationError {
    /// Error compiling a regex
    RegexError {
        /// Expression used as a regex, that failed to build
        expr: String,
        /// Error returned by the [`regex`] crate.
        error: regex::Error,
    },
}

impl CompilationError {
    #[must_use]
    pub(crate) fn to_diagnostic(&self) -> Diagnostic<()> {
        match self {
            // TODO: get span from parser
            Self::RegexError { expr, error } => Diagnostic::error()
                .with_message(format!("regex `{}` failed to build: {:?}", expr, error)),
        }
    }
}
