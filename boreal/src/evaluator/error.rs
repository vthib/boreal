//! Errors related to evaluation of rules.

/// Type of error while compiling a rule.
#[derive(Debug)]
pub enum EvalError {
    /// Undecidable evaluation.
    ///
    /// Can be returned when evaluating rules without the variable evaluations, and the rules
    /// need those to be computed.
    Undecidable,
}

impl std::error::Error for EvalError {}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undecidable => write!(f, "undecidable"),
        }
    }
}
