//! Errors related to evaluation of rules.

/// Type of error while compiling a rule.
#[derive(Debug)]
pub enum EvalError {
    /// Undecidable evaluation.
    ///
    /// Can be returned when evaluating rules without the variable evaluations, and the rules
    /// need those to be computed.
    Undecidable,

    /// Timeout while scanning.
    Timeout,

    /// The scan callback asked for the scan to be aborted.
    CallbackAbort,
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(EvalError::Undecidable);
    }
}
