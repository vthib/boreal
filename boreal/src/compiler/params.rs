//! Compilation parameters

/// Parameters used during compilation.
#[derive(Clone, Debug)]
pub struct CompilerParams {
    /// Maximum depth in a rule's condition AST.
    pub(crate) max_condition_depth: u32,
}

impl Default for CompilerParams {
    fn default() -> Self {
        Self {
            max_condition_depth: 40,
        }
    }
}

impl CompilerParams {
    /// Maximum depth in a rule's condition AST.
    ///
    /// This is a defensive limit to prevent the compilation or evaluation of
    /// the rule to trigger a stack overflow.
    ///
    /// This limit should only be reached in rules written to try to trigger
    /// a stack overflow. However, should this limit be too low for real rules,
    /// it can be raised.
    ///
    /// Default value is `40`.
    #[must_use]
    pub fn max_condition_depth(mut self, max_condition_depth: u32) -> Self {
        self.max_condition_depth = max_condition_depth;
        self
    }
}
