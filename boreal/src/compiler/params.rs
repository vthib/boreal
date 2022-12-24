//! Compilation parameters

/// Parameters that can be modified during compilation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Parameters {
    /// Maximum depth in a rule's condition AST.
    ///
    /// Default value is `40`.
    pub max_condition_depth: u32,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            max_condition_depth: 40,
        }
    }
}
