//! Compilation parameters

/// Parameters used during compilation.
#[derive(Clone, Debug)]
pub struct CompilerParams {
    /// Maximum depth in a rule's condition AST.
    pub(crate) max_condition_depth: u32,

    /// Fail adding rules on warnings.
    pub(crate) fail_on_warnings: bool,

    /// Compute statistics when compiling rules.
    pub(crate) compute_statistics: bool,
}

impl Default for CompilerParams {
    fn default() -> Self {
        Self {
            max_condition_depth: 40,
            fail_on_warnings: false,
            compute_statistics: false,
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

    /// Report all warnings as errors.
    ///
    /// If set, all warnings are returned as errors, aborting adding rules to the
    /// compiler.
    ///
    /// Please note that new releases may introduce new warnings. Enabling this flag
    /// can thus break existing rules outside of semantic versioning, although new warnings
    /// will be reported on every new releases.
    ///
    /// Default value is false.
    #[must_use]
    pub fn fail_on_warnings(mut self, fail_on_warnings: bool) -> Self {
        self.fail_on_warnings = fail_on_warnings;
        self
    }

    /// Compute statistics during compilation.
    ///
    /// This option allows retrieve statistics related to the compilation of strings.
    /// See `AddRuleStatus::statistics`.
    ///
    /// Default value is false.
    #[must_use]
    pub fn compute_statistics(mut self, compute_statistics: bool) -> Self {
        self.compute_statistics = compute_statistics;
        self
    }
}
