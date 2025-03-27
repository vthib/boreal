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

    /// Disable includes in YARA documents.
    pub(crate) disable_includes: bool,

    /// Maximum number of strings in a single rule.
    pub(crate) max_strings_per_rule: usize,

    /// Disable unknown escapes in regex warnings.
    pub(crate) disable_unknown_escape_warning: bool,
}

impl Default for CompilerParams {
    fn default() -> Self {
        Self {
            max_condition_depth: 40,
            fail_on_warnings: false,
            compute_statistics: false,
            disable_includes: false,
            max_strings_per_rule: 10_000,
            disable_unknown_escape_warning: false,
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

    /// Disable the possibility to include yara files.
    ///
    /// If true, an error is returned if the `include` keyword is used in a YARA document.
    /// Compute statistics during compilation.
    ///
    /// Default value is false.
    #[must_use]
    pub fn disable_includes(mut self, disable_includes: bool) -> Self {
        self.disable_includes = disable_includes;
        self
    }

    /// Set the maximum number of strings in a single rule.
    ///
    /// If a rule contains more strings than this limit, its compilation will fail.
    ///
    /// Default value is 10 000.
    #[must_use]
    pub fn max_strings_per_rule(mut self, max_strings_per_rule: usize) -> Self {
        self.max_strings_per_rule = max_strings_per_rule;
        self
    }

    /// Disable the "unknown escape sequence" warning.
    ///
    /// By default, unknown escape sequences in regexes generate warnings.
    /// Setting this parameter to true removes those warnings.
    ///
    /// Default value is false
    #[must_use]
    pub fn disable_unknown_escape_warning(mut self, disable_unknown_escape_warning: bool) -> Self {
        self.disable_unknown_escape_warning = disable_unknown_escape_warning;
        self
    }
}
