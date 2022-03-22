//! This module contains everything related to errors occurring during scanning.

#[derive(Debug, PartialEq)]
pub enum ScanError {
    /// Overflow on an arithmetic operation
    Overflow {
        left_value: i64,
        right_value: i64,
        operator: String,
    },

    /// Invalid type of an expression.
    ///
    /// The resulting value of the evaluation of an expression
    /// does not have the right type.
    InvalidType {
        /// Type of the evaluated expression
        typ: String,
        /// Expected type
        expected_type: String,
        /// Operator that raised the error
        operator: String,
    },

    /// Two types incompatible with an operator
    IncompatibleTypes {
        /// Type of the expression on the left
        left_type: String,
        /// Type of the right expression (unset if operator is unary)
        right_type: Option<String>,
        /// Operator that raised the error
        operator: String,
    },

    /// An unnamed variable was used outside of a for context.
    ///
    /// This indicates the use of `$` or equivalents, outside the body of a for expression.
    // FIXME: this should be caught during compilation.
    UnnamedVariableUsed,
}
