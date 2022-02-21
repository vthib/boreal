//! Errors related to compilation of rules.
use std::ops::Range;

use codespan_reporting::diagnostic::{Diagnostic, Label};

/// Type of error while compiling a rule.
#[derive(Debug)]
pub enum CompilationError {
    /// Error compiling a regex
    RegexError {
        /// Expression used as a regex, that failed to build
        expr: String,
        /// Error returned by the [`regex`] crate.
        error: regex::Error,
    },

    /// Expression with an invalid type
    ExpressionInvalidType {
        /// Type of the expression
        ty: String,
        /// Expected type
        expected_type: String,
        /// Span of the expression
        span: Range<usize>,
    },

    /// Operands of an expression have incompatible types.
    ///
    /// The incompatibility is either between the two operands (e.g. integer
    /// and string) or with the operator (e.g. division between regexes).
    ExpressionIncompatibleTypes {
        /// Type of the left operand
        left_type: String,
        /// Span of the left operand
        left_span: Range<usize>,
        /// Type of the right operand
        right_type: String,
        /// Span of the right operand
        right_span: Range<usize>,
    },
}

impl CompilationError {
    #[must_use]
    pub(crate) fn to_diagnostic(&self) -> Diagnostic<()> {
        match &self {
            // TODO: get span from parser
            Self::RegexError { expr, error } => Diagnostic::error()
                .with_message(format!("regex `{}` failed to build: {:?}", expr, error)),
            Self::ExpressionInvalidType {
                ty,
                expected_type,
                span,
            } => Diagnostic::error()
                .with_message("expression has an invalid type")
                .with_labels(vec![Label::primary((), span.clone())
                    .with_message(format!("expected {}, found {}", expected_type, ty))]),
            Self::ExpressionIncompatibleTypes {
                left_type,
                left_span,
                right_type,
                right_span,
            } => Diagnostic::error()
                .with_message("expressions have invalid types")
                .with_labels(vec![
                    Label::secondary((), left_span.clone())
                        .with_message(format!("this has type {}", left_type)),
                    Label::secondary((), right_span.clone())
                        .with_message(format!("this has type {}", right_type)),
                ]),
        }
    }
}
