//! Errors related to compilation of rules.
use std::ops::Range;

use codespan_reporting::diagnostic::{Diagnostic, Label};

/// Error while compiling a rule.
#[derive(Debug)]
pub struct CompilationError {
    /// Kind of the error
    pub kind: CompilationErrorKind,
    /// Span of the parsed string comprising the error
    pub span: Range<usize>,
}

/// Type of error while compiling a rule.
#[derive(Debug)]
pub enum CompilationErrorKind {
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
        match &self.kind {
            // TODO: get span from parser
            CompilationErrorKind::RegexError { expr, error } => Diagnostic::error()
                .with_message(format!("regex `{}` failed to build: {:?}", expr, error)),
            CompilationErrorKind::ExpressionInvalidType { ty, expected_type } => {
                Diagnostic::error()
                    .with_message("expression has an invalid type")
                    .with_labels(vec![Label::primary((), self.span.clone())
                        .with_message(format!("expected {}, found {}", expected_type, ty))])
            }
            CompilationErrorKind::ExpressionIncompatibleTypes {
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
