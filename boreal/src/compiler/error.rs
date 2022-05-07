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
        /// Span of the regex expression in the input
        span: Range<usize>,
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

    /// Duplicated rule name in a namespace.
    // TODO: add span
    DuplicatedRuleName(String),

    /// Duplicated variable names in a rule.
    ///
    /// The value is the name of the variable that appears more than once
    /// in the declarations.
    DuplicatedVariable(String),

    /// Invalid binding of an identifier in a for expression.
    ///
    /// This indicates that the iterator items is a different cardinality from the bound identifiers.
    ///
    /// For example, `for any i in module.dictionary`, or `for any k, v in (0..3)`.
    InvalidIdentifierBinding {
        /// Actual number of identifiers to bind.
        actual_number: usize,
        /// Expected number of identifiers, i.e. cardinality of the iterator's items.
        expected_number: usize,
        /// Span of the identifiers
        identifiers_span: Range<usize>,
        /// Span of the iterator
        iterator_span: Range<usize>,
    },

    /// Invalid function call on an identifier
    InvalidIdentifierCall {
        /// Types of the provided arguments
        arguments_types: Vec<String>,
        /// The span of the function call.
        span: Range<usize>,
    },

    /// Invalid type for an expression used as an index in an identifier.
    ///
    /// For example, `pe.section[true]`
    InvalidIdentifierIndexType {
        /// Type of the expression
        ty: String,
        /// Span of the expression
        span: Range<usize>,
        /// Expected type for the index
        expected_type: String,
    },

    /// Invalid type for an identifier
    InvalidIdentifierType {
        /// Type of the identifier
        actual_type: String,
        /// The expected type
        expected_type: String,
        /// The span of the identifier with the wrong type.
        span: Range<usize>,
    },

    /// Invalid use of an identifier.
    ///
    /// This indicates either:
    ///
    /// - that an identifier with a compound type was used as a value in an expression.
    ///   For example, `pe.foo > 0`, where `pe.foo` is an array, a dictionary or a function.
    /// - that a rule identifier (so a boolean) was used as a compound type.
    ///   For example, `a.foo`, when `a` is the name of a rule, as `a` is a boolean.
    InvalidIdentifierUse {
        /// The span of the identifier that is not used correctly.
        span: Range<usize>,
    },

    /// Unknown identifier used in a rule.
    UnknownIdentifier {
        /// The name of the identifier that is not bound.
        name: String,
        /// Span of the identifier name
        span: Range<usize>,
    },

    /// Unknown import used in a file.
    ///
    /// The value is the name of the import that did not match any known module.
    // TODO: add span
    UnknownImport(String),

    /// Unknown field used in a identifier.
    UnknownIdentifierField {
        /// The name of the field that is unknown.
        field_name: String,
        /// Span of the field access
        span: Range<usize>,
    },

    /// Unknown variable used in a rule.
    UnknownVariable {
        /// Name of the variable
        variable_name: String,
        /// Span of the variable use in the condition
        span: Range<usize>,
    },

    /// Error while compiling a variable, indicating an issue with
    /// its expression.
    VariableCompilation {
        /// Name of the variable
        variable_name: String,

        /// Error returned by [`grep_regex`] when compiling the contents
        /// of the variable.
        error: grep_regex::Error,
    },
}

impl CompilationError {
    #[must_use]
    pub(crate) fn to_diagnostic(&self) -> Diagnostic<()> {
        match self {
            Self::RegexError { expr, error, span } => Diagnostic::error()
                .with_message(format!("regex `{}` failed to build: {:?}", expr, error))
                .with_labels(vec![Label::primary((), span.clone())]),

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

            Self::DuplicatedRuleName(name) => Diagnostic::error().with_message(format!(
                "rule `{}` is already declared in this namespace",
                name
            )),

            Self::DuplicatedVariable(name) => Diagnostic::error()
                .with_message(format!("variable ${} is declared more than once", name)),

            Self::InvalidIdentifierIndexType {
                ty,
                span,
                expected_type,
            } => Diagnostic::error()
                .with_message(format!("expected an expression of type {}", expected_type))
                .with_labels(vec![
                    Label::primary((), span.clone()).with_message(format!("this has type {}", ty))
                ]),

            Self::InvalidIdentifierType {
                actual_type,
                expected_type,
                span,
            } => Diagnostic::error()
                .with_message("invalid identifier type")
                .with_labels(vec![Label::primary((), span.clone()).with_message(
                    format!("expected {}, found {}", expected_type, actual_type),
                )]),

            Self::InvalidIdentifierBinding {
                actual_number,
                expected_number,
                identifiers_span,
                iterator_span,
            } => Diagnostic::error()
                .with_message(format!(
                    "expected {} identifiers to bind, got {}",
                    expected_number, actual_number
                ))
                .with_labels(vec![
                    Label::primary(
                        (),
                        Range {
                            start: identifiers_span.start,
                            end: iterator_span.end,
                        },
                    ),
                    Label::secondary((), identifiers_span.clone())
                        .with_message(format!("only {} identifiers being bound", actual_number)),
                    Label::secondary((), iterator_span.clone()).with_message(format!(
                        "this yields {} elements on every iteration",
                        expected_number
                    )),
                ]),

            Self::InvalidIdentifierCall {
                arguments_types,
                span,
            } => Diagnostic::error()
                .with_message(format!(
                    "invalid arguments types: [{}]",
                    arguments_types.join(", ")
                ))
                .with_labels(vec![Label::primary((), span.clone())]),

            Self::InvalidIdentifierUse { span } => Diagnostic::error()
                .with_message("wrong use of identifier")
                .with_labels(vec![Label::primary((), span.clone())]),

            Self::UnknownIdentifier { name, span } => Diagnostic::error()
                .with_message(format!("unknown identifier \"{}\"", name))
                .with_labels(vec![Label::primary((), span.clone())]),

            Self::UnknownImport(name) => {
                Diagnostic::error().with_message(format!("unknown import {}", name))
            }

            Self::UnknownIdentifierField { field_name, span } => Diagnostic::error()
                .with_message(format!("unknown field \"{}\"", field_name))
                .with_labels(vec![Label::primary((), span.clone())]),

            Self::UnknownVariable {
                variable_name,
                span,
            } => Diagnostic::error()
                .with_message(format!("unknown variable ${}", variable_name))
                .with_labels(vec![Label::primary((), span.clone())]),

            // TODO: need span for variable
            Self::VariableCompilation {
                variable_name,
                error,
            } => Diagnostic::error().with_message(format!(
                "variable ${} cannot be compiled: {:?}",
                variable_name, error
            )),
        }
    }
}
