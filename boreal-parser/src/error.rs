use std::num::{ParseFloatError, ParseIntError};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use nom::error::{ErrorKind as NomErrorKind, ParseError};

use super::types::{Input, Span};

/// Parsing error.
#[derive(Debug)]
pub struct Error {
    /// Span of the error in the input.
    ///
    /// This is a range of offset, in chars, from the beginning
    /// of the input given to [`parse_str`].
    span: Span,

    /// Kind of the error.
    kind: ErrorKind,
}

impl Error {
    #[must_use]
    pub(crate) fn new(span: Span, kind: ErrorKind) -> Self {
        Self { span, kind }
    }

    /// Convert to a [`Diagnostic`].
    ///
    /// This can be used to display the error in a more user-friendly manner
    /// than the simple `to_short_description`. It does require depending
    /// on the `codespan_reporting` crate to make use of this diagnostic
    /// however.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic<()> {
        match &self.kind {
            ErrorKind::Base64AlphabetInvalidLength { length } => Diagnostic::error()
                .with_message("base64 modifier alphabet must contain exactly 64 characters")
                .with_labels(vec![Label::primary((), self.span.clone())
                    .with_message(format!("this contains {} characters", length))]),

            ErrorKind::EmptyRegex => Diagnostic::error()
                .with_message("regexes cannot be empty")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::HasTrailingData => Diagnostic::error()
                .with_message("some data could not be parsed")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpEmpty => Diagnostic::error()
                .with_message("jump cannot have a length of 0")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpRangeInvalid { from, to } => Diagnostic::error()
                .with_message(format!("invalid range for the jump: {} > {}", from, to))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpTooBigInAlternation { limit } => Diagnostic::error()
                .with_message(format!(
                    "jumps over {} not allowed inside alternations (|)",
                    limit
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpUnboundedInAlternation => Diagnostic::error()
                .with_message("unbounded jumps not allowed inside alternations (|)")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::ModifiersDuplicated { modifier_name } => Diagnostic::error()
                .with_message(format!(
                    "string modifier {} appears multiple times",
                    modifier_name
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::ModifiersIncompatible {
                first_modifier_name,
                second_modifier_name,
            } => Diagnostic::error()
                .with_message(format!(
                    "string modifiers {} and {} are incompatible",
                    first_modifier_name, second_modifier_name,
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::MulOverflow { left, right } => Diagnostic::error()
                .with_message(format!("multiplication {} * {} overflows", left, right))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::NomError(_) => Diagnostic::error()
                // TODO: improve nom error reporting.
                // At least, on tag and char errors, it would be great to indicate
                // which char and tag was expected.
                .with_message("syntax error")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToFloatError(err) => Diagnostic::error()
                .with_message(format!("error converting to float: {}", err))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToIntError(err) => Diagnostic::error()
                .with_message(format!("error converting to integer: {}", err))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToHexIntError(err) => Diagnostic::error()
                .with_message(format!(
                    "error converting hexadecimal notation to integer: {}",
                    err
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToOctIntError(err) => Diagnostic::error()
                .with_message(format!(
                    "error converting octal notation to integer: {}",
                    err
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StringDeclarationDuplicated { name } => Diagnostic::error()
                .with_message(format!("multiple strings named {} declared", name))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::XorRangeInvalidValue { value } => Diagnostic::error()
                .with_message(format!(
                    "xor range value {} invalid, must be in [0-255]",
                    value
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::XorRangeInvalid { from, to } => Diagnostic::error()
                .with_message(format!("xor range invalid: {} > {}", from, to))
                .with_labels(vec![Label::primary((), self.span.clone())]),
        }
    }

    fn from_nom_error_kind(position: usize, kind: NomErrorKind) -> Self {
        Self {
            span: Span {
                start: position,
                end: position + 1,
            },
            kind: ErrorKind::NomError(kind),
        }
    }
}

impl ParseError<Input<'_>> for Error {
    fn from_error_kind(input: Input, kind: NomErrorKind) -> Self {
        Self::from_nom_error_kind(input.get_position(), kind)
    }

    fn append(_: Input, _: NomErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    /// A base64 modifier alphabet has an invalid length.
    ///
    /// The length must be 64.
    Base64AlphabetInvalidLength { length: usize },

    /// Empty regex declaration, forbidden
    EmptyRegex,

    /// There are trailing data that could not be parsed.
    HasTrailingData,

    /// Jump of an empty size (i.e. `[0]`).
    JumpEmpty,

    /// Jump with a invalid range, ie `from` > `to`:
    JumpRangeInvalid { from: u32, to: u32 },

    /// Jump over a certain size used inside an alternation (`|`).
    JumpTooBigInAlternation {
        /// Maximum size of jumps (included).
        limit: u32,
    },

    /// Unbounded jump (`[-]`) used inside an alternation (`|`) in an hex string.
    JumpUnboundedInAlternation,

    /// Duplicated string modifiers
    ModifiersDuplicated {
        /// First modifier name
        modifier_name: String,
    },

    /// Incompatible string modifiers.
    ModifiersIncompatible {
        /// First modifier name
        first_modifier_name: String,
        /// Second modifier name
        second_modifier_name: String,
    },

    /// Overflow on a multiplication
    MulOverflow { left: i64, right: i64 },

    /// Generic error on nom parsing utilities
    NomError(NomErrorKind),

    /// Error converting a string to an float
    StrToFloatError(ParseFloatError),

    /// Error converting a string to an integer
    StrToIntError(ParseIntError),

    /// Error converting a string to an integer in base 16
    StrToHexIntError(ParseIntError),

    /// Error converting a string to an integer in base 16
    StrToOctIntError(ParseIntError),

    /// Multiple string declarations with the same name
    StringDeclarationDuplicated { name: String },

    /// A value used in a xor modifier range is outside the [0-255] range.
    XorRangeInvalidValue { value: i64 },

    /// Xor modifier with a invalid range, ie `from` > `to`:
    XorRangeInvalid { from: u8, to: u8 },
}
