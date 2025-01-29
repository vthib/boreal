//! Parsing error types.
use std::num::ParseIntError;
use std::ops::Range;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use nom::error::{ErrorKind as NomErrorKind, ParseError};

use super::types::Input;

/// Parsing error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Span of the error in the input.
    ///
    /// This is a range of offset, in chars, from the beginning
    /// of the input given to [`crate::parse`].
    span: Range<usize>,

    /// Kind of the error.
    kind: ErrorKind,
}

impl Error {
    #[must_use]
    pub(crate) fn new(span: Range<usize>, kind: ErrorKind) -> Self {
        Self { span, kind }
    }

    /// Convert to a [`Diagnostic`].
    ///
    /// This can be used to display the error in a user-friendly manner.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic<()> {
        match &self.kind {
            ErrorKind::Base64AlphabetInvalidLength { length } => Diagnostic::error()
                .with_message("base64 modifier alphabet must contain exactly 64 characters")
                .with_labels(vec![Label::primary((), self.span.clone())
                    .with_message(format!("this contains {length} characters"))]),

            ErrorKind::Base64AlphabetIncompatible => Diagnostic::error()
                .with_message("alphabets used for base64 and base64wide must be identical")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::CannotNegateMaskAll => Diagnostic::error()
                .with_message("negating an unknown byte is not allowed")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::ExprTooDeep => Diagnostic::error()
                .with_message("too many imbricated expressions")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::RegexClassRangeInvalid => Diagnostic::error()
                .with_message("invalid regex class range, start must be <= to end")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::RegexNonAsciiByte => Diagnostic::error()
                .with_message("regex should only contain ascii bytes")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::RegexRangeInvalid => Diagnostic::error()
                .with_message("invalid regex range, start must be <= to end")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::RegexTooDeep => Diagnostic::error()
                .with_message("too many imbricated groups in the regex")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::HexStringTooDeep => Diagnostic::error()
                .with_message("too many imbricated groups in the hex string")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpAtBound => Diagnostic::error()
                .with_message("a list of tokens cannot start or end with a jump")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpEmpty => Diagnostic::error()
                .with_message("jump cannot have a length of 0")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpRangeInvalid { from, to } => Diagnostic::error()
                .with_message(format!("invalid range for the jump: {from} > {to}"))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpTooBigInAlternation { limit } => Diagnostic::error()
                .with_message(format!(
                    "jumps over {limit} not allowed inside alternations (|)",
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::JumpUnboundedInAlternation => Diagnostic::error()
                .with_message("unbounded jumps not allowed inside alternations (|)")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::ModifiersDuplicated { modifier_name } => Diagnostic::error()
                .with_message(format!(
                    "string modifier {modifier_name} appears multiple times",
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::ModifiersIncompatible {
                first_modifier_name,
                second_modifier_name,
            } => Diagnostic::error()
                .with_message(format!(
                    "string modifiers {first_modifier_name} and {second_modifier_name} are incompatible",
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::MulOverflow { left, right } => Diagnostic::error()
                .with_message(format!("multiplication {left} * {right} overflows"))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::NomError(_) => Diagnostic::error()
                // TODO: improve nom error reporting.
                // At least, on tag and char errors, it would be great to indicate
                // which char and tag was expected.
                .with_message("syntax error")
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToIntError(err) => Diagnostic::error()
                .with_message(format!("error converting to integer: {err}"))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToHexIntError(err) => Diagnostic::error()
                .with_message(format!(
                    "error converting hexadecimal notation to integer: {err}"
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::StrToOctIntError(err) => Diagnostic::error()
                .with_message(format!(
                    "error converting octal notation to integer: {err}"
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::XorRangeInvalidValue { value } => Diagnostic::error()
                .with_message(format!(
                    "xor range value {value} invalid, must be in [0-255]"
                ))
                .with_labels(vec![Label::primary((), self.span.clone())]),

            ErrorKind::XorRangeInvalid { from, to } => Diagnostic::error()
                .with_message(format!("xor range invalid: {from} > {to}"))
                .with_labels(vec![Label::primary((), self.span.clone())]),
        }
    }

    fn from_nom_error_kind(position: usize, kind: NomErrorKind) -> Self {
        Self {
            span: Range {
                start: position,
                end: position + 1,
            },
            kind: ErrorKind::NomError(kind),
        }
    }
}

impl ParseError<Input<'_>> for Error {
    fn from_error_kind(input: Input, kind: NomErrorKind) -> Self {
        Self::from_nom_error_kind(input.get_position_offset(), kind)
    }

    fn append(_: Input, _: NomErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    /// A base64 modifier alphabet has an invalid length.
    ///
    /// The length must be 64.
    Base64AlphabetInvalidLength { length: usize },

    /// Alphabets used for base64 and base64wide for the same string are not identical.
    Base64AlphabetIncompatible,

    /// The '~??' syntax cannot be used in a hex string
    CannotNegateMaskAll,

    /// An expression contains too many imbricated expressions.
    ExprTooDeep,

    /// A hex string contains too many imbricated groups.
    HexStringTooDeep,

    /// A jump is not allowed at the beginning or end of hex tokens
    JumpAtBound,

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

    /// Range used in regex class is invalid, from > to.
    RegexClassRangeInvalid,

    /// Regex contains a non ascii byte, this is not allowed.
    RegexNonAsciiByte,

    /// Invalid range in a regex, from > to.
    RegexRangeInvalid,

    /// Regex has too much depth, meaning there are too many imbricated groups.
    RegexTooDeep,

    /// Error converting a string to an integer
    StrToIntError(ParseIntError),

    /// Error converting a string to an integer in base 16
    StrToHexIntError(ParseIntError),

    /// Error converting a string to an integer in base 16
    StrToOctIntError(ParseIntError),

    /// A value used in a xor modifier range is outside the [0-255] range.
    XorRangeInvalidValue { value: i64 },

    /// Xor modifier with a invalid range, ie `from` > `to`:
    XorRangeInvalid { from: u8, to: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_public_type;

    #[test]
    fn test_public_types() {
        test_public_type(Error::new(0..3, ErrorKind::JumpEmpty));
    }
}
