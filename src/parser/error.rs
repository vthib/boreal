use std::num::{ParseFloatError, ParseIntError};

use nom::error::{ErrorKind as NomErrorKind, FromExternalError, ParseError};

use super::types::Input;

#[derive(Debug)]
pub struct Error {
    errors: Vec<SingleError>,
}

impl Error {
    pub fn new(input: Input, kind: ErrorKind) -> Self {
        Self {
            errors: vec![SingleError {
                position: input.get_position(),
                kind,
            }],
        }
    }

    pub fn new_with_pos(position: usize, kind: ErrorKind) -> Self {
        Self {
            errors: vec![SingleError { position, kind }],
        }
    }
}

impl ParseError<Input<'_>> for Error {
    fn from_error_kind(input: Input, kind: NomErrorKind) -> Self {
        Self {
            errors: vec![SingleError::from_nom_error_kind(input.get_position(), kind)],
        }
    }

    fn append(input: Input, kind: NomErrorKind, mut other: Self) -> Self {
        other
            .errors
            .push(SingleError::from_nom_error_kind(input.get_position(), kind));
        other
    }
}

impl FromExternalError<Input<'_>, ErrorKind> for Error {
    fn from_external_error(input: Input, _: NomErrorKind, kind: ErrorKind) -> Self {
        Self {
            errors: vec![SingleError {
                position: input.get_position(),
                kind,
            }],
        }
    }
}

#[derive(Debug)]
struct SingleError {
    // position of the error in the original input
    position: usize,

    kind: ErrorKind,
}

impl SingleError {
    fn from_nom_error_kind(position: usize, kind: NomErrorKind) -> Self {
        Self {
            position,
            kind: ErrorKind::NomError(kind),
        }
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
        /// Type of the right operand
        right_type: String,
    },

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
