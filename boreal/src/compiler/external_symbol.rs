use super::expression::Type;
use super::rule::RuleCompiler;

#[derive(Clone, Debug)]
pub(crate) struct ExternalSymbol {
    /// Name of the symbol.
    ///
    /// Must be unique across all others external symbols, but can have the same name as other
    /// types of symbols: rule name, modules, etc. See order of symbol resolution.
    pub name: String,

    /// Default value of the symbol.
    ///
    /// If no value is specified for this symbol during a scan, this value will be used instead.
    /// It is also used to type-check the expression during compilation.
    pub default_value: ExternalValue,
}

/// A value used for an external symbol.
#[derive(Clone, Debug, PartialEq)]
pub enum ExternalValue {
    /// An integer
    Integer(i64),
    /// A floating-point value.
    Float(f64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A boolean.
    Boolean(bool),
}

impl ExternalValue {
    pub(super) fn get_type(&self) -> Type {
        match self {
            Self::Integer(_) => Type::Integer,
            Self::Float(_) => Type::Float,
            Self::Bytes(_) => Type::Bytes,
            Self::Boolean(_) => Type::Boolean,
        }
    }
}

pub(super) fn get_external_symbol<'a>(
    compiler: &'a RuleCompiler,
    name: &str,
) -> Option<(usize, &'a ExternalValue)> {
    for (index, sym) in compiler.external_symbols.iter().enumerate() {
        if sym.name == name {
            return Some((index, &sym.default_value));
        }
    }
    None
}

impl From<i64> for ExternalValue {
    fn from(v: i64) -> Self {
        Self::Integer(v)
    }
}

impl From<f64> for ExternalValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl From<bool> for ExternalValue {
    fn from(v: bool) -> Self {
        Self::Boolean(v)
    }
}

macro_rules! impl_into_bytes {
    ($ty:ty) => {
        impl From<$ty> for ExternalValue {
            fn from(v: $ty) -> Self {
                Self::Bytes(v.into())
            }
        }
    };
}

impl_into_bytes!(Vec<u8>);
impl_into_bytes!(&[u8]);
impl_into_bytes!(String);
impl_into_bytes!(&str);

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use super::ExternalValue;

    impl Serialize for ExternalValue {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Self::Integer(v) => {
                    0_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
                Self::Float(v) => {
                    1_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
                Self::Bytes(v) => {
                    2_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
                Self::Boolean(v) => {
                    3_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
            }
            Ok(())
        }
    }

    impl Deserialize for ExternalValue {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let discriminant = u8::deserialize_reader(reader)?;
            match discriminant {
                0 => Ok(ExternalValue::Integer(i64::deserialize_reader(reader)?)),
                1 => Ok(ExternalValue::Float(f64::deserialize_reader(reader)?)),
                2 => Ok(ExternalValue::Bytes(<Vec<u8>>::deserialize_reader(reader)?)),
                3 => Ok(ExternalValue::Boolean(bool::deserialize_reader(reader)?)),
                v => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid discriminant when deserializing an external value: {v}"),
                )),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::wire::tests::{test_invalid_deserialization, test_round_trip};

        #[test]
        fn test_wire_external_value() {
            test_round_trip(&ExternalValue::Integer(-239), &[0, 2]);
            test_round_trip(&ExternalValue::Float(-5.2), &[0, 2]);
            test_round_trip(&ExternalValue::Bytes(b"azea".to_vec()), &[0, 2, 6]);
            test_round_trip(&ExternalValue::Boolean(true), &[0, 1]);

            test_invalid_deserialization::<ExternalValue>(b"\x05");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits;

    #[test]
    fn test_types_traits() {
        test_type_traits(ExternalSymbol {
            name: "a".to_owned(),
            default_value: ExternalValue::Integer(0),
        });
        test_type_traits(ExternalValue::Integer(0));
    }
}
