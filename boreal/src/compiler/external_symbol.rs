use super::{RuleCompiler, Type};

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
#[derive(Clone, Debug)]
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
