use super::{RuleCompiler, Type};

#[derive(Clone, Debug)]
pub struct ExternalSymbol {
    /// Name of the symbol.
    ///
    /// Must be unique across all others external symbols, but can have the same name as other
    /// types of symbols: rule name, modules, etc. See order of symbol resolution.
    name: String,

    /// Default value of the symbol.
    ///
    /// If no value is specified for this symbol during a scan, this value will be used instead.
    /// It is also used to type-check the expression during compilation.
    default_value: ExternalValue,
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
