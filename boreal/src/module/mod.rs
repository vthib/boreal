use regex::Regex;
use std::collections::HashMap;

pub mod tests;

/// A module allows providing custom values and functions in rules.
///
/// The trait in itself only requires static values and methods, which are used
/// only the module itself is added to
pub trait Module {
    /// Name of the module, used in `import` clauses.
    fn get_name(&self) -> String;

    /// Symbol exported by the module.
    ///
    /// This is the symbol bound to the module name when the module
    /// is imported in a rule.
    ///
    /// ```ignore
    /// import "foo"
    ///
    /// rule a {
    ///     condition:
    ///         a >= 0 # a resolves to this symbol
    /// ```
    ///
    /// This function is called once, when the module is added to a scanner.
    fn get_symbol(&self) -> Symbol;
}

#[derive(Debug)]
pub enum Symbol {
    Value(Value),
    Array(Vec<Symbol>),
    Dictionary(HashMap<&'static str, Symbol>),

    Function {
        arguments_description: String,
        result_type: char,
        fun: fn(Vec<Value>) -> Option<Value>,
    },

    // TODO: provide the structural typing for the result to typecheck on rule compilation.
    Lazy(fn() -> Option<Symbol>),
}

impl<V: Into<Value>> From<V> for Symbol {
    fn from(v: V) -> Symbol {
        Symbol::Value(v.into())
    }
}

impl Symbol {
    fn integer(v: i64) -> Self {
        Symbol::Value(Value::Number(v))
    }

    fn float(v: f64) -> Self {
        Symbol::Value(Value::Float(v))
    }

    fn string<T: Into<String>>(v: T) -> Self {
        Symbol::Value(Value::String(v.into()))
    }

    fn dictionary<const N: usize>(v: [(&'static str, Symbol); N]) -> Self {
        Symbol::Dictionary(v.into())
    }

    fn function(
        fun: fn(Vec<Value>) -> Option<Value>,
        arguments_description: &str,
        result_type: char,
    ) -> Self {
        Symbol::Function {
            arguments_description: arguments_description.to_owned(),
            result_type,
            fun,
        }
    }
}

#[derive(Debug)]
pub enum Value {
    Number(i64),
    Float(f64),
    String(String),
    Regex(Regex),
    Boolean(bool),
}

macro_rules! try_from_value {
    ($ty:ty, $name:ident) => {
        impl TryFrom<Value> for $ty {
            type Error = ();

            fn try_from(value: Value) -> Result<$ty, ()> {
                match value {
                    Value::$name(v) => Ok(v),
                    _ => Err(()),
                }
            }
        }
    };
}

try_from_value!(i64, Number);
try_from_value!(f64, Float);
try_from_value!(String, String);
try_from_value!(Regex, Regex);
try_from_value!(bool, Boolean);
