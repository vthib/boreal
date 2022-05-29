use regex::bytes::Regex;
use std::collections::HashMap;

mod time;
pub use time::Time;

#[cfg(feature = "hash")]
mod hash;
#[cfg(feature = "hash")]
pub use hash::Hash;

#[cfg(feature = "object")]
mod elf;
#[cfg(feature = "object")]
pub use elf::Elf;

/// Module providing custom values and functions in rules.
///
/// A module can provide values in two ways:
///
/// - As static values, whose shape do not depend on the memory being scanned. This includes
///   constants such as `pe.MACHINE_AMD64`, but also functions such as `hash.md5`: the function
///   pointer is static, and do not need to be recomputed on every scan.
///
/// - As dynamic values, whose shape depend on the memory being scanned. This often includes
///   arrays such as `elf.sections`, or raw values such as `pe.machine`.
pub trait Module {
    /// Name of the module, used in `import` clauses.
    fn get_name(&self) -> String;

    /// Static values exported by the module.
    ///
    /// This function is called once, when the module is added to a scanner.
    fn get_static_values(&self) -> HashMap<&'static str, Value> {
        HashMap::new()
    }

    /// Type of the dynamic values exported by the module.
    ///
    /// Dynamic values are computed on every new scan. As these values are not known when compiling
    /// the rules, its type must be returned here to check the validity of rules using the module.
    ///
    /// For example, lets take this module:
    ///
    /// ```
    /// # use std::collections::HashMap;
    /// use boreal::module::{Module, Value, Type, ScanContext};
    ///
    /// struct Foo;
    ///
    /// impl Module for Foo {
    ///     fn get_name(&self) -> String {
    ///         "foo".to_owned()
    ///     }
    ///
    ///     fn get_static_values(&self) -> HashMap<&'static str, Value> {
    ///         [("int", Value::Integer(1))].into()
    ///     }
    ///
    ///     fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
    ///         [("array", Type::array(Type::String))].into()
    ///     }
    ///
    ///     fn get_dynamic_values(&self) -> HashMap<&'static str, Value> {
    ///         [("array", Value::array(bar_array, Type::String))].into()
    ///     }
    /// }
    ///
    /// fn bar_array(_: &ScanContext) -> Option<Vec<Value>> {
    ///     Some(vec![Value::string("a"), Value::string("b")])
    /// }
    /// ```
    ///
    /// Then:
    ///
    /// * `foo.a > 0` would fail to compile, as the module does not expose the key `a`.
    /// * `foo.int == !a` would compile directly to `1 == !a`, as we already know the value of this
    ///    key when compiling the rule.
    /// * `foo.array[2] matches /regex/` would compile properly, but delay evaluation of the array
    ///   on every scan.
    /// * `foo.array[2] + 1` would fail to compile, as the array is indicated as returning a
    ///   string, which cannot be added to an integer.
    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        HashMap::new()
    }

    /// Values computed dynamically.
    ///
    /// This is called on every scan.
    fn get_dynamic_values(&self) -> HashMap<&'static str, Value> {
        HashMap::new()
    }
}

/// Context provided to module functions during scanning.
#[derive(Debug)]
pub struct ScanContext<'a> {
    /// Input being scanned.
    pub mem: &'a [u8],
}

/// A value bound to an identifier.
///
/// This object represents an immediately resolvable value for an identifier.
#[derive(Clone)]
pub enum Value {
    /// An integer
    Integer(i64),
    /// A floating-point value.
    Float(f64),
    /// A string.
    String(String),
    /// A regex.
    Regex(Regex),
    /// A boolean.
    Boolean(bool),
    /// An object, mapping to other values.
    ///
    /// For example, if a module `foo` exports an object value with the key `bar`, then it can
    /// be accessed with the syntax `foo.bar` in a rule.
    Object(HashMap<&'static str, Value>),

    /// An array.
    ///
    /// For example, if a module `foo` exports an array value, then it can be accessed with the
    /// syntax `foo[x]` in a rule.
    Array {
        /// Function called during scanning.
        ///
        /// The only argument is the accessed index in the array.
        ///
        /// The function can return None if the array does not make sense in the current context.
        /// For example, `pe.sections[0]` does not make sense if the scanned object is not a PE.
        on_scan: fn(&ScanContext) -> Option<Vec<Value>>,

        /// Type of all the elements in the array.
        ///
        /// This is not a [`Value`] as we cannot know the real values of this before evaluating
        /// a rule during scanning and accessing the array. Hence, this can only be a [`Type`],
        /// which still provides the description of the type stored in the array, which can
        /// be used to properly type-check use of this array in rules.
        value_type: Type,
    },

    /// A dictionary.
    ///
    /// For example, if a module `foo` exports a dictionary value, then it can be accessed with the
    /// syntax `foo["key"]` in a rule.
    Dictionary {
        /// Function called during scanning.
        ///
        /// The function can return None if the array does not make sense in the current context.
        /// For example, `pe.sections[0]` does not make sense if the scanned object is not a PE.
        on_scan: fn(&ScanContext) -> Option<HashMap<String, Value>>,

        /// Type of all the elements in the dirctionary.
        ///
        /// This is not a [`Value`] as we cannot know the real values of this before evaluating
        /// a rule during scanning and accessing the array. Hence, this can only be a [`Type`],
        /// which still provides the description of the type stored in the array, which can
        /// be used to properly type-check use of this array in rules.
        value_type: Type,
    },

    /// A function.
    ///
    /// For example, if a module `foo` exports a function, then it can be accessed with the
    /// syntax `foo(arg1, arg2, ...)` in a rule.
    ///
    /// Do note that if the function is documented as taking no arguments, then both `foo()` and
    /// simply `foo` are valid syntaxes to call the function. This is useful to have lazy evaluated
    /// values, such as `pe.nb_sections`, which can be used as is in a rule, but will call
    /// a function declared by the `pe` module, so that its value can depend on the current scan.
    Function {
        /// The function to call during scanning.
        ///
        /// The provided argument is a vec of the arguments evaluated during the scan. For example,
        ///
        /// `fun("a", 1 + 2, #foo)` would call the function `fun` with:
        ///
        /// ```
        /// # use boreal::module::{ScanContext, Value};
        /// # let x = 3;
        /// # fn fun(_: &ScanContext, _: Vec<Value>) -> Option<Value> { None }
        /// # let ctx = ScanContext { mem: b"" };
        /// let result = fun(&ctx, vec![
        ///     Value::string("a"),
        ///     Value::Integer(3),
        ///     Value::Integer(x), // Number of matches of string $foo
        /// ]);
        /// ```
        fun: fn(&ScanContext, Vec<Value>) -> Option<Value>,

        /// List of types of arguments.
        ///
        /// Each element of the list is a valid list of types that are accepted as arguments for
        /// the function. This is used when compiling a rule, to check the typings are correct.
        ///
        /// For example: `[ [Type::Boolean], [Type::String, Type::Integer] ]` accepts both:
        /// - `fun(<boolean>)``
        /// - `fun(<string>, <integer>)`
        ///
        /// Anything else will be rejected when compiling the rule.
        ///
        /// Please note that only primitive values can actually be received: integer, floats,
        /// strings, regexes or booleans.
        arguments_types: Vec<Vec<Type>>,

        /// Type of the value returned by the function.
        return_type: Type,
    },
}

// XXX: custom Debug impl needed because derive does not work with the fn fields.
impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(arg0) => f.debug_tuple("Integer").field(arg0).finish(),
            Self::Float(arg0) => f.debug_tuple("Float").field(arg0).finish(),
            Self::String(arg0) => f.debug_tuple("String").field(arg0).finish(),
            Self::Regex(arg0) => f.debug_tuple("Regex").field(arg0).finish(),
            Self::Boolean(arg0) => f.debug_tuple("Boolean").field(arg0).finish(),
            Self::Object(arg0) => f.debug_tuple("Object").field(arg0).finish(),
            Self::Array {
                on_scan,
                value_type,
            } => f
                .debug_struct("Array")
                .field("on_scan", &(*on_scan as usize))
                .field("value_type", value_type)
                .finish(),
            Self::Dictionary {
                on_scan,
                value_type,
            } => f
                .debug_struct("Dictionary")
                .field("on_scan", &(*on_scan as usize))
                .field("value_type", value_type)
                .finish(),
            Self::Function {
                fun,
                arguments_types,
                return_type,
            } => f
                .debug_struct("Function")
                .field("fun", &(*fun as usize))
                .field("arguments_types", arguments_types)
                .field("return_type", return_type)
                .finish(),
        }
    }
}

impl Value {
    pub fn string<T: Into<String>>(v: T) -> Self {
        Value::String(v.into())
    }

    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, Value); N]) -> Self {
        Value::Object(v.into())
    }

    pub fn array(fun: fn(&ScanContext) -> Option<Vec<Value>>, ty: Type) -> Self {
        Value::Array {
            on_scan: fun,
            value_type: ty,
        }
    }

    pub fn dict(fun: fn(&ScanContext) -> Option<HashMap<String, Value>>, ty: Type) -> Self {
        Value::Dictionary {
            on_scan: fun,
            value_type: ty,
        }
    }

    pub fn function(
        fun: fn(&ScanContext, Vec<Value>) -> Option<Value>,
        arguments_types: Vec<Vec<Type>>,
        return_type: Type,
    ) -> Self {
        Value::Function {
            fun,
            arguments_types,
            return_type,
        }
    }
}

/// Type of a value returned during scanning.
#[derive(Clone, Debug)]
pub enum Type {
    Integer,
    Float,
    String,
    Regex,
    Boolean,
    Object(HashMap<&'static str, Type>),
    Array {
        value_type: Box<Type>,
    },
    Dictionary {
        value_type: Box<Type>,
    },
    Function {
        arguments_types: Vec<Vec<Type>>,
        return_type: Box<Type>,
    },
}

impl Type {
    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, Type); N]) -> Self {
        Self::Object(v.into())
    }

    #[must_use]
    pub fn array(value_type: Type) -> Self {
        Self::Array {
            value_type: Box::new(value_type),
        }
    }

    #[must_use]
    pub fn dict(value_type: Type) -> Self {
        Self::Dictionary {
            value_type: Box::new(value_type),
        }
    }

    #[must_use]
    pub fn function(arguments_types: Vec<Vec<Type>>, return_type: Type) -> Self {
        Self::Function {
            arguments_types,
            return_type: Box::new(return_type),
        }
    }
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

try_from_value!(i64, Integer);
try_from_value!(f64, Float);
try_from_value!(String, String);
try_from_value!(Regex, Regex);
try_from_value!(bool, Boolean);

macro_rules! from_prim {
    ($ty:ty, $name:ident) => {
        impl From<$ty> for Value {
            fn from(v: $ty) -> Value {
                Value::$name(v.into())
            }
        }
    };
}

from_prim!(i64, Integer);
from_prim!(u32, Integer);
from_prim!(i32, Integer);
from_prim!(u16, Integer);
from_prim!(i16, Integer);
from_prim!(u8, Integer);
from_prim!(i8, Integer);
from_prim!(f64, Float);
from_prim!(String, String);
from_prim!(Regex, Regex);
from_prim!(bool, Boolean);

macro_rules! try_from_value_integer {
    ($ty:ty) => {
        impl TryFrom<$ty> for Value {
            type Error = <i64 as TryFrom<$ty>>::Error;

            fn try_from(v: $ty) -> Result<Value, Self::Error> {
                v.try_into().map(Value::Integer)
            }
        }
    };
}

try_from_value_integer!(u64);
try_from_value_integer!(usize);
