use std::any::{Any, TypeId};
use std::collections::HashMap;

use regex::bytes::Regex;

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
#[cfg(feature = "object")]
mod macho;
#[cfg(feature = "object")]
pub use macho::MachO;
#[cfg(feature = "object")]
mod pe;
#[cfg(feature = "object")]
pub use pe::Pe;

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
    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
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
    /// use boreal::module::{Module, StaticValue, Value, Type, ScanContext};
    ///
    /// struct Foo;
    ///
    /// impl Module for Foo {
    ///     fn get_name(&self) -> String {
    ///         "foo".to_owned()
    ///     }
    ///
    ///     fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
    ///         [("int", StaticValue::Integer(1))].into()
    ///     }
    ///
    ///     fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
    ///         [("array", Type::array(Type::Bytes))].into()
    ///     }
    ///
    ///     fn get_dynamic_values(&self, _ctx: &mut ScanContext) -> HashMap<&'static str, Value> {
    ///         [(
    ///             "array",
    ///             Value::Array(vec![Value::bytes("a"), Value::bytes("b")])
    ///         )].into()
    ///     }
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
    fn get_dynamic_values(&self, _ctx: &mut ScanContext) -> HashMap<&'static str, Value> {
        HashMap::new()
    }
}

impl std::fmt::Debug for Box<dyn Module> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.get_name())
            .finish()
    }
}

/// Context provided to module functions during scanning.
pub struct ScanContext<'a> {
    /// Input being scanned.
    pub mem: &'a [u8],

    /// Private data (per-scan) of each module.
    ///
    /// This can be used by a module to store data used in functions. The data must be set when
    /// [`Module::get_dynamic_values`] is called, and can be retrieved when functions are called.
    ///
    /// ```
    /// # use std::collections::HashMap;
    /// use boreal::module::{Module, StaticValue, Value, Type, ScanContext, ModuleData};
    ///
    /// struct Foo;
    ///
    /// struct FooData {
    ///     a: i64,
    /// }
    ///
    /// impl ModuleData for Foo {
    ///     type Data = FooData;
    /// }
    ///
    /// impl Module for Foo {
    ///     fn get_name(&self) -> String {
    ///         "foo".to_owned()
    ///     }
    ///
    ///     fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
    ///         [("fun", StaticValue::function(Self::fun, vec![vec![]], Type::Integer))].into()
    ///     }
    ///
    ///     fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
    ///         [("b", Type::Boolean)].into()
    ///     }
    ///
    ///     fn get_dynamic_values(&self, ctx: &mut ScanContext) -> HashMap<&'static str, Value> {
    ///         ctx.module_data.insert::<Self>(FooData {
    ///             a: 5,
    ///             });
    ///
    ///         [("b", true.into())].into()
    ///     }
    /// }
    ///
    /// impl Foo {
    ///     fn fun(ctx: &ScanContext, _args: Vec<Value>) -> Option<Value> {
    ///         let data = ctx.module_data.get::<Self>()?;
    ///
    ///         Some(data.a.into())
    ///     }
    /// }
    /// ```
    pub module_data: ModuleDataMap,
}

impl std::fmt::Debug for ScanContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanContext").finish()
    }
}

#[derive(Default)]
pub struct ModuleDataMap(HashMap<TypeId, Box<dyn Any>>);

pub trait ModuleData {
    type Data: Any + Send + Sync;
}

impl ModuleDataMap {
    pub fn insert<T: ModuleData + 'static>(&mut self, data: T::Data) {
        let _r = self.0.insert(TypeId::of::<T>(), Box::new(data));
    }

    #[must_use]
    pub fn get<T: ModuleData + 'static>(&self) -> Option<&T::Data> {
        self.0
            .get(&TypeId::of::<T>())
            .and_then(|v| v.downcast_ref())
    }
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
    /// A byte string.
    Bytes(Vec<u8>),
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
    Array(Vec<Value>),

    /// A dictionary.
    ///
    /// For example, if a module `foo` exports a dictionary value, then it can be accessed with the
    /// syntax `foo["key"]` in a rule.
    Dictionary(HashMap<String, Value>),

    /// A function.
    ///
    /// For example, if a module `foo` exports a function, then it can be accessed with the
    /// syntax `foo(arg1, arg2, ...)` in a rule.
    // TODO: remove the typings? there should be no need for it.
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
        /// # let ctx = ScanContext { mem: b"", module_data: Default::default() };
        /// let result = fun(&ctx, vec![
        ///     Value::bytes("a"),
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
        /// For example: `[ [Type::Boolean], [Type::Bytes, Type::Integer] ]` accepts both:
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
            Self::Bytes(arg0) => {
                let mut t = f.debug_tuple("Bytes");
                match std::str::from_utf8(arg0) {
                    Ok(v) => t.field(&v).finish(),
                    Err(_) => t.field(arg0).finish(),
                }
            }
            Self::Regex(arg0) => f.debug_tuple("Regex").field(arg0).finish(),
            Self::Boolean(arg0) => f.debug_tuple("Boolean").field(arg0).finish(),
            Self::Object(arg0) => f.debug_tuple("Object").field(arg0).finish(),
            Self::Array(arg0) => f.debug_tuple("Array").field(arg0).finish(),
            Self::Dictionary(arg0) => f.debug_tuple("Dictionary").field(arg0).finish(),
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

/// A static value provided by a module at compilation time.
///
/// This is similar to [`Value`], but without some compounds values that require evaluation
/// to resolve.
#[derive(Clone)]
pub enum StaticValue {
    /// An integer
    Integer(i64),
    /// A floating-point value.
    Float(f64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A regex.
    Regex(Regex),
    /// A boolean.
    Boolean(bool),
    /// An object, mapping to other values. See [`Value::Object`].
    Object(HashMap<&'static str, StaticValue>),

    /// A function, see [`Value::Function`].
    Function {
        fun: fn(&ScanContext, Vec<Value>) -> Option<Value>,
        arguments_types: Vec<Vec<Type>>,
        return_type: Type,
    },
}

// XXX: custom Debug impl needed because derive does not work with the fn fields.
impl std::fmt::Debug for StaticValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(arg0) => f.debug_tuple("Integer").field(arg0).finish(),
            Self::Float(arg0) => f.debug_tuple("Float").field(arg0).finish(),
            Self::Bytes(arg0) => f.debug_tuple("Bytes").field(arg0).finish(),
            Self::Regex(arg0) => f.debug_tuple("Regex").field(arg0).finish(),
            Self::Boolean(arg0) => f.debug_tuple("Boolean").field(arg0).finish(),
            Self::Object(arg0) => f.debug_tuple("Object").field(arg0).finish(),
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
    pub fn bytes<T: Into<Vec<u8>>>(v: T) -> Self {
        Self::Bytes(v.into())
    }

    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, Value); N]) -> Self {
        Self::Object(v.into())
    }

    pub fn function(
        fun: fn(&ScanContext, Vec<Value>) -> Option<Value>,
        arguments_types: Vec<Vec<Type>>,
        return_type: Type,
    ) -> Self {
        Self::Function {
            fun,
            arguments_types,
            return_type,
        }
    }
}

impl StaticValue {
    pub fn bytes<T: Into<Vec<u8>>>(v: T) -> Self {
        Self::Bytes(v.into())
    }

    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, StaticValue); N]) -> Self {
        Self::Object(v.into())
    }

    pub fn function(
        fun: fn(&ScanContext, Vec<Value>) -> Option<Value>,
        arguments_types: Vec<Vec<Type>>,
        return_type: Type,
    ) -> Self {
        Self::Function {
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
    Bytes,
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
try_from_value!(Vec<u8>, Bytes);
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
from_prim!(Vec<u8>, Bytes);
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
