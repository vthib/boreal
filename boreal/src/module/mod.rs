//! Modules that can be imported and used in rules.
//!
//! To implement a new module, the [`Module`] trait must be implemented. This module can then
//! be added to the compiler by calling [`crate::compiler::CompilerBuilder::add_module`],
//! making it available to all future rules added to this compiler.
//!
//! ```
//! use boreal::module::{Module, StaticValue};
//! use boreal::compiler::CompilerBuilder;
//! use std::collections::HashMap;
//!
//! struct Pi;
//!
//! impl Module for Pi {
//!     fn get_name(&self) -> &'static str {
//!         "pi"
//!     }
//!
//!     fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
//!         [
//!             ("PI", StaticValue::Float(std::f64::consts::PI))
//!         ].into()
//!     }
//! }
//!
//! const RULE: &str = r#"
//!     import "pi"
//!
//!     rule a {
//!         condition: pi.PI != 0.0
//!     }
//! "#;
//!
//! fn main() {
//!     let mut compiler = CompilerBuilder::new().add_module(Pi).build();
//!     assert!(compiler.add_rules_str(RULE).is_ok());
//! }
//! ```
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use crate::memory::{Memory, Region};
use crate::regex::Regex;

mod console;
pub use console::{Console, ConsoleData, LogCallback};

mod time;
pub use time::Time;

#[allow(clippy::cast_precision_loss)]
mod math;
pub use math::Math;

mod string;
pub use string::String_;

#[cfg(feature = "hash")]
mod hash;
#[cfg(feature = "hash")]
pub use hash::Hash;

#[cfg(feature = "object")]
mod dotnet;
#[cfg(feature = "object")]
pub use dotnet::Dotnet;

#[cfg(feature = "object")]
// pub to allow use of the entry_point for the entrypoint expression.
pub(crate) mod elf;
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

#[cfg(feature = "object")]
mod dex;
#[cfg(feature = "object")]
pub use dex::Dex;

#[cfg(feature = "magic")]
mod magic;
#[cfg(feature = "magic")]
pub use self::magic::Magic;

#[cfg(feature = "cuckoo")]
mod cuckoo;
#[cfg(feature = "cuckoo")]
pub use self::cuckoo::{Cuckoo, CuckooData};

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
pub trait Module: Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Name of the module, used in `import` clauses.
    fn get_name(&self) -> &'static str;

    /// Static values exported by the module.
    ///
    /// This function is called once, when the module is added to a scanner.
    fn get_static_values(&self) -> HashMap<&'static str, StaticValue>;

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
    ///     fn get_name(&self) -> &'static str {
    ///         "foo"
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
    ///     fn get_dynamic_values(&self, _ctx: &mut ScanContext, out: &mut HashMap<&'static str, Value>) {
    ///         out.extend([(
    ///             "array",
    ///             Value::Array(vec![Value::bytes("a"), Value::bytes("b")])
    ///         )]);
    ///     }
    /// }
    /// ```
    ///
    /// Then:
    ///
    /// * `foo.a > 0` would fail to compile, as the module does not expose the key `a`.
    /// * `foo.int == !a` would compile directly to `1 == !a`, as we already know the value of this
    ///   key when compiling the rule.
    /// * `foo.array[2] matches /regex/` would compile properly, but delay evaluation of the array
    ///   on every scan.
    /// * `foo.array[2] + 1` would fail to compile, as the array is indicated as returning a
    ///   string, which cannot be added to an integer.
    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        HashMap::new()
    }

    /// Setup data when a new scan is started.
    ///
    /// This method is called when a new scan is started, before calling
    /// [`Module::get_dynamic_values`]. It should be used to save a new instance
    /// of the module data for the scan. See [`ModuleData`].
    ///
    /// It is better to add the module data in this method rather than in
    /// `Module::get_dynamic_values` for two reasons:
    /// - The [`Module::get_dynamic_values`] method can be called multiple times
    ///   during a single scan, for example when scanning the memory of a process.
    /// - Some module use data without having any dynamic values
    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        let _ = data_map;
    }

    /// Values computed dynamically.
    ///
    /// This is called on every scan, but can be called multiple times.
    /// When scanning a file or a byte slice, this is only called once per scan.
    /// However, when scanning the memory of a process, this is called once per
    /// every region.
    fn get_dynamic_values(
        &self,
        _ctx: &mut ScanContext,
        _values: &mut HashMap<&'static str, Value>,
    ) {
    }
}

impl std::fmt::Debug for Box<dyn Module> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.get_name())
            .finish()
    }
}

/// Context provided to module methods during scanning.
pub struct ScanContext<'a, 'b, 'c> {
    /// Memory region being scanned.
    pub region: &'a Region<'b>,

    /// Private data (per-scan) of each module.
    ///
    /// See [`ModuleData`] for an example on how this can be used.
    pub module_data: &'a mut ModuleDataMap<'c>,

    /// True if the region should be considered part of a process memory.
    ///
    /// See [`crate::scanner::ScanParams::process_memory`] for more details.
    pub process_memory: bool,
}

impl std::fmt::Debug for ScanContext<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanContext").finish()
    }
}

/// Context provided to module functions during evaluation.
pub struct EvalContext<'a, 'b, 'c> {
    /// Input being scanned.
    pub mem: &'b mut Memory<'a>,

    /// Private data (per-scan) of each module.
    ///
    /// See [`ModuleData`] for an example on how this can be used.
    pub module_data: &'b ModuleDataMap<'c>,

    /// True if the scan is done on a process memory.
    ///
    /// See [`crate::scanner::ScanParams::process_memory`] for more details.
    pub process_memory: bool,
}

impl std::fmt::Debug for EvalContext<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalContext").finish()
    }
}

#[doc(hidden)]
#[derive(Default, Clone)]
pub struct ModuleUserData(
    pub HashMap<TypeId, Arc<dyn Any + Send + Sync + UnwindSafe + RefUnwindSafe>>,
);

impl std::fmt::Debug for ModuleUserData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ModuleUserData").finish()
    }
}

/// Object holding the data of each module. See [`ModuleData`].
pub struct ModuleDataMap<'scanner> {
    private_data: HashMap<TypeId, Box<dyn Any + Send + Sync + UnwindSafe + RefUnwindSafe>>,
    user_data: &'scanner ModuleUserData,
}

impl std::fmt::Debug for ModuleDataMap<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ModuleDataMap").finish()
    }
}

/// Data used by a module.
///
/// There are two types of data that can be associated with a module:
///
/// - private data, that a module can use to store values with exposed functions.
/// - user data, that a user can provide to a module for use in rules.
///
/// # Private Data
///
/// Functions exposed by a module may need to use values that are computed when
/// [`Module::get_dynamic_values`] is called. In that case, this trait can be implemented on a
/// private struct, and:
/// - an instance of this type can be saved during the [`Module::get_dynamic_values`] call, by
///   calling [`ModuleDataMap::insert::<Self>`].
/// - this instance can be retrieved in any function call by calling
///   [`ModuleDataMap::get::<Self>`].
///
/// ```
/// use std::collections::HashMap;
/// use boreal::module::{
///     EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Value, Type, ScanContext
/// };
///
/// struct Foo;
///
/// struct FooData {
///     value: u32,
/// }
///
/// impl ModuleData for Foo {
///     type PrivateData = FooData;
///     type UserData = ();
/// }
///
/// impl Module for Foo {
///     fn get_name(&self) -> &'static str {
///         "foo"
///     }
///
///     fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
///         [(
///             "get_data_value",
///             StaticValue::function(Self::get_data_value, vec![], Type::Integer)
///         )].into()
///     }
///
///     fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
///         data_map.insert::<Self>(FooData { value: 5 });
///     }
/// }
///
/// impl Foo {
///     fn get_data_value(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
///         let data = ctx.module_data.get::<Self>()?;
///         Some(data.value.into())
///     }
/// }
/// ```
///
/// # User Data
///
/// A user can also provide data that the module can then use during a scan. The typical
/// example is the cuckoo module, where the user can provide a cuckoo JSON report to the
/// module, and then use the module functions to access this report in rules.
///
/// ```
/// use std::collections::HashMap;
/// use boreal::module::{EvalContext, Module, ModuleData, StaticValue, Value, Type};
/// use boreal::compiler::CompilerBuilder;
///
/// struct Bar;
///
/// struct BarUserData {
///     value: u32,
/// }
///
/// impl ModuleData for Bar {
///     type PrivateData = ();
///     type UserData = BarUserData;
/// }
///
/// impl Module for Bar {
///     fn get_name(&self) -> &'static str {
///         "bar"
///     }
///
///     fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
///         [(
///             "get_data_value",
///             StaticValue::function(Self::get_data_value, vec![], Type::Integer)
///         )].into()
///     }
/// }
///
/// impl Bar {
///     fn get_data_value(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
///         let data = ctx.module_data.get_user_data::<Self>()?;
///         Some(data.value.into())
///     }
/// }
///
/// let mut compiler = CompilerBuilder::new().add_module(Bar).build();
/// compiler.add_rules_str(r#"
/// import "bar"
///
/// rule a {
///     condition: bar.get_data_value() == 3
/// }"#).unwrap();
///
/// let mut scanner = compiler.finalize();
/// scanner.set_module_data::<Bar>(BarUserData { value: 3 });
///
/// let result = scanner.scan_mem(b"").unwrap();
/// assert_eq!(result.rules.len(), 1);
/// ```
pub trait ModuleData: Module {
    /// Private Data to associate with the module.
    ///
    /// This is the data that the module can store and retrieve during a scan.
    type PrivateData: Any + Send + Sync + UnwindSafe + RefUnwindSafe;

    /// Data that the user can provide to the module.
    ///
    /// This data is provided by the user with calls to
    /// [`Scanner::set_module_data`](crate::scanner::Scanner::set_module_data).
    type UserData: Any + Send + Sync + UnwindSafe + RefUnwindSafe;
}

impl<'scanner> ModuleDataMap<'scanner> {
    #[doc(hidden)]
    #[must_use]
    pub fn new(user_data: &'scanner ModuleUserData) -> Self {
        Self {
            private_data: HashMap::new(),
            user_data,
        }
    }

    /// Insert the private data of a module in the map.
    pub fn insert<T: Module + ModuleData + 'static>(&mut self, data: T::PrivateData) {
        let _r = self.private_data.insert(TypeId::of::<T>(), Box::new(data));
    }

    /// Retrieve the private data of a module.
    #[must_use]
    pub fn get<T: Module + ModuleData + 'static>(&self) -> Option<&T::PrivateData> {
        self.private_data.get(&TypeId::of::<T>()).and_then(|v| {
            // For some reason, having "dyn Any + Send + Sync + UnwindSafe + RefUnwindSafe"
            // causes the rust compiler to fail to resolve `v.downcast_ref()`, so we need to
            // explicit where this method comes from.
            <dyn Any>::downcast_ref(&**v)
        })
    }

    /// Retrieve a mutable borrow on the private data of a module.
    #[must_use]
    pub fn get_mut<T: Module + ModuleData + 'static>(&mut self) -> Option<&mut T::PrivateData> {
        self.private_data.get_mut(&TypeId::of::<T>()).and_then(|v| {
            // For some reason, having "dyn Any + Send + Sync + UnwindSafe + RefUnwindSafe"
            // causes the rust compiler to fail to resolve `v.downcast_mut()`, so we need to
            // explicit where this method comes from.
            <dyn Any>::downcast_mut(&mut **v)
        })
    }

    /// Retrieve the user data of a module.
    #[must_use]
    pub fn get_user_data<T: Module + ModuleData + 'static>(&self) -> Option<&T::UserData> {
        self.user_data.0.get(&TypeId::of::<T>()).and_then(|v| {
            // For some reason, having "dyn Any + Send + Sync + UnwindSafe + RefUnwindSafe"
            // causes the rust compiler to fail to resolve `v.downcast_ref()`, so we need to
            // explicit where this method comes from.
            <dyn Any>::downcast_ref(&**v)
        })
    }
}

pub(crate) fn add_default_modules<F: FnMut(Box<dyn Module>)>(mut cb: F) {
    cb(Box::new(Time));
    cb(Box::new(Math));
    cb(Box::new(String_));

    #[cfg(feature = "hash")]
    cb(Box::new(Hash));

    #[cfg(feature = "object")]
    cb(Box::new(Pe));
    #[cfg(feature = "object")]
    cb(Box::new(Elf));
    #[cfg(feature = "object")]
    cb(Box::new(MachO));
    #[cfg(feature = "object")]
    cb(Box::new(Dotnet));
    #[cfg(feature = "object")]
    cb(Box::new(Dex));

    #[cfg(feature = "magic")]
    cb(Box::new(Magic));

    #[cfg(feature = "cuckoo")]
    cb(Box::new(Cuckoo));
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

    /// A dictionary, indexed by bytes.
    ///
    /// For example, if a module `foo` exports a dictionary value, then it can be accessed with the
    /// syntax `foo["key"]` in a rule.
    Dictionary(HashMap<Vec<u8>, Value>),

    /// A function.
    ///
    /// For example, if a module `foo` exports a function, then it can be accessed with the
    /// syntax `foo(arg1, arg2, ...)` in a rule.
    Function(
        /// The function to call during scanning.
        ///
        /// The provided argument is a vec of the arguments evaluated during the scan. For example,
        ///
        /// `fun("a", 1 + 2, #foo)` would call the function `fun` with:
        ///
        /// ```
        /// # use std::collections::HashMap;
        /// # use boreal::memory::Memory;
        /// # use boreal::module::{EvalContext, Value, ModuleDataMap, ModuleUserData};
        /// # let x = 3;
        /// # fn fun(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> { None }
        /// # let user_data = ModuleUserData::default();
        /// # let mut ctx = EvalContext {
        /// #     mem: &mut Memory::Direct(b""),
        /// #     module_data: &ModuleDataMap::new(&user_data),
        /// #     process_memory: false,
        /// # };
        /// let result = fun(&mut ctx, vec![
        ///     Value::bytes("a"),
        ///     Value::Integer(3),
        ///     Value::Integer(x), // Number of matches of string $foo
        /// ]);
        /// ```
        #[allow(clippy::type_complexity)]
        Arc<dyn Fn(&mut EvalContext, Vec<Value>) -> Option<Value> + Send + Sync>,
    ),

    /// An undefined value.
    ///
    /// This is useful when filling up structure or dictionaries where some keys have no values for
    /// some given scanned bytes. Using the undefined value works as if the key was not filled.
    Undefined,
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
            Self::Function(_) => f.debug_struct("Function").finish(),
            Self::Undefined => write!(f, "Undefined"),
        }
    }
}

pub(crate) type StaticFunction = fn(&mut EvalContext, Vec<Value>) -> Option<Value>;

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
    /// A boolean.
    Boolean(bool),
    /// An object, mapping to other values. See [`Value::Object`].
    Object(HashMap<&'static str, StaticValue>),

    /// A function, see [`Value::Function`].
    Function {
        /// The function to call.
        fun: StaticFunction,

        /// Types of arguments for the function.
        ///
        /// See [`Type::Function::arguments_types`] for more details.
        arguments_types: Vec<Vec<Type>>,

        /// Type of the function's returned value.
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
    /// Build a [`Self::Bytes`] value.
    ///
    /// ```
    /// use boreal::module::Value;
    ///
    /// let value = Value::bytes("value");
    /// ```
    pub fn bytes<T: Into<Vec<u8>>>(v: T) -> Self {
        Self::Bytes(v.into())
    }

    /// Build a [`Self::Object`] value.
    ///
    /// ```
    /// use boreal::module::Value;
    ///
    /// let value = Value::object([("a", 1.into()), ("b", Value::bytes("b"))]);
    /// ```
    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, Value); N]) -> Self {
        Self::Object(v.into())
    }

    /// Build a [`Self::Function`] value.
    ///
    /// A closure can be provided that captures values that have been generated locally. This
    /// allows declaring functions which are context dependant, such as a function in an array of
    /// object that depends on the index in the array.
    /// ```
    /// use boreal::module::Value;
    ///
    /// let value = Value::function(|_ctx, args| args.into_iter().next());
    /// ```
    pub fn function<F>(f: F) -> Self
    where
        F: Fn(&mut EvalContext, Vec<Value>) -> Option<Value> + Send + Sync + 'static,
    {
        Self::Function(Arc::new(f))
    }
}

impl StaticValue {
    /// Build a [`Self::Bytes`] static value.
    ///
    /// ```
    /// use boreal::module::StaticValue;
    ///
    /// let value = StaticValue::bytes("value");
    /// ```
    pub fn bytes<T: Into<Vec<u8>>>(v: T) -> Self {
        Self::Bytes(v.into())
    }

    /// Build a [`Self::Object`] static value.
    ///
    /// ```
    /// use boreal::module::StaticValue;
    ///
    /// let value = StaticValue::object([
    ///     ("a", StaticValue::Integer(1)),
    ///     ("b", StaticValue::bytes("b"))
    /// ]);
    /// ```
    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, StaticValue); N]) -> Self {
        Self::Object(v.into())
    }

    /// Build a [`Self::Function`] static value.
    ///
    /// ```
    /// use boreal::module::{EvalContext, StaticValue, Type, Value};
    ///
    /// fn change_case(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
    ///     let mut args = args.into_iter();
    ///     let s: Vec<u8> = args.next()?.try_into().ok()?;
    ///     let to_upper: bool = args.next()?.try_into().ok()?;
    ///
    ///     if to_upper {
    ///         Some(s.to_ascii_uppercase().into())
    ///     } else {
    ///         Some(s.to_ascii_lowercase().into())
    ///     }
    /// }
    ///
    /// let value = StaticValue::function(
    ///     change_case,
    ///     vec![vec![Type::Bytes, Type::Boolean]],
    ///     Type::Bytes
    /// );
    /// ```
    pub fn function(
        fun: fn(&mut EvalContext, Vec<Value>) -> Option<Value>,
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
    /// Integer type, matching [`Value::Integer`].
    Integer,
    /// Floating-point number type, matching [`Value::Float`].
    Float,
    /// Bytes type, matching [`Value::Bytes`].
    Bytes,
    /// Regex type, matching [`Value::Regex`].
    Regex,
    /// Boolean type, matching [`Value::Boolean`].
    Boolean,
    /// Object type, matching [`Value::Object`].
    Object(HashMap<&'static str, Type>),
    /// Array type, matching [`Value::Array`].
    Array {
        /// Type of the values in the array.
        value_type: Box<Type>,
    },
    /// Dictionary type, matching [`Value::Dictionary`].
    Dictionary {
        /// Type of the values in the dictionary (keys are bytes).
        value_type: Box<Type>,
    },
    /// Function type, matching [`Value::Function`].
    Function {
        /// Types of arguments for the function.
        ///
        /// Each element in the list is a list of arguments types that the function accepts.
        /// This is only used to type-check the function call when a rule is compiled.
        ///
        /// For example: `vec![ vec![Type::Integer, Type::Boolean], vec![Type::String] ]` accepts
        /// `f(5, true)` and `f("a")`, but rejects `f()`, `f(5)` or `f("a", true)`.
        arguments_types: Vec<Vec<Type>>,

        /// Type of the function's returned value.
        return_type: Box<Type>,
    },
}

impl Type {
    /// Build a [`Self::Object`] type.
    ///
    /// ```
    /// use boreal::module::Type;
    ///
    /// let t = Type::object([("a", Type::Integer), ("b", Type::Bytes)]);
    /// ```
    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, Type); N]) -> Self {
        Self::Object(v.into())
    }

    /// Build a [`Self::Array`] type.
    #[must_use]
    pub fn array(value_type: Type) -> Self {
        Self::Array {
            value_type: Box::new(value_type),
        }
    }

    /// Build a [`Self::Dictionary`] type.
    #[must_use]
    pub fn dict(value_type: Type) -> Self {
        Self::Dictionary {
            value_type: Box::new(value_type),
        }
    }

    /// Build a [`Self::Function`] type.
    ///
    /// ```
    /// use boreal::module::Type;
    ///
    /// let t = Type::function(vec![vec![Type::Bytes, Type::Float]], Type::Integer);
    /// ```
    #[must_use]
    pub fn function(arguments_types: Vec<Vec<Type>>, return_type: Type) -> Self {
        Self::Function {
            arguments_types,
            return_type: Box::new(return_type),
        }
    }
}

/// Error converting into a [`Value`].
pub struct ValueTryFromError;

macro_rules! try_from_value {
    ($ty:ty, $name:ident) => {
        impl TryFrom<Value> for $ty {
            type Error = ValueTryFromError;

            fn try_from(value: Value) -> Result<$ty, Self::Error> {
                match value {
                    Value::$name(v) => Ok(v),
                    _ => Err(ValueTryFromError),
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

macro_rules! from_big_integer {
    ($ty:ty) => {
        impl From<$ty> for Value {
            fn from(v: $ty) -> Value {
                v.try_into().map_or(Value::Undefined, Value::Integer)
            }
        }
    };
}

from_big_integer!(u64);
from_big_integer!(usize);

impl<T> From<Option<T>> for Value
where
    Value: From<T>,
{
    fn from(v: Option<T>) -> Value {
        v.map_or(Value::Undefined, Value::from)
    }
}

fn hex_encode<T: AsRef<[u8]>>(v: T) -> Vec<u8> {
    hex_encode_inner(v.as_ref())
}

fn hex_encode_inner(v: &[u8]) -> Vec<u8> {
    const DICT: &[u8] = b"0123456789abcdef";

    // This code is actually the one i found generates the best codegen, with:
    // - a single allocation for the vector with the right size
    // - no bounds checking
    v.iter()
        .flat_map(|b| {
            [
                DICT[usize::from((*b & 0xF0) >> 4)],
                DICT[usize::from(*b & 0x0F)],
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_fun(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        drop(args);
        None
    }

    #[test]
    fn test_types_traits() {
        test_type_traits(ModuleUserData::default());
        test_type_traits_non_clonable(ScanContext {
            region: &Region { start: 0, mem: b"" },
            module_data: &mut ModuleDataMap::new(&ModuleUserData::default()),
            process_memory: false,
        });
        test_type_traits_non_clonable(EvalContext {
            mem: &mut Memory::Direct(b""),
            module_data: &ModuleDataMap::new(&ModuleUserData::default()),
            process_memory: false,
        });

        test_type_traits(Value::Integer(0));
        test_type_traits(StaticValue::Integer(0));
        test_type_traits(Type::Integer);

        test_type_traits_non_clonable(Time);
        test_type_traits_non_clonable(Math);
        test_type_traits_non_clonable(String_);
        #[cfg(feature = "hash")]
        test_type_traits_non_clonable(Hash);
        #[cfg(feature = "object")]
        {
            test_type_traits_non_clonable(Elf);
            test_type_traits_non_clonable(MachO);
            test_type_traits_non_clonable(Pe);
        }

        assert_eq!(format!("{:?}", Value::Integer(0)), "Integer(0)");
        assert_eq!(format!("{:?}", Value::Float(0.0)), "Float(0.0)");
        assert_eq!(format!("{:?}", Value::Bytes(Vec::new())), "Bytes(\"\")");
        assert_eq!(format!("{:?}", Value::Bytes(vec![255])), "Bytes([255])");
        assert!(format!(
            "{:?}",
            Value::Regex(Regex::from_string(String::new(), false, false).unwrap())
        )
        .starts_with("Regex("),);
        assert_eq!(format!("{:?}", Value::Boolean(true)), "Boolean(true)");
        assert_eq!(format!("{:?}", Value::Object(HashMap::new())), "Object({})");
        assert_eq!(format!("{:?}", Value::Array(Vec::new())), "Array([])");
        assert_eq!(
            format!("{:?}", Value::Dictionary(HashMap::new())),
            "Dictionary({})"
        );
        assert!(format!("{:?}", Value::function(test_fun)).starts_with("Function"));

        assert_eq!(format!("{:?}", StaticValue::Integer(0)), "Integer(0)");
        assert_eq!(format!("{:?}", StaticValue::Float(0.0)), "Float(0.0)");
        assert_eq!(format!("{:?}", StaticValue::Bytes(Vec::new())), "Bytes([])");
        assert_eq!(format!("{:?}", StaticValue::Bytes(vec![2])), "Bytes([2])");
        assert_eq!(format!("{:?}", StaticValue::Boolean(true)), "Boolean(true)");
        assert_eq!(
            format!("{:?}", StaticValue::Object(HashMap::new())),
            "Object({})"
        );
        assert!(format!(
            "{:?}",
            StaticValue::Function {
                fun: test_fun,
                arguments_types: Vec::new(),
                return_type: Type::Boolean
            }
        )
        .starts_with("Function"));
    }
}
