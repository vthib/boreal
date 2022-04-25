use regex::bytes::Regex;
use std::collections::HashMap;

/// A module allows providing custom values and functions in rules.
///
/// The trait in itself only requires static values and methods, which are used
/// only the module itself is added to
pub trait Module {
    /// Name of the module, used in `import` clauses.
    fn get_name(&self) -> String;

    /// Value exported by the module.
    ///
    /// This is the value bound to the module name when the module is imported in a rule.
    ///
    /// ```ignore
    /// import "foo"
    ///
    /// rule a {
    ///     condition:
    ///         a >= 0 # a resolves to this value
    /// ```
    ///
    /// This function is called once, when the module is added to a scanner. It must describe all
    /// of the accessible data from this module.
    ///
    /// This is used to check the validity of rules using the module, but also to improve scan
    /// times by resolving as much as possible the vule when compiling a rule.
    ///
    /// For example, lets take this module:
    ///
    /// ```
    /// use boreal::module::{Module, Value, Type};
    ///
    /// struct Foo;
    ///
    /// impl Module for Foo {
    ///     fn get_name(&self) -> String {
    ///         "foo".to_owned()
    ///     }
    ///
    ///     fn get_value(&self) -> Value {
    ///         Value::object([
    ///             ("int", Value::Integer(1)),
    ///             ("array", Value::array(bar_array, Type::String)),
    ///         ])
    ///     }
    /// }
    ///
    /// fn bar_array(index: u64) -> Option<Value> {
    ///     Some(Value::String(index.to_string()))
    /// }
    /// ```
    ///
    /// Then:
    ///
    /// * `foo.a > 0` would fail to compile, as the module does not expose the key `a`.
    /// * `foo.int > 0` would compile directly to `true`, as we already know the value of this key
    ///    when compiling the rule.
    /// * `foo.array[2] matches /regex/` would compile properly, but delay evaluating the array
    ///   on every scan.
    /// * `foo.array[2] + 1` would fail to compile, as the array is indicated as returning a
    ///   string, which cannot be added to an integer.
    fn get_value(&self) -> Value;
}

/// A value bound to an identifier.
///
/// This object represents an immediately resolvable value for an identifier.
#[derive(Debug)]
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
        /// The function can return None, if the index is out-of-bounds, or if the array does not
        /// make sense in the current context. For example, `pe.sections[0]` does not make sense
        /// if the scanned object is not a PE.
        on_scan: fn(u64) -> Option<Value>,

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
        /// The only argument is the accessed index in the array.
        ///
        /// The function can return None, if the index is out-of-bounds, or if the array does not
        /// make sense in the current context. For example, `pe.sections[0]` does not make sense
        /// if the scanned object is not a PE.
        on_scan: fn(String) -> Option<Value>,

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
        /// # use boreal::module::Value;
        /// # let x = 3;
        /// # fn fun(_: Vec<Value>) -> Option<Value> { None }
        /// let result = fun(vec![
        ///     Value::string("a"),
        ///     Value::Integer(3),
        ///     Value::Integer(x), // Number of matches of string $foo
        /// ]);
        /// ```
        fun: fn(Vec<Value>) -> Option<Value>,

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

impl Value {
    pub fn string<T: Into<String>>(v: T) -> Self {
        Value::String(v.into())
    }

    #[must_use]
    pub fn object<const N: usize>(v: [(&'static str, Value); N]) -> Self {
        Value::Object(v.into())
    }

    pub fn array(fun: fn(u64) -> Option<Value>, ty: Type) -> Self {
        Value::Array {
            on_scan: fun,
            value_type: ty,
        }
    }

    pub fn dict(fun: fn(String) -> Option<Value>, ty: Type) -> Self {
        Value::Dictionary {
            on_scan: fun,
            value_type: ty,
        }
    }

    pub fn function(
        fun: fn(Vec<Value>) -> Option<Value>,
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
#[derive(Debug)]
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
