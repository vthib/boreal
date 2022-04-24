use regex::bytes::Regex;

use boreal::module::{Module, Type, Value};

#[derive(Debug)]
pub struct Tests;

impl Module for Tests {
    fn get_name(&self) -> String {
        "tests".to_owned()
    }

    fn get_value(&self) -> Value {
        Value::dictionary([
            (
                "constants",
                Value::dictionary([
                    ("one", Value::Integer(1)),
                    ("one_half", Value::Float(0.5)),
                    ("regex", Value::Regex(Regex::new("<a.b>").unwrap())),
                    ("str", Value::string("str")),
                    ("true", Value::Boolean(true)),
                ]),
            ),
            (
                "lazy",
                Value::function(
                    Self::lazy,
                    vec![],
                    Type::dictionary([
                        ("one", Type::Integer),
                        ("one_half", Type::Float),
                        ("regex", Type::Regex),
                        ("str", Type::String),
                        ("true", Type::Boolean),
                        (
                            "dict",
                            Type::dictionary([
                                ("i", Type::Integer),
                                ("s", Type::String),
                                // Declared here, but not exposed on evaluation
                                ("oops", Type::Boolean),
                            ]),
                        ),
                        ("str_array", Type::array(Type::String)),
                        (
                            "isum",
                            Type::function(vec![vec![Type::Integer, Type::Integer]], Type::Integer),
                        ),
                        // Declared as a bool, but exposes an array
                        ("fake_bool_to_array", Type::Boolean),
                        // Declared as a bool, but exposes a dict
                        ("fake_bool_to_dict", Type::Boolean),
                        // Declared as a bool, but exposes a function
                        ("fake_bool_to_fun", Type::Boolean),
                        // Declared as an integer, but exposes a regex
                        ("fake_int", Type::Integer),
                        // Declare as a dict, but exposes a bool
                        (
                            "fake_dict_to_bool",
                            Type::dictionary([("i", Type::Integer)]),
                        ),
                        // Declare as an array, but exposes a bool
                        ("fake_array_to_bool", Type::array(Type::String)),
                        // Declare as a function, but exposes a bool
                        ("fake_fun_to_bool", Type::function(vec![], Type::Boolean)),
                        // Lazy to lazy to int
                        (
                            "lazy",
                            Type::function(
                                vec![],
                                Type::dictionary([(
                                    "lazy_int",
                                    Type::function(vec![], Type::Integer),
                                )]),
                            ),
                        ),
                    ]),
                ),
            ),
            (
                "undefined_str",
                Value::function(Self::undefined, vec![], Type::String),
            ),
            (
                "undefined_int",
                Value::function(Self::undefined, vec![], Type::Integer),
            ),
            (
                "undefined",
                Value::function(
                    Self::undefined,
                    vec![],
                    Type::dictionary([("i", Type::Integer), ("f", Type::Float)]),
                ),
            ),
            (
                "string_dict",
                Value::dictionary([
                    ("foo", Value::string("foo")),
                    ("bar", Value::string("bar")),
                    (
                        "undefined",
                        Value::function(Self::undefined, vec![], Type::String),
                    ),
                ]),
            ),
            (
                "struct_dict",
                Value::dictionary([(
                    "foo",
                    Value::dictionary([("s", Value::string("foo")), ("i", Value::Integer(1))]),
                )]),
            ),
            (
                "integer_array",
                Value::array(Self::integer_array, Type::Integer),
            ),
            (
                "string_array",
                Value::array(Self::string_array, Type::String),
            ),
            (
                "struct_array",
                Value::array(
                    Self::struct_array,
                    Type::dictionary([("i", Type::Integer), ("s", Type::String)]),
                ),
            ),
            (
                "match",
                Value::function(
                    Self::r#match,
                    vec![vec![Type::String, Type::Regex]],
                    Type::Boolean,
                ),
            ),
            (
                "isum",
                Value::function(
                    Self::isum,
                    vec![
                        vec![Type::Integer, Type::Integer],
                        vec![Type::Integer, Type::Integer, Type::Integer],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "fsum",
                Value::function(
                    Self::fsum,
                    vec![
                        vec![Type::Float, Type::Float],
                        vec![Type::Float, Type::Float, Type::Integer],
                    ],
                    Type::Float,
                ),
            ),
            (
                "length",
                Value::function(Self::length, vec![vec![Type::String]], Type::Integer),
            ),
            ("empty", Value::function(Self::empty, vec![], Type::String)),
            (
                "log",
                Value::function(
                    Self::log,
                    vec![
                        vec![Type::Integer],
                        vec![Type::Boolean, Type::Regex, Type::String],
                        vec![Type::Boolean, Type::Regex],
                        vec![Type::Integer, Type::Boolean],
                    ],
                    Type::Boolean,
                ),
            ),
        ])
    }
}

impl Tests {
    fn undefined(_: Vec<Value>) -> Option<Value> {
        None
    }

    fn fsum(arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let mut res = f64::try_from(args.next()?).ok()?;
        res += f64::try_from(args.next()?).ok()?;
        if let Some(v) = args.next() {
            let v: i64 = v.try_into().ok()?;
            res += v as f64;
        }
        Some(Value::Float(res))
    }

    fn isum(arguments: Vec<Value>) -> Option<Value> {
        let mut res = 0;
        for arg in arguments {
            res += i64::try_from(arg).ok()?;
        }
        Some(Value::Integer(res))
    }

    fn length(arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let s: String = args.next()?.try_into().ok()?;

        i64::try_from(s.len()).ok().map(Value::Integer)
    }

    fn empty(_: Vec<Value>) -> Option<Value> {
        Some(Value::String("".into()))
    }

    fn log(_: Vec<Value>) -> Option<Value> {
        Some(Value::Boolean(true))
    }

    fn r#match(arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let s: String = args.next()?.try_into().ok()?;
        let regex: Regex = args.next()?.try_into().ok()?;

        Some(Value::Boolean(regex.is_match(s.as_bytes())))
    }

    fn integer_array(index: u64) -> Option<Value> {
        if index <= 2 {
            Some(Value::Integer(index as i64))
        } else {
            None
        }
    }

    fn string_array(index: u64) -> Option<Value> {
        match index {
            0 => Some(Value::string("foo")),
            1 => Some(Value::string("bar")),
            2 => Some(Value::string("baz")),
            3 => Some(Value::string("foo\0bar")),
            _ => None,
        }
    }

    fn struct_array(index: u64) -> Option<Value> {
        if index == 1 {
            Some(Value::dictionary([("i", Value::Integer(1))]))
        } else {
            None
        }
    }

    fn lazy(_: Vec<Value>) -> Option<Value> {
        Some(Value::dictionary([
            ("one", Value::Integer(1)),
            ("one_half", Value::Float(0.5)),
            ("regex", Value::Regex(Regex::new("<a.b>").unwrap())),
            ("str", Value::string("str")),
            ("true", Value::Boolean(true)),
            (
                "dict",
                Value::dictionary([("i", Value::Integer(3)), ("s", Value::string("<acb>"))]),
            ),
            ("str_array", Value::array(Self::string_array, Type::String)),
            (
                "isum",
                Value::function(
                    Self::isum,
                    vec![vec![Type::Integer, Type::Integer]],
                    Type::Integer,
                ),
            ),
            (
                "fake_bool_to_array",
                Value::array(Self::integer_array, Type::Integer),
            ),
            ("fake_bool_to_dict", Value::dictionary([])),
            (
                "fake_bool_to_fun",
                Value::function(Self::empty, vec![], Type::Boolean),
            ),
            ("fake_int", Value::Regex(Regex::new("ht+p").unwrap())),
            ("fake_dict_to_bool", Value::Boolean(false)),
            ("fake_array_to_bool", Value::Boolean(false)),
            ("fake_fun_to_bool", Value::Boolean(false)),
            (
                "lazy",
                Value::function(
                    Self::lazy_lazy,
                    vec![],
                    Type::dictionary([("lazy_int", Type::function(vec![], Type::Integer))]),
                ),
            ),
        ]))
    }

    fn lazy_lazy(_: Vec<Value>) -> Option<Value> {
        Some(Value::dictionary([(
            "lazy_int",
            Value::function(Self::lazy_lazy_int, vec![], Type::Integer),
        )]))
    }

    fn lazy_lazy_int(_: Vec<Value>) -> Option<Value> {
        Some(Value::Integer(3))
    }
}
