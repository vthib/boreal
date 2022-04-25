use regex::bytes::Regex;

use boreal::module::{Module, Type, Value};

#[derive(Debug)]
pub struct Tests;

impl Module for Tests {
    fn get_name(&self) -> String {
        "tests".to_owned()
    }

    fn get_value(&self) -> Value {
        Value::object([
            // Following is same as libyara, used in compliance tests
            (
                "constants",
                Value::object([
                    ("one", Value::Integer(1)),
                    ("two", Value::Integer(2)),
                    ("foo", Value::string("foo")),
                    ("empty", Value::string("")),
                    // Not libyara
                    ("one_half", Value::Float(0.5)),
                    ("regex", Value::Regex(Regex::new("<a.b>").unwrap())),
                    ("str", Value::string("str")),
                    ("true", Value::Boolean(true)),
                ]),
            ),
            (
                "undefined",
                Value::function(
                    Self::undefined,
                    vec![],
                    Type::object([("i", Type::Integer), ("f", Type::Float)]),
                ),
            ),
            // TODO: missing module_data
            (
                "integer_array",
                Value::array(Self::integer_array, Type::Integer),
            ),
            (
                "string_array",
                Value::array(Self::string_array, Type::String),
            ),
            (
                "integer_dict",
                Value::dict(Self::integer_dict, Type::Integer),
            ),
            ("string_dict", Value::dict(Self::string_dict, Type::String)),
            (
                "struct_array",
                Value::array(
                    Self::struct_array,
                    Type::object([("i", Type::Integer), ("s", Type::String)]),
                ),
            ),
            (
                "struct_dict",
                Value::dict(
                    Self::struct_dict,
                    Type::object([("i", Type::Integer), ("s", Type::String)]),
                ),
            ),
            (
                "empty_struct_dict",
                Value::dict(Self::undefined_dict, Type::object([("i", Type::Integer)])),
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
                "foobar",
                Value::function(Self::foobar, vec![vec![Type::Integer]], Type::String),
            ),
            // The rest is not in libyara
            (
                "lazy",
                Value::function(
                    Self::lazy,
                    vec![],
                    Type::object([
                        ("one", Type::Integer),
                        ("one_half", Type::Float),
                        ("regex", Type::Regex),
                        ("str", Type::String),
                        ("true", Type::Boolean),
                        (
                            "dict",
                            Type::object([
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
                        ("string_dict", Type::dict(Type::String)),
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
                        ("fake_dict_to_bool", Type::object([("i", Type::Integer)])),
                        // Declare as an array, but exposes a bool
                        ("fake_array_to_bool", Type::array(Type::String)),
                        // Declare as a function, but exposes a bool
                        ("fake_fun_to_bool", Type::function(vec![], Type::Boolean)),
                        // Lazy to lazy to int
                        (
                            "lazy",
                            Type::function(
                                vec![],
                                Type::object([("lazy_int", Type::function(vec![], Type::Integer))]),
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

    fn undefined_dict(_: String) -> Option<Value> {
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

    fn foobar(args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v = i64::try_from(args.next()?).ok()?;

        Some(Value::string(match v {
            1 => "foo",
            2 => "bar",
            _ => "oops",
        }))
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
        match index {
            0 | 1 | 2 | 256 => Some(Value::Integer(index as i64)),
            _ => None,
        }
    }

    fn string_array(index: u64) -> Option<Value> {
        match index {
            0 => Some(Value::string("foo")),
            1 => Some(Value::string("bar")),
            2 => Some(Value::string("baz")),
            _ => None,
        }
    }

    fn integer_dict(v: String) -> Option<Value> {
        match &*v {
            "foo" => Some(Value::Integer(1)),
            "bar" => Some(Value::Integer(2)),
            _ => None,
        }
    }
    fn string_dict(v: String) -> Option<Value> {
        if v == "foo" || v == "bar" {
            Some(Value::String(v))
        } else {
            None
        }
    }

    fn struct_array(index: u64) -> Option<Value> {
        if index == 1 {
            Some(Value::object([("i", Value::Integer(1))]))
        } else {
            None
        }
    }

    fn struct_dict(v: String) -> Option<Value> {
        if v == "foo" {
            Some(Value::object([
                ("i", Value::Integer(1)),
                ("s", Value::String(v)),
            ]))
        } else {
            None
        }
    }

    fn lazy(_: Vec<Value>) -> Option<Value> {
        Some(Value::object([
            ("one", Value::Integer(1)),
            ("one_half", Value::Float(0.5)),
            ("regex", Value::Regex(Regex::new("<a.b>").unwrap())),
            ("str", Value::string("str")),
            ("true", Value::Boolean(true)),
            (
                "dict",
                Value::object([("i", Value::Integer(3)), ("s", Value::string("<acb>"))]),
            ),
            ("str_array", Value::array(Self::string_array, Type::String)),
            ("string_dict", Value::dict(Self::string_dict, Type::String)),
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
            ("fake_bool_to_dict", Value::object([])),
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
                    Type::object([("lazy_int", Type::function(vec![], Type::Integer))]),
                ),
            ),
        ]))
    }

    fn lazy_lazy(_: Vec<Value>) -> Option<Value> {
        Some(Value::object([(
            "lazy_int",
            Value::function(Self::lazy_lazy_int, vec![], Type::Integer),
        )]))
    }

    fn lazy_lazy_int(_: Vec<Value>) -> Option<Value> {
        Some(Value::Integer(3))
    }
}
