use std::collections::HashMap;

use regex::bytes::Regex;

use boreal::module::{Module, ScanContext, Type, Value};

#[derive(Debug)]
pub struct Tests;

impl Module for Tests {
    fn get_name(&self) -> String {
        "tests".to_owned()
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        [
            // Following is same as libyara, used in compliance tests
            (
                "constants",
                Type::object([
                    ("one", Type::Integer),
                    ("two", Type::Integer),
                    ("foo", Type::String),
                    ("empty", Type::String),
                    // Not libyara
                    ("one_half", Type::Float),
                    ("regex", Type::Regex),
                    ("str", Type::String),
                    ("true", Type::Boolean),
                ]),
            ),
            (
                "undefined",
                Type::function(
                    vec![],
                    Type::object([("i", Type::Integer), ("f", Type::Float)]),
                ),
            ),
            // TODO: missing module_data
            ("integer_array", Type::array(Type::Integer)),
            ("string_array", Type::array(Type::String)),
            ("integer_dict", Type::dict(Type::Integer)),
            ("string_dict", Type::dict(Type::String)),
            (
                "struct_array",
                Type::array(Type::object([("i", Type::Integer), ("s", Type::String)])),
            ),
            (
                "struct_dict",
                Type::dict(Type::object([("i", Type::Integer), ("s", Type::String)])),
            ),
            (
                "empty_struct_dict",
                Type::dict(Type::object([("i", Type::Integer)])),
            ),
            (
                "empty_struct_array",
                Type::array(Type::object([
                    (
                        "struct_array",
                        Type::array(Type::object([("unused", Type::String)])),
                    ),
                    (
                        "struct_dict",
                        Type::dict(Type::object([("unused", Type::String)])),
                    ),
                ])),
            ),
            (
                "match",
                Type::function(vec![vec![Type::Regex, Type::String]], Type::Integer),
            ),
            (
                "isum",
                Type::function(
                    vec![
                        vec![Type::Integer, Type::Integer],
                        vec![Type::Integer, Type::Integer, Type::Integer],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "fsum",
                Type::function(
                    vec![
                        vec![Type::Float, Type::Float],
                        vec![Type::Float, Type::Float, Type::Float],
                    ],
                    Type::Float,
                ),
            ),
            (
                "length",
                Type::function(vec![vec![Type::String]], Type::Integer),
            ),
            ("empty", Type::function(vec![], Type::String)),
            (
                "foobar",
                Type::function(vec![vec![Type::Integer]], Type::String),
            ),
            // The rest is not in libyara
            (
                "lazy",
                Type::function(
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
            ("undefined_str", Type::function(vec![], Type::String)),
            ("undefined_int", Type::function(vec![], Type::Integer)),
            (
                "log",
                Type::function(
                    vec![
                        vec![Type::Integer],
                        vec![Type::Boolean, Type::Regex, Type::String],
                        vec![Type::Boolean, Type::Regex],
                        vec![Type::Integer, Type::Boolean],
                    ],
                    Type::Boolean,
                ),
            ),
        ]
        .into()
    }

    fn get_dynamic_values(&self, _ctx: &ScanContext) -> HashMap<&'static str, Value> {
        [
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
                "empty_struct_array",
                Value::array(
                    Self::undefined_array,
                    Type::object([
                        (
                            "struct_array",
                            Type::array(Type::object([("unused", Type::String)])),
                        ),
                        (
                            "struct_dict",
                            Type::dict(Type::object([("unused", Type::String)])),
                        ),
                    ]),
                ),
            ),
            (
                "match",
                Value::function(
                    Self::r#match,
                    vec![vec![Type::Regex, Type::String]],
                    Type::Integer,
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
                        vec![Type::Float, Type::Float, Type::Float],
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
        ]
        .into()
    }
}

impl Tests {
    fn undefined(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        None
    }

    fn undefined_dict(_: &ScanContext) -> Option<HashMap<String, Value>> {
        None
    }

    fn undefined_array(_: &ScanContext) -> Option<Vec<Value>> {
        None
    }

    fn fsum(_: &ScanContext, arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let mut res = f64::try_from(args.next()?).ok()?;
        res += f64::try_from(args.next()?).ok()?;
        if let Some(v) = args.next() {
            res += f64::try_from(v).ok()?;
        }
        Some(Value::Float(res))
    }

    fn isum(_: &ScanContext, arguments: Vec<Value>) -> Option<Value> {
        let mut res = 0;
        for arg in arguments {
            res += i64::try_from(arg).ok()?;
        }
        Some(Value::Integer(res))
    }

    fn length(_: &ScanContext, arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let s: String = args.next()?.try_into().ok()?;

        i64::try_from(s.len()).ok().map(Value::Integer)
    }

    fn empty(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::String("".into()))
    }

    fn foobar(_: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v = i64::try_from(args.next()?).ok()?;

        Some(Value::string(match v {
            1 => "foo",
            2 => "bar",
            _ => "oops",
        }))
    }

    fn log(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Boolean(true))
    }

    fn r#match(_: &ScanContext, arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let regex: Regex = args.next()?.try_into().ok()?;
        let s: String = args.next()?.try_into().ok()?;

        Some(Value::Integer(match regex.find(s.as_bytes()) {
            Some(m) => m.range().len() as i64,
            None => -1,
        }))
    }

    fn integer_array(_: &ScanContext) -> Option<Vec<Value>> {
        Some(vec![
            Value::Integer(0),
            Value::Integer(1),
            Value::Integer(2),
        ])
    }

    fn string_array(_: &ScanContext) -> Option<Vec<Value>> {
        Some(vec![
            Value::string("foo"),
            Value::string("bar"),
            Value::string("baz"),
            Value::string("foo\0bar"),
        ])
    }

    fn integer_dict(_: &ScanContext) -> Option<HashMap<String, Value>> {
        Some(
            [
                ("foo".to_string(), Value::Integer(1)),
                ("bar".to_string(), Value::Integer(2)),
            ]
            .into(),
        )
    }

    fn string_dict(_: &ScanContext) -> Option<HashMap<String, Value>> {
        Some(
            [
                ("foo".to_string(), Value::string("foo")),
                ("bar".to_string(), Value::string("bar")),
            ]
            .into(),
        )
    }

    fn struct_array(_: &ScanContext) -> Option<Vec<Value>> {
        Some(vec![
            Value::object([("i", Value::Integer(0))]),
            Value::object([("i", Value::Integer(1))]),
        ])
    }

    fn struct_dict(_: &ScanContext) -> Option<HashMap<String, Value>> {
        Some(
            [(
                "foo".to_string(),
                Value::object([("i", Value::Integer(1)), ("s", Value::string("foo"))]),
            )]
            .into(),
        )
    }

    fn lazy(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
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

    fn lazy_lazy(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::object([(
            "lazy_int",
            Value::function(Self::lazy_lazy_int, vec![], Type::Integer),
        )]))
    }

    fn lazy_lazy_int(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Integer(3))
    }
}
