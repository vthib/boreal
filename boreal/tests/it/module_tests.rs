use std::collections::HashMap;

use regex::bytes::Regex;

use boreal::module::{Module, ScanContext, StaticValue, Type, Value};

#[derive(Debug)]
pub struct Tests;

impl Module for Tests {
    fn get_name(&self) -> String {
        "tests".to_owned()
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "constants",
                StaticValue::object([
                    ("one", StaticValue::Integer(1)),
                    ("two", StaticValue::Integer(2)),
                    ("foo", StaticValue::bytes("foo")),
                    ("empty", StaticValue::bytes("")),
                    // Not libyara
                    ("one_half", StaticValue::Float(0.5)),
                    ("regex", StaticValue::Regex(Regex::new("<a.b>").unwrap())),
                    ("str", StaticValue::bytes("str")),
                    ("true", StaticValue::Boolean(true)),
                ]),
            ),
            (
                "match",
                StaticValue::function(
                    Self::r#match,
                    vec![vec![Type::Regex, Type::Bytes]],
                    Type::Integer,
                ),
            ),
            (
                "isum",
                StaticValue::function(
                    Self::isum,
                    vec![
                        vec![Type::Integer, Type::Integer],
                        vec![Type::Integer, Type::Integer, Type::Integer],
                    ],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        [
            // Following is same as libyara, used in compliance tests
            (
                "undefined",
                Type::object([("i", Type::Integer), ("f", Type::Float)]),
            ),
            ("integer_array", Type::array(Type::Integer)),
            ("string_array", Type::array(Type::Bytes)),
            ("integer_dict", Type::dict(Type::Integer)),
            ("string_dict", Type::dict(Type::Bytes)),
            (
                "struct_array",
                Type::array(Type::object([("i", Type::Integer), ("s", Type::Bytes)])),
            ),
            (
                "struct_dict",
                Type::dict(Type::object([("i", Type::Integer), ("s", Type::Bytes)])),
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
                        Type::array(Type::object([("unused", Type::Bytes)])),
                    ),
                    (
                        "struct_dict",
                        Type::dict(Type::object([("unused", Type::Bytes)])),
                    ),
                ])),
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
                Type::function(vec![vec![Type::Bytes]], Type::Integer),
            ),
            ("empty", Type::function(vec![], Type::Bytes)),
            (
                "foobar",
                Type::function(vec![vec![Type::Integer]], Type::Bytes),
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
                        ("str", Type::Bytes),
                        ("true", Type::Boolean),
                        (
                            "dict",
                            Type::object([
                                ("i", Type::Integer),
                                ("s", Type::Bytes),
                                // Declared here, but not exposed on evaluation
                                ("oops", Type::Boolean),
                            ]),
                        ),
                        ("str_array", Type::array(Type::Bytes)),
                        (
                            "isum",
                            Type::function(vec![vec![Type::Integer, Type::Integer]], Type::Integer),
                        ),
                        ("string_dict", Type::dict(Type::Bytes)),
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
                        ("fake_array_to_bool", Type::array(Type::Bytes)),
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
            ("undefined_str", Type::Bytes),
            ("undefined_int", Type::Integer),
            (
                "log",
                Type::function(
                    vec![
                        vec![Type::Integer],
                        vec![Type::Boolean, Type::Regex, Type::Bytes],
                        vec![Type::Boolean, Type::Regex],
                        vec![Type::Integer, Type::Boolean],
                    ],
                    Type::Boolean,
                ),
            ),
        ]
        .into()
    }

    fn get_dynamic_values(&self, _ctx: &mut ScanContext) -> HashMap<&'static str, Value> {
        [
            // TODO: missing module_data
            (
                "integer_array",
                Value::Array(vec![
                    Value::Integer(0),
                    Value::Integer(1),
                    Value::Integer(2),
                ]),
            ),
            (
                "string_array",
                Value::Array(vec![
                    Value::bytes("foo"),
                    Value::bytes("bar"),
                    Value::bytes("baz"),
                    Value::bytes("foo\0bar"),
                ]),
            ),
            (
                "integer_dict",
                Value::Dictionary(
                    [
                        (b"foo".to_vec(), Value::Integer(1)),
                        (b"bar".to_vec(), Value::Integer(2)),
                    ]
                    .into(),
                ),
            ),
            (
                "string_dict",
                Value::Dictionary(
                    [
                        (b"foo".to_vec(), Value::bytes("foo")),
                        (b"bar".to_vec(), Value::bytes("bar")),
                    ]
                    .into(),
                ),
            ),
            (
                "struct_array",
                Value::Array(vec![
                    Value::object([("i", Value::Integer(0))]),
                    Value::object([("i", Value::Integer(1))]),
                ]),
            ),
            (
                "struct_dict",
                Value::Dictionary(
                    [(
                        b"foo".to_vec(),
                        Value::object([("i", Value::Integer(1)), ("s", Value::bytes("foo"))]),
                    )]
                    .into(),
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
                Value::function(Self::length, vec![vec![Type::Bytes]], Type::Integer),
            ),
            ("empty", Value::function(Self::empty, vec![], Type::Bytes)),
            (
                "foobar",
                Value::function(Self::foobar, vec![vec![Type::Integer]], Type::Bytes),
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
                        ("str", Type::Bytes),
                        ("true", Type::Boolean),
                        (
                            "dict",
                            Type::object([
                                ("i", Type::Integer),
                                ("s", Type::Bytes),
                                // Declared here, but not exposed on evaluation
                                ("oops", Type::Boolean),
                            ]),
                        ),
                        ("str_array", Type::array(Type::Bytes)),
                        (
                            "isum",
                            Type::function(vec![vec![Type::Integer, Type::Integer]], Type::Integer),
                        ),
                        ("string_dict", Type::dict(Type::Bytes)),
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
                        ("fake_array_to_bool", Type::array(Type::Bytes)),
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
                "log",
                Value::function(
                    Self::log,
                    vec![
                        vec![Type::Integer],
                        vec![Type::Boolean, Type::Regex, Type::Bytes],
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
        let s: Vec<u8> = args.next()?.try_into().ok()?;

        i64::try_from(s.len()).ok().map(Value::Integer)
    }

    fn empty(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Bytes("".into()))
    }

    fn foobar(_: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v = i64::try_from(args.next()?).ok()?;

        Some(Value::bytes(match v {
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
        let s: Vec<u8> = args.next()?.try_into().ok()?;

        Some(Value::Integer(match regex.find(&s) {
            Some(m) => m.range().len() as i64,
            None => -1,
        }))
    }

    fn lazy(_: &ScanContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::object([
            ("one", Value::Integer(1)),
            ("one_half", Value::Float(0.5)),
            ("regex", Value::Regex(Regex::new("<a.b>").unwrap())),
            ("str", Value::bytes("str")),
            ("true", Value::Boolean(true)),
            (
                "dict",
                Value::object([("i", Value::Integer(3)), ("s", Value::bytes("<acb>"))]),
            ),
            (
                "str_array",
                Value::Array(vec![
                    Value::bytes("foo"),
                    Value::bytes("bar"),
                    Value::bytes("baz"),
                    Value::bytes("foo\0bar"),
                ]),
            ),
            (
                "string_dict",
                Value::Dictionary(
                    [
                        (b"foo".to_vec(), Value::bytes("foo")),
                        (b"bar".to_vec(), Value::bytes("bar")),
                    ]
                    .into(),
                ),
            ),
            (
                "isum",
                Value::function(
                    Self::isum,
                    vec![vec![Type::Integer, Type::Integer]],
                    Type::Integer,
                ),
            ),
            ("fake_bool_to_array", Value::Array(vec![Value::Integer(2)])),
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
