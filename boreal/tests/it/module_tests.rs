use std::collections::HashMap;

use boreal::module::{EvalContext, Module, ScanContext, StaticValue, Type, Value};
use boreal::regex::Regex;

#[derive(Debug)]
pub struct Tests;

impl Module for Tests {
    fn get_name(&self) -> &'static str {
        "tests"
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
                        // Declared as an integer, but exposes a string
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
            // Used for iterable tests
            (
                "simple_dict",
                Type::dict(Type::object([
                    ("array", Type::array(Type::dict(Type::Integer))),
                    (
                        "lazy_array",
                        Type::function(
                            vec![],
                            Type::array(Type::object([(
                                "another_array",
                                Type::array(Type::object([(
                                    "person",
                                    Type::object([("name", Type::Bytes), ("age", Type::Integer)]),
                                )])),
                            )])),
                        ),
                    ),
                ])),
            ),
            // Function using types that are not scalar: won't ever be usable
            (
                "invalid_fun",
                Type::function(vec![vec![Type::array(Type::Integer)]], Type::Bytes),
            ),
        ]
        .into()
    }

    fn get_dynamic_values(&self, _ctx: &mut ScanContext, out: &mut HashMap<&'static str, Value>) {
        if !out.is_empty() {
            return;
        }

        out.extend([
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
                "simple_dict",
                Value::Dictionary(
                    [
                        (
                            b"first".to_vec(),
                            Value::object([
                                (
                                    "array",
                                    Value::Array(vec![
                                        Value::Dictionary(
                                            [
                                                (b"a".to_vec(), Value::Integer(1)),
                                                (b"b".to_vec(), Value::Integer(2)),
                                            ]
                                            .into(),
                                        ),
                                        Value::Dictionary(
                                            [
                                                (b"c".to_vec(), Value::Integer(3)),
                                                (b"d".to_vec(), Value::Integer(4)),
                                            ]
                                            .into(),
                                        ),
                                    ]),
                                ),
                                ("lazy_array", Value::function(Self::lazy_array)),
                            ]),
                        ),
                        (
                            b"second".to_vec(),
                            Value::object([
                                (
                                    "array",
                                    Value::Array(vec![Value::Dictionary(
                                        [
                                            (b"y".to_vec(), Value::Integer(25)),
                                            (b"z".to_vec(), Value::Integer(26)),
                                        ]
                                        .into(),
                                    )]),
                                ),
                                ("lazy_array", Value::function(Self::lazy_array)),
                            ]),
                        ),
                    ]
                    .into(),
                ),
            ),
            ("fsum", Value::function(Self::fsum)),
            ("length", Value::function(Self::length)),
            ("empty", Value::function(Self::empty)),
            ("foobar", Value::function(Self::foobar)),
            // The rest is not in libyara
            ("lazy", Value::function(Self::lazy)),
            ("log", Value::function(Self::log)),
            ("invalid_fun", Value::function(Self::foobar)),
        ]);
    }
}

impl Tests {
    fn fsum(_: &mut EvalContext, arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let mut res = f64::try_from(args.next()?).ok()?;
        res += f64::try_from(args.next()?).ok()?;
        if let Some(v) = args.next() {
            res += f64::try_from(v).ok()?;
        }
        Some(Value::Float(res))
    }

    fn isum(_: &mut EvalContext, arguments: Vec<Value>) -> Option<Value> {
        let mut res = 0;
        for arg in arguments {
            res += i64::try_from(arg).ok()?;
        }
        Some(Value::Integer(res))
    }

    fn length(_: &mut EvalContext, arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let s: Vec<u8> = args.next()?.try_into().ok()?;

        i64::try_from(s.len()).ok().map(Value::Integer)
    }

    fn empty(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Bytes("".into()))
    }

    fn foobar(_: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v = i64::try_from(args.next()?).ok()?;

        Some(Value::bytes(match v {
            1 => "foo",
            2 => "bar",
            _ => "oops",
        }))
    }

    fn log(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Boolean(true))
    }

    fn r#match(_: &mut EvalContext, arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let regex: Regex = args.next()?.try_into().ok()?;
        let s: Vec<u8> = args.next()?.try_into().ok()?;

        Some(Value::Integer(match regex.find(&s) {
            Some(m) => m.len() as i64,
            None => -1,
        }))
    }

    fn lazy(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::object([
            ("one", Value::Integer(1)),
            ("one_half", Value::Float(0.5)),
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
            ("isum", Value::function(Self::isum)),
            ("fake_bool_to_array", Value::Array(vec![Value::Integer(2)])),
            ("fake_bool_to_dict", Value::object([])),
            ("fake_bool_to_fun", Value::function(Self::empty)),
            ("fake_int", Value::bytes("ht+p")),
            ("fake_dict_to_bool", Value::Boolean(false)),
            ("fake_array_to_bool", Value::Boolean(false)),
            ("fake_fun_to_bool", Value::Boolean(false)),
            ("lazy", Value::function(Self::lazy_lazy)),
        ]))
    }

    fn lazy_lazy(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::object([(
            "lazy_int",
            Value::function(Self::lazy_lazy_int),
        )]))
    }

    fn lazy_lazy_int(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Integer(3))
    }

    fn lazy_array(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        Some(Value::Array(vec![
            Value::object([(
                "another_array",
                Value::Array(vec![
                    Value::object([(
                        "person",
                        Value::object([
                            ("name", Value::Bytes(b"alice".to_vec())),
                            ("age", Value::Integer(57)),
                        ]),
                    )]),
                    Value::object([(
                        "person",
                        Value::object([
                            ("name", Value::Bytes(b"bob".to_vec())),
                            ("age", Value::Integer(23)),
                        ]),
                    )]),
                ]),
            )]),
            Value::object([(
                "another_array",
                Value::Array(vec![Value::object([(
                    "person",
                    Value::object([
                        ("name", Value::Bytes(b"charlie".to_vec())),
                        ("age", Value::Integer(15)),
                    ]),
                )])]),
            )]),
        ]))
    }
}
