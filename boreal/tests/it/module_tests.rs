use regex::Regex;

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
                    ("two", Value::Integer(2)),
                    ("foo", Value::string("foo")),
                    ("empty", Value::string("")),
                ]),
            ),
            ("undefined", Value::function(Self::undefined, Type::Boolean)),
            (
                "string_dict",
                Value::dictionary([("foo", Value::string("foo")), ("bar", Value::string("bar"))]),
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
            ("match", Value::function(Self::r#match, Type::Boolean)),
            ("isum", Value::function(Self::isum, Type::Integer)),
            ("fsum", Value::function(Self::fsum, Type::Float)),
            ("length", Value::function(Self::length, Type::Integer)),
            ("empty", Value::function(Self::empty, Type::String)),
            ("foobar", Value::function(Self::foobar, Type::String)),
        ])
    }
}

impl Tests {
    fn undefined(_: Vec<Value>) -> Option<Value> {
        None
    }

    fn fsum(arguments: Vec<Value>) -> Option<Value> {
        let mut res = 0.0;
        for arg in arguments {
            res += f64::try_from(arg).ok()?;
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

    #[allow(clippy::unnecessary_wraps)]
    fn empty(_: Vec<Value>) -> Option<Value> {
        Some(Value::String("".into()))
    }

    fn foobar(arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let v: i64 = args.next()?.try_into().ok()?;

        Some(Value::String(
            match v {
                1 => "foo",
                2 => "bar",
                _ => "oops",
            }
            .into(),
        ))
    }

    fn r#match(arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let regex: Regex = args.next()?.try_into().ok()?;
        let s: String = args.next()?.try_into().ok()?;

        Some(Value::Boolean(regex.is_match(&s)))
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
}
