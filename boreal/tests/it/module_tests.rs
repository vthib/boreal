use regex::Regex;

use boreal::module::{Module, Symbol, Value};

#[derive(Debug)]
pub struct Tests;

impl Module for Tests {
    fn get_name(&self) -> String {
        "tests".to_owned()
    }

    fn get_symbol(&self) -> Symbol {
        Symbol::dictionary([
            (
                "constants",
                Symbol::dictionary([
                    ("one", Symbol::integer(1)),
                    ("two", Symbol::integer(2)),
                    ("foo", Symbol::string("foo")),
                    ("empty", Symbol::string("")),
                ]),
            ),
            ("undefined", Symbol::Lazy(Self::undefined)),
            (
                "string_dict",
                Symbol::dictionary([
                    ("foo", Symbol::string("foo")),
                    ("bar", Symbol::string("bar")),
                ]),
            ),
            (
                "struct_dict",
                Symbol::dictionary([(
                    "foo",
                    Symbol::dictionary([("s", Symbol::string("foo")), ("i", Symbol::integer(1))]),
                )]),
            ),
            (
                "integer_array",
                Symbol::Array(vec![
                    Symbol::integer(0),
                    Symbol::integer(1),
                    Symbol::integer(2),
                ]),
            ),
            (
                "string_array",
                Symbol::Array(vec![
                    Symbol::string("foo"),
                    Symbol::string("bar"),
                    Symbol::string("baz"),
                    Symbol::string("foo\0bar"),
                ]),
            ),
            (
                "struct_array",
                Symbol::Array(vec![
                    Symbol::Lazy(Self::undefined),
                    Symbol::dictionary([("i", Symbol::integer(1))]),
                ]),
            ),
            ("match", Symbol::function(Self::r#match, "rs", 'b')),
            ("isum", Symbol::function(Self::isum, "ii+", 'i')),
            ("fsum", Symbol::function(Self::fsum, "ff+", 'f')),
            ("length", Symbol::function(Self::length, "s", 'i')),
            ("empty", Symbol::function(Self::empty, "", 's')),
            ("foobar", Symbol::function(Self::foobar, "i", 's')),
        ])
    }
}

impl Tests {
    fn undefined() -> Option<Symbol> {
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
        Some(Value::Number(res))
    }

    fn length(arguments: Vec<Value>) -> Option<Value> {
        let mut args = arguments.into_iter();
        let s: String = args.next()?.try_into().ok()?;

        i64::try_from(s.len()).ok().map(Value::Number)
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
}
