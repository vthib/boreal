use std::collections::HashMap;

use super::{EvalContext, Module, StaticValue, Type, Value};

/// `string` module.
#[derive(Debug)]
pub struct String_;

impl Module for String_ {
    fn get_name(&self) -> &'static str {
        "string"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "to_int",
                StaticValue::function(
                    Self::to_int,
                    vec![vec![Type::Bytes], vec![Type::Bytes, Type::Integer]],
                    Type::Integer,
                ),
            ),
            (
                "length",
                StaticValue::function(Self::length, vec![vec![Type::Bytes]], Type::Integer),
            ),
        ]
        .into()
    }
}

impl String_ {
    fn to_int(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();

        let s: Vec<u8> = args.next()?.try_into().ok()?;

        // Ideally, we would just use i64::from_str_radix. However, that does not
        // exhibit the same behavior as strtol used in libyara, so we need to
        // do the parsing by hand.

        let mut s = s.as_slice();
        while !s.is_empty() && s[0].is_ascii_whitespace() {
            s = &s[1..];
        }

        let mut base: u32 = match args.next() {
            Some(Value::Integer(i)) => {
                let i = i.try_into().ok()?;
                if i == 0 || (2..=36).contains(&i) {
                    i
                } else {
                    return None;
                }
            }
            Some(_) => return None,
            None => 0,
        };

        let is_negative = if s.starts_with(b"-") {
            s = &s[1..];
            true
        } else if s.starts_with(b"+") {
            s = &s[1..];
            false
        } else {
            false
        };

        if base == 0 {
            if s.starts_with(b"0x") || s.starts_with(b"0X") {
                base = 16;
                s = &s[2..];
            } else if s.starts_with(b"0") {
                base = 8;
                // Do not advance s to s[1..]. Why? This is to ensure that "0" is properly
                // parsed, and not considered as an empty string which returns an undefined
                // value.
            } else {
                base = 10;
            }
        }

        if s.is_empty() {
            return None;
        }

        let mut res: i64 = 0;
        for c in s {
            match (*c as char).to_digit(base) {
                Some(c) => {
                    res = res.checked_mul(i64::from(base))?;
                    if is_negative {
                        res = res.checked_sub(i64::from(c))?;
                    } else {
                        res = res.checked_add(i64::from(c))?;
                    }
                }
                None => return None,
            }
        }
        Some(Value::Integer(res))
    }

    fn length(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let s: Vec<u8> = args.next()?.try_into().ok()?;

        Some(Value::Integer(s.len().try_into().ok()?))
    }
}
