use std::collections::HashMap;

use super::{Module, ScanContext, StaticValue, Type, Value};

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
    fn to_int(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();

        let s: Vec<u8> = args.next()?.try_into().ok()?;

        // Ideally, we would just use i64::from_str_radix. However, that does not
        // exhibit the same behavior as strtol used in libyara, so we need to
        // do the parsing by hand.

        // FIXME: trim without going through a string
        let s = std::str::from_utf8(&s).ok()?;
        let s = s.trim();
        let s = s.as_bytes();

        let base: u32 = match args.next() {
            Some(Value::Integer(i)) => {
                let i = i.try_into().ok()?;
                if (2..=36).contains(&i) {
                    i
                } else {
                    return None;
                }
            }
            Some(_) => return None,
            None => 10,
        };

        if s.is_empty() {
            return None;
        }
        let (is_negative, s) = match s[0] {
            b'-' => (true, &s[1..]),
            b'+' => (false, &s[1..]),
            _ => (false, s),
        };
        if s.is_empty() {
            return None;
        }

        let mut res: i64 = 0;
        for (i, c) in s.iter().enumerate() {
            match (*c as char).to_digit(base) {
                Some(c) => {
                    res = res.checked_mul(i64::from(base))?;
                    if is_negative {
                        res = res.checked_sub(i64::from(c))?;
                    } else {
                        res = res.checked_add(i64::from(c))?;
                    }
                }
                // If no digit was parsed at all, return an error
                None if i == 0 => return None,
                None => break,
            }
        }
        Some(Value::Integer(res))
    }

    fn length(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let s: Vec<u8> = args.next()?.try_into().ok()?;

        Some(Value::Integer(s.len().try_into().ok()?))
    }
}
