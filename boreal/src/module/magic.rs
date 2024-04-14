use std::collections::HashMap;

use magic::cookie::{Cookie, DatabasePaths, Flags};

use super::{EvalContext, Module, StaticValue, Type, Value};

/// `magic` module.
#[derive(Debug)]
pub struct Magic;

impl Module for Magic {
    fn get_name(&self) -> &'static str {
        "magic"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "mime_type",
                StaticValue::function(Self::get_mime_type, vec![], Type::Bytes),
            ),
            (
                "type",
                StaticValue::function(Self::get_type, vec![], Type::Bytes),
            ),
        ]
        .into()
    }
}

impl Magic {
    fn get_mime_type(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        get_magic_value(ctx, Flags::MIME_TYPE)
    }

    fn get_type(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        get_magic_value(ctx, Flags::default())
    }
}

fn get_magic_value(ctx: &EvalContext, flags: Flags) -> Option<Value> {
    let cookie = Cookie::open(flags).ok()?;
    let cookie = cookie.load(&DatabasePaths::default()).ok()?;

    let mem = ctx.mem.get_direct()?;
    let mime_type = cookie.buffer(mem).ok()?;
    dbg!(&mime_type);

    Some(Value::Bytes(mime_type.into_bytes()))
}
