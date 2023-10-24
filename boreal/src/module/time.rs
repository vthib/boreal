use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{EvalContext, Module, StaticValue, Type, Value};

/// `time` module. Only exposes a `now` function to get the unix timestamp.
#[derive(Debug)]
pub struct Time;

impl Module for Time {
    fn get_name(&self) -> &'static str {
        "time"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [(
            "now",
            StaticValue::function(Self::now, vec![], Type::Integer),
        )]
        .into()
    }
}

impl Time {
    fn now(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            // This should not fail unless the clock is set to before the unix epoch.
            // But if it actually is the case, we just return an undefined value
            .ok()
            .map(|d| d.as_secs())
            .and_then(|v| i64::try_from(v).ok())
            .map(Value::Integer)
    }
}
