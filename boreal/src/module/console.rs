use std::fmt::Write;
use std::{collections::HashMap, sync::Arc};

use super::{EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Type, Value};

/// `console` module.
pub struct Console {
    callback: Arc<LogCallback>,
}

/// Type of callback called when a message is logged.
pub type LogCallback = dyn Fn(String) + Send + Sync;

impl Module for Console {
    fn get_name(&self) -> &'static str {
        "console"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "log",
                StaticValue::function(
                    Self::log,
                    vec![
                        vec![Type::Bytes],
                        vec![Type::Bytes, Type::Bytes],
                        vec![Type::Integer],
                        vec![Type::Bytes, Type::Integer],
                        vec![Type::Float],
                        vec![Type::Bytes, Type::Float],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "hex",
                StaticValue::function(
                    Self::hex,
                    vec![vec![Type::Integer], vec![Type::Bytes, Type::Integer]],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        data_map.insert::<Self>(Data {
            callback: Arc::clone(&self.callback),
        });
    }
}

pub struct Data {
    callback: Arc<LogCallback>,
}

impl ModuleData for Console {
    type PrivateData = Data;
}

impl Console {
    /// Create a new console module with a callback.
    ///
    /// The callback will be called when expressions using this module
    /// are used.
    #[must_use]
    pub fn with_callback<T>(callback: T) -> Self
    where
        T: Fn(String) + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
        }
    }

    fn log(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let mut res = String::new();
        add_value(args.next()?, &mut res)?;
        if let Some(arg) = args.next() {
            add_value(arg, &mut res)?;
        }

        let data = ctx.module_data.get::<Console>()?;
        (data.callback)(res);

        Some(Value::Integer(1))
    }

    fn hex(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let res = match args.next()? {
            Value::Integer(v) => format!("0x{v:x}"),
            value => {
                let mut res = String::new();
                add_value(value, &mut res)?;
                let v: i64 = args.next()?.try_into().ok()?;
                write!(&mut res, "0x{v:x}").ok()?;
                res
            }
        };

        let data = ctx.module_data.get::<Console>()?;
        (data.callback)(res);

        Some(Value::Integer(1))
    }
}

fn add_value(value: Value, out: &mut String) -> Option<()> {
    match value {
        Value::Integer(v) => write!(out, "{v}").ok(),
        Value::Float(v) => write!(out, "{v}").ok(),
        Value::Bytes(v) => {
            for byte in v {
                for b in std::ascii::escape_default(byte) {
                    out.push(char::from(b));
                }
            }
            Some(())
        }
        _ => None,
    }
}
