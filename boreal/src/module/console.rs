use std::fmt::Write;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::{collections::HashMap, sync::Arc};

use super::{EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Type, Value};

/// `console` module.
///
/// To use the module, you must provide a callback which will be called when
/// `console.log` is called.
///
/// The callback can also be overridden on every scan by specifying a `ConsoleData`
/// in the scanner.
///
/// ```
/// use boreal::module::{Console, ConsoleData};
/// use boreal::compiler::CompilerBuilder;
///
/// let mut compiler = CompilerBuilder::new()
///     // Do not log anything by default
///     .add_module(Console::with_callback(|_log| {}))
///     .build();
/// compiler.add_rules_str(r#"
/// import "console"
///
/// rule a {
///     condition: console.log("one")
/// }"#).unwrap();
/// let mut scanner = compiler.finalize();
///
/// scanner.scan_mem(b""); // Will not log anything
///
/// let console_data = ConsoleData::new(|log| {
///     println!("yara console log: {log}");
/// });
/// scanner.set_module_data::<Console>(console_data);
/// scanner.scan_mem(b""); // Will log "yara console log: one"
/// ```
pub struct Console {
    callback: Arc<LogCallback>,
}

/// Type of callback called when a message is logged.
pub type LogCallback = dyn Fn(String) + Send + Sync + UnwindSafe + RefUnwindSafe;

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
        data_map.insert::<Self>(PrivateData {
            callback: Arc::clone(&self.callback),
        });
    }
}

pub struct PrivateData {
    callback: Arc<LogCallback>,
}

impl ModuleData for Console {
    type PrivateData = PrivateData;
    type UserData = ConsoleData;
}

/// Data used by the console module.
///
/// This data can be provided by a call to
/// [`Scanner::set_module_data`](crate::scanner::Scanner::set_module_data) to override
/// the default callback that was specified when compiling rules.
pub struct ConsoleData {
    callback: Box<LogCallback>,
}

impl ConsoleData {
    /// Provide a callback called when console.log is evaluted in rules.
    pub fn new<T>(callback: T) -> Self
    where
        T: Fn(String) + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
    {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl Console {
    /// Create a new console module with a callback.
    ///
    /// The callback will be called when expressions using this module
    /// are used.
    #[must_use]
    pub fn with_callback<T>(callback: T) -> Self
    where
        T: Fn(String) + Send + Sync + UnwindSafe + RefUnwindSafe + 'static,
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

        call_callback(ctx, res)?;

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

        call_callback(ctx, res)?;

        Some(Value::Integer(1))
    }
}

fn call_callback(ctx: &EvalContext, log: String) -> Option<()> {
    // First, check if there is a callback specified for this scan.
    if let Some(data) = ctx.module_data.get_user_data::<Console>() {
        (data.callback)(log);
    } else {
        // Otherwise, use the callback specified when building the module.
        let data = ctx.module_data.get::<Console>()?;
        (data.callback)(log);
    }
    Some(())
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
