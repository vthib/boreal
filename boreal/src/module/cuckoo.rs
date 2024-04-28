use std::collections::HashMap;

use crate::regex::Regex;

use super::{EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Type, Value};

/// `cuckoo` module.
#[derive(Debug)]
pub struct Cuckoo;

impl Module for Cuckoo {
    fn get_name(&self) -> &'static str {
        "cuckoo"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "network",
                StaticValue::object([
                    (
                        "dns_lookup",
                        StaticValue::function(
                            Self::network_dns_lookup,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "http_get",
                        StaticValue::function(
                            Self::network_http_get,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "http_post",
                        StaticValue::function(
                            Self::network_http_post,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "http_request",
                        StaticValue::function(
                            Self::network_http_request,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "http_user_agent",
                        StaticValue::function(
                            Self::network_http_user_agent,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "host",
                        StaticValue::function(
                            Self::network_host,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "tcp",
                        StaticValue::function(
                            Self::network_tcp,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "udp",
                        StaticValue::function(
                            Self::network_udp,
                            vec![vec![Type::Regex]],
                            Type::Integer,
                        ),
                    ),
                ]),
            ),
            (
                "registry",
                StaticValue::object([(
                    "key_access",
                    StaticValue::function(
                        Self::registry_key_access,
                        vec![vec![Type::Regex]],
                        Type::Integer,
                    ),
                )]),
            ),
            (
                "filesystem",
                StaticValue::object([(
                    "file_access",
                    StaticValue::function(
                        Self::filesystem_file_access,
                        vec![vec![Type::Regex]],
                        Type::Integer,
                    ),
                )]),
            ),
            (
                "sync",
                StaticValue::object([(
                    "mutex",
                    StaticValue::function(Self::sync_mutex, vec![vec![Type::Regex]], Type::Integer),
                )]),
            ),
        ]
        .into()
    }

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        let Some(user_data) = data_map.get_user_data::<Self>() else {
            return;
        };

        let Ok(mut report) = serde_json::from_str::<serde_json::Value>(&user_data.json_report)
        else {
            return;
        };

        let network = report.get_mut("network").map(serde_json::Value::take);
        let summary = report
            .get_mut("behavior")
            .and_then(|v| v.get_mut("summary"))
            .map(serde_json::Value::take);

        data_map.insert::<Self>(Data { network, summary });
    }
}

/// Data used by the cuckoo module.
///
/// This data must be provided by a call to
/// [`Scanner::set_module_data`](crate::scanner::Scanner::set_module_data).
pub struct CuckooData {
    /// The Cuckoo report in JSON format.
    pub json_report: String,
}

pub struct Data {
    /// The "network" key in the parsed json report.
    network: Option<serde_json::Value>,

    /// The "behavior.summary" key in the parsed json report.
    summary: Option<serde_json::Value>,
}

impl ModuleData for Cuckoo {
    type PrivateData = Data;
    type UserData = CuckooData;
}

impl Cuckoo {
    fn network_dns_lookup(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_http_get(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_http_post(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_http_request(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_http_user_agent(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_host(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_tcp(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn network_udp(_ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn registry_key_access(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        regex_matches_summary_string_array(ctx, args, "keys")
    }

    fn filesystem_file_access(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        regex_matches_summary_string_array(ctx, args, "files")
    }

    fn sync_mutex(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        regex_matches_summary_string_array(ctx, args, "mutexes")
    }
}

fn regex_matches_summary_string_array(
    ctx: &mut EvalContext,
    args: Vec<Value>,
    key_name: &str,
) -> Option<Value> {
    let data = ctx.module_data.get::<Cuckoo>()?;
    let values = data.summary.as_ref()?.get(key_name)?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    let found = values
        .iter()
        .filter_map(|v| v.as_str())
        .any(|name| regex.is_match(name.as_bytes()));
    Some(Value::Integer(i64::from(found)))
}
