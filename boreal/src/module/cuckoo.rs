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
                            vec![vec![Type::Regex, Type::Integer]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "udp",
                        StaticValue::function(
                            Self::network_udp,
                            vec![vec![Type::Regex, Type::Integer]],
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
    fn network_dns_lookup(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Cuckoo>()?;
        let network = data.network.as_ref()?;
        let (values, host_field_name) = match network.get("domains") {
            Some(v) => (v.as_array()?, "domain"),
            None => (network.get("dns")?.as_array()?, "hostname"),
        };

        let mut args = args.into_iter();
        let regex: Regex = args.next()?.try_into().ok()?;

        let found = values
            .iter()
            .filter_map(|value| value.get(host_field_name))
            .filter_map(|host| host.as_str())
            .any(|host| regex.is_match(host.as_bytes()));
        Some(Value::Integer(i64::from(found)))
    }

    fn network_http_get(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        search_http_request(ctx, args, true, false)
    }

    fn network_http_post(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        search_http_request(ctx, args, false, true)
    }

    fn network_http_request(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        search_http_request(ctx, args, true, true)
    }

    fn network_http_user_agent(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Cuckoo>()?;
        let http = data.network.as_ref()?.get("http")?.as_array()?;

        let mut args = args.into_iter();
        let regex: Regex = args.next()?.try_into().ok()?;

        let found = http
            .iter()
            .filter_map(|req| req.get("user-agent"))
            .filter_map(|user_agent| user_agent.as_str())
            .any(|user_agent| regex.is_match(user_agent.as_bytes()));
        Some(Value::Integer(i64::from(found)))
    }

    fn network_host(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Cuckoo>()?;
        let hosts = data.network.as_ref()?.get("hosts")?.as_array()?;

        let mut args = args.into_iter();
        let regex: Regex = args.next()?.try_into().ok()?;

        let found = hosts
            .iter()
            .filter_map(|host| host.as_str())
            .any(|host| regex.is_match(host.as_bytes()));
        Some(Value::Integer(i64::from(found)))
    }

    fn network_tcp(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Cuckoo>()?;
        let tcp = data.network.as_ref()?.get("tcp")?.as_array()?;

        search_tcp_udp(args, tcp)
    }

    fn network_udp(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Cuckoo>()?;
        let udp = data.network.as_ref()?.get("udp")?.as_array()?;

        search_tcp_udp(args, udp)
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

fn search_http_request(
    ctx: &mut EvalContext,
    args: Vec<Value>,
    method_get: bool,
    method_post: bool,
) -> Option<Value> {
    let data = ctx.module_data.get::<Cuckoo>()?;
    let http = data.network.as_ref()?.get("http")?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    let found = http
        .iter()
        .filter_map(|req| parse_http_request(req))
        .any(|(uri, method)| {
            ((method_get && method.eq_ignore_ascii_case("get"))
                || (method_post && method.eq_ignore_ascii_case("post")))
                && regex.is_match(uri.as_bytes())
        });
    Some(Value::Integer(i64::from(found)))
}

fn parse_http_request(request: &serde_json::Value) -> Option<(&str, &str)> {
    let uri = request.get("uri")?.as_str()?;
    let method = request.get("method")?.as_str()?;
    Some((uri, method))
}

fn search_tcp_udp(args: Vec<Value>, values: &[serde_json::Value]) -> Option<Value> {
    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;
    let port: i64 = args.next()?.try_into().ok()?;

    let found = values
        .iter()
        .filter_map(|req| parse_tcp_udp(req))
        .any(|(dst, dport)| dport == port && regex.is_match(dst.as_bytes()));
    Some(Value::Integer(i64::from(found)))
}

fn parse_tcp_udp(request: &serde_json::Value) -> Option<(&str, i64)> {
    let dst = request.get("dst")?.as_str()?;
    let dport = request.get("dport")?.as_number()?.as_i64()?;
    Some((dst, dport))
}
