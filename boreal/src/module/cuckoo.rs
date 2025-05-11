use std::collections::HashMap;

use crate::regex::Regex;

use super::{EvalContext, Module, ModuleData, StaticValue, Type, Value};

/// `cuckoo` module.
///
/// To use the module, the json report must be provided before the scan:
///
/// ```
/// use boreal::module::{Cuckoo, CuckooData};
/// use boreal::compiler::CompilerBuilder;
///
/// let mut compiler = CompilerBuilder::new().add_module(Cuckoo).build();
/// compiler.add_rules_str(r#"
/// import "cuckoo"
///
/// rule a {
///     condition: cuckoo.network.host(/crates.io/)
/// }"#).unwrap();
/// let mut scanner = compiler.finalize();
///
/// let report = r#"{ "network": { "hosts": ["crates.io"] } }"#;
/// let cuckoo_data = CuckooData::from_json_report(report).unwrap();
/// scanner.set_module_data::<Cuckoo>(cuckoo_data);
///
/// let result = scanner.scan_mem(b"").unwrap();
/// assert_eq!(result.rules.len(), 1);
/// ```
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
}

/// Data used by the cuckoo module.
///
/// This data must be provided by a call to
/// [`Scanner::set_module_data`](crate::scanner::Scanner::set_module_data).
pub struct CuckooData {
    /// The "network" key in the parsed json report.
    network: Option<serde_json::Value>,

    /// The "behavior.summary" key in the parsed json report.
    summary: Option<serde_json::Value>,
}

impl CuckooData {
    /// Build the data needed by the cuckoo module from a json report.
    ///
    /// Returns None if the report could not be parsed.
    pub fn from_json_report(report: &str) -> Option<Self> {
        let mut report = serde_json::from_str::<serde_json::Value>(report).ok()?;

        let network = report.get_mut("network").map(serde_json::Value::take);
        let summary = report
            .get_mut("behavior")
            .and_then(|v| v.get_mut("summary"))
            .map(serde_json::Value::take);

        Some(Self { network, summary })
    }
}

impl ModuleData for Cuckoo {
    type PrivateData = ();
    type UserData = CuckooData;
}

impl Cuckoo {
    fn network_dns_lookup(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_dns(ctx, args))
    }

    fn network_http_get(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_http_request(ctx, args, true, false))
    }

    fn network_http_post(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_http_request(ctx, args, false, true))
    }

    fn network_http_request(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_http_request(ctx, args, true, true))
    }

    fn network_http_user_agent(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_http_user_agent(ctx, args))
    }

    fn network_host(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_host(ctx, args))
    }

    fn network_tcp(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_tcp_udp(ctx, args, "tcp"))
    }

    fn network_udp(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(search_tcp_udp(ctx, args, "udp"))
    }

    fn registry_key_access(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(regex_matches_summary_string_array(ctx, args, "keys"))
    }

    fn filesystem_file_access(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(regex_matches_summary_string_array(ctx, args, "files"))
    }

    fn sync_mutex(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        opt_bool_to_value(regex_matches_summary_string_array(ctx, args, "mutexes"))
    }
}

#[allow(clippy::unnecessary_wraps)]
fn opt_bool_to_value(v: Option<bool>) -> Option<Value> {
    match v {
        Some(true) => Some(Value::Integer(1)),
        Some(false) | None => Some(Value::Integer(0)),
    }
}

fn search_dns(ctx: &mut EvalContext, args: Vec<Value>) -> Option<bool> {
    let data = ctx.module_data.get_user_data::<Cuckoo>()?;
    let network = data.network.as_ref()?;
    let (values, host_field_name) = match network.get("domains") {
        Some(v) => (v.as_array()?, "domain"),
        None => (network.get("dns")?.as_array()?, "hostname"),
    };

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    Some(
        values
            .iter()
            .filter_map(|value| {
                // For some reason, YARA parses the "ip" key even though it does not use it.
                // This means it considers objects without this key as invalid and will not
                // consider them.
                // It's unclear if this is voluntary or not, but align with this behavior
                // for now.
                let _ip = value.get("ip")?;
                value.get(host_field_name)
            })
            .filter_map(|host| host.as_str())
            .any(|host| regex.is_match(host.as_bytes())),
    )
}

fn regex_matches_summary_string_array(
    ctx: &mut EvalContext,
    args: Vec<Value>,
    key_name: &str,
) -> Option<bool> {
    let data = ctx.module_data.get_user_data::<Cuckoo>()?;
    let values = data.summary.as_ref()?.get(key_name)?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    Some(
        values
            .iter()
            .filter_map(|v| v.as_str())
            .any(|name| regex.is_match(name.as_bytes())),
    )
}

fn search_http_request(
    ctx: &mut EvalContext,
    args: Vec<Value>,
    method_get: bool,
    method_post: bool,
) -> Option<bool> {
    let data = ctx.module_data.get_user_data::<Cuckoo>()?;
    let http = data.network.as_ref()?.get("http")?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    Some(
        http.iter()
            .filter_map(|req| parse_http_request(req))
            .any(|(uri, method)| {
                ((method_get && method.eq_ignore_ascii_case("get"))
                    || (method_post && method.eq_ignore_ascii_case("post")))
                    && regex.is_match(uri.as_bytes())
            }),
    )
}

fn parse_http_request(request: &serde_json::Value) -> Option<(&str, &str)> {
    let uri = request.get("uri")?.as_str()?;
    let method = request.get("method")?.as_str()?;
    Some((uri, method))
}

fn search_http_user_agent(ctx: &mut EvalContext, args: Vec<Value>) -> Option<bool> {
    let data = ctx.module_data.get_user_data::<Cuckoo>()?;
    let http = data.network.as_ref()?.get("http")?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    Some(
        http.iter()
            .filter_map(|req| req.get("user-agent"))
            .filter_map(|user_agent| user_agent.as_str())
            .any(|user_agent| regex.is_match(user_agent.as_bytes())),
    )
}

fn search_host(ctx: &mut EvalContext, args: Vec<Value>) -> Option<bool> {
    let data = ctx.module_data.get_user_data::<Cuckoo>()?;
    let hosts = data.network.as_ref()?.get("hosts")?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;

    Some(
        hosts
            .iter()
            .filter_map(|host| host.as_str())
            .any(|host| regex.is_match(host.as_bytes())),
    )
}

fn search_tcp_udp(ctx: &mut EvalContext, args: Vec<Value>, key: &str) -> Option<bool> {
    let data = ctx.module_data.get_user_data::<Cuckoo>()?;
    let values = data.network.as_ref()?.get(key)?.as_array()?;

    let mut args = args.into_iter();
    let regex: Regex = args.next()?.try_into().ok()?;
    let port: i64 = args.next()?.try_into().ok()?;

    Some(
        values
            .iter()
            .filter_map(|req| parse_tcp_udp(req))
            .any(|(dst, dport)| dport == port && regex.is_match(dst.as_bytes())),
    )
}

fn parse_tcp_udp(request: &serde_json::Value) -> Option<(&str, i64)> {
    let dst = request.get("dst")?.as_str()?;
    let dport = request.get("dport")?.as_number()?.as_i64()?;
    Some((dst, dport))
}
