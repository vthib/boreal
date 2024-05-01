use crate::utils::Checker;
use boreal::module::{Cuckoo, CuckooData};

#[track_caller]
fn test(cond: &str, report: Option<&str>) {
    let checker = Checker::new(&format!(
        r#"
import "cuckoo"

rule test {{
    condition: {cond}
}}"#,
    ));
    let mut scanner = checker.scanner();
    if let Some(report) = report {
        scanner
            .scanner
            .set_module_data::<Cuckoo>(CuckooData::from_json_report(report).unwrap());
    }

    scanner.check_boreal(b"", true);

    let mut report = report.map(ToOwned::to_owned);

    // Also check for yara
    if let Some(yara_scanner) = scanner.yara_scanner.as_mut() {
        let mut results = Vec::new();
        yara_scanner
            .scan_mem_callback(b"", |msg| {
                match msg {
                    yara::CallbackMsg::ImportModule(mut module) => {
                        if module.name() == Some(b"cuckoo") {
                            if let Some(report) = &mut report {
                                // Safety: report is alive for longer than the scan.
                                unsafe {
                                    module
                                        .set_module_data(report.as_mut_ptr().cast(), report.len());
                                }
                            }
                        }
                    }
                    yara::CallbackMsg::RuleMatching(rule) => results.push(rule),
                    _ => (),
                };
                yara::CallbackReturn::Continue
            })
            .unwrap();
        assert!(!results.is_empty(), "comformity test failed for libyara");
    }
}

#[test]
fn test_registry_key_access() {
    // undefined if no report is provided
    test("cuckoo.registry.key_access(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.registry.key_access(/^a/) == 1",
        Some(r#"{ "behavior": { "summary": { "keys": ["key_access", "abcde"] } } }"#),
    );

    // unmatched case
    test(
        "cuckoo.registry.key_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "keys": ["key_access"] } } }"#),
    );

    // Bad json shape cases
    test(
        "cuckoo.registry.key_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "keys": "abcde" } } }"#),
    );
    test(
        "cuckoo.registry.key_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "key": ["abcde"] } } }"#),
    );
    test(
        "cuckoo.registry.key_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": {} } }"#),
    );
    test(
        "cuckoo.registry.key_access(/^a/) == 0",
        Some(r#"{ "behavior": {} }"#),
    );
    test(
        "cuckoo.registry.key_access(/^a/) == 0",
        Some(r#"{ "beh": {} }"#),
    );
    test("cuckoo.registry.key_access(/^a/) == 0", Some(r#"["beh"]"#));
}

#[test]
fn test_filesystem_file_access() {
    // undefined if no report is provided
    test("cuckoo.filesystem.file_access(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.filesystem.file_access(/^a/) == 1",
        Some(r#"{ "behavior": { "summary": { "files": ["file_access", "abcde"] } } }"#),
    );

    // unmatched case
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "files": ["file_access"] } } }"#),
    );

    // Bad json shape cases
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "files": "abcde" } } }"#),
    );
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "file": ["abcde"] } } }"#),
    );
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": {} } }"#),
    );
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"{ "behavior": {} }"#),
    );
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"{ "beh": {} }"#),
    );
    test(
        "cuckoo.filesystem.file_access(/^a/) == 0",
        Some(r#"["beh"]"#),
    );
}

#[test]
fn test_sync_mutex() {
    // undefined if no report is provided
    test("cuckoo.sync.mutex(/abc/) == 0", None);

    // valid case
    test(
        "cuckoo.sync.mutex(/^a/) == 1",
        Some(r#"{ "behavior": { "summary": { "mutexes": ["mutex", "abcde"] } } }"#),
    );

    // unmatched case
    test(
        "cuckoo.sync.mutex(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "mutexes": ["mutex"] } } }"#),
    );

    // Bad json shape cases
    test(
        "cuckoo.sync.mutex(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "mutexes": "abcde" } } }"#),
    );
    test(
        "cuckoo.sync.mutex(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": { "mutex": ["abcde"] } } }"#),
    );
    test(
        "cuckoo.sync.mutex(/^a/) == 0",
        Some(r#"{ "behavior": { "summary": {} } }"#),
    );
    test(
        "cuckoo.sync.mutex(/^a/) == 0",
        Some(r#"{ "behavior": {} }"#),
    );
    test("cuckoo.sync.mutex(/^a/) == 0", Some(r#"{ "beh": {} }"#));
    test("cuckoo.sync.mutex(/^a/) == 0", Some(r#"["beh"]"#));
}

#[test]
fn test_network_http_get() {
    // undefined if no report is provided
    test("cuckoo.network.http_get(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.network.http_get(/^a/) == 1",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "post" },
                { "uri": "abcde", "method": "get" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
    // unmatch case
    test(
        "cuckoo.network.http_get(/^a/) == 0",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "post" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
}

#[test]
fn test_network_http_post() {
    // undefined if no report is provided
    test("cuckoo.network.http_post(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.network.http_post(/^a/) == 1",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "post" },
                { "uri": "abcde", "method": "get" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
    // unmatch case
    test(
        "cuckoo.network.http_post(/^a/) == 0",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "get" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
}

#[test]
fn test_network_http_request() {
    // undefined if no report is provided
    test("cuckoo.network.http_request(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.network.http_request(/^a/) == 1",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "post" },
                { "uri": "abcde", "method": "get" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.http_request(/^a/) == 1",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "post" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.http_request(/^a/) == 1",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde", "method": "get" },
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
    // unmatch case
    test(
        "cuckoo.network.http_request(/^a/) == 0",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "defgh", "method": "get" },
                { "uri": "defgh", "method": "post" }
            ]}
        }"#,
        ),
    );
}

#[test]
fn test_network_http_request_bad_shapes() {
    let cond = r#"
        cuckoo.network.http_get(/^a/) == 0 and
        cuckoo.network.http_post(/^a/) == 0 and
        cuckoo.network.http_request(/^a/) == 0
    "#;

    // test bad json shape cases
    test(
        cond,
        Some(r#"{ "network": { "http": [{ "ura": "abcdef", "method": "get" }] } }"#),
    );
    test(
        cond,
        Some(r#"{ "network": { "http": [{ "uri": "abcdef", "metho": "get" }] } }"#),
    );
    test(
        cond,
        Some(r#"{ "network": { "http": [{ "uri": "abcdef", "method": true }] } }"#),
    );
    test(
        cond,
        Some(r#"{ "network": { "http": [{ "uri": true, "method": "get" }] } }"#),
    );
    test(
        cond,
        Some(r#"{ "network": { "http": { "uri": "abc", "method": "get" } } }"#),
    );

    test(
        cond,
        Some(r#"{ "network": { "htt": [{ "uri": "abc", "method": "get" }] } }"#),
    );
    test(cond, Some(r#"{ "network": true }"#));
    test(
        cond,
        Some(r#"{ "net": { "http": [{ "uri": "abc", "method": "get" }] } }"#),
    );
    test(cond, Some(r#"[{ "uri": "abc", "method": "get" }]"#));
}

#[test]
fn test_network_http_user_agent() {
    // undefined if no report is provided
    test("cuckoo.network.http_user_agent(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.network.http_user_agent(/^a/) == 1",
        Some(
            r#"{
            "network": { "http": [
                { "user-agent": "gheif" },
                { "user-agent": "abcde" }
            ]}
        }"#,
        ),
    );
    // unmatched cases
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(
            r#"{
            "network": { "http": [
                { "user-agent": "gheif" }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(
            r#"{
            "network": { "http": [
                { "uri": "abcde" }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(r#"{ "network": { "http": [] } }"#),
    );

    // bad shapes
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(r#"{ "network": { "http": [ { "user-agent": false } ] } }"#),
    );
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(r#"{ "network": { "htt": [{ "user-agent": "abc" }] } }"#),
    );
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(r#"{ "network": { "http": "abc" } }"#),
    );
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(r#"{ "net": { "http": [{ "user-agent": "abc" }] } }"#),
    );
    test(
        "cuckoo.network.http_user_agent(/^a/) == 0",
        Some(r#"[{ "user-agent": "abc" }]"#),
    );
}

#[test]
fn test_network_host() {
    // undefined if no report is provided
    test("cuckoo.network.host(/abc/) == 0", None);

    // valid case
    test(
        "cuckoo.network.host(/^a/) == 1",
        Some(r#"{ "network": { "hosts": ["host", "abcde"] } }"#),
    );

    // unmatched case
    test(
        "cuckoo.network.host(/^a/) == 0",
        Some(r#"{ "network": { "hosts": ["host"] } }"#),
    );

    // Bad json shape cases
    test(
        "cuckoo.network.host(/^a/) == 0",
        Some(r#"{ "network": { "hosts": "abcde" } }"#),
    );
    test(
        "cuckoo.network.host(/^a/) == 0",
        Some(r#"{ "network": { "host": ["abcde"] } }"#),
    );
    test(
        "cuckoo.network.host(/^a/) == 0",
        Some(r#"{ "network": {} }"#),
    );
    test("cuckoo.network.host(/^a/) == 0", Some(r#"{ "net": {} }"#));
    test("cuckoo.network.host(/^a/) == 0", Some(r#"["net"]"#));
}

#[test]
fn test_network_tcp() {
    // undefined if no report is provided
    test("cuckoo.network.tcp(/abc/, 23) == 0", None);

    // valid cases
    test(
        "cuckoo.network.tcp(/^a/, 23) == 1",
        Some(
            r#"{
            "network": { "tcp": [
                { "dst": "abcde", "dport": "23" },
                { "dst": false, "dport": 23 },
                { "dst": "gheif", "dport": 23 },
                { "dst": "abcde", "dport": 24 },
                { "dst": "abcde", "dport": 23 },
                { "dst": "gheif", "dport": 24 }
            ]}
        }"#,
        ),
    );
    // unmatched cases
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(
            r#"{
            "network": { "tcp": [
                { "dst": "abcde", "dport": "23" },
                { "dst": false, "dport": 23 },
                { "dst": "gheif", "dport": 23 },
                { "dst": "abcde", "dport": 24 },
                { "dst": "gheif", "dport": 24 }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(
            r#"{
            "network": { "tcp": [
                { "dst": "abcde" },
                { "dport": 23 },
                { "dst": "abcde", "dport": "23" }
            ]}
        }"#,
        ),
    );

    // test bad json shape cases
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(r#"{ "network": { "tcp": ["abc"] } }"#),
    );
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(r#"{ "network": { "tc": [{ "dst": "abc", "dport": 23 }] } }"#),
    );
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(r#"{ "network": { "tcp": { "dst": "abc", "dport": 23 } } }"#),
    );
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(r#"{ "network": { "tcp": "abc" } }"#),
    );
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(r#"{ "net": [{ "tcp": { "dst": "abc", "dport": 23 } }] }"#),
    );
    test(
        "cuckoo.network.tcp(/^a/, 23) == 0",
        Some(r#"[{ "dst": "abc", "dport": 23 }]"#),
    );
}

#[test]
fn test_network_udp() {
    // undefined if no report is provided
    test("cuckoo.network.udp(/abc/, 23) == 0", None);

    // valid cases
    test(
        "cuckoo.network.udp(/^a/, 23) == 1",
        Some(
            r#"{
            "network": { "udp": [
                { "dst": "abcde", "dport": "23" },
                { "dst": false, "dport": 23 },
                { "dst": "gheif", "dport": 23 },
                { "dst": "abcde", "dport": 24 },
                { "dst": "abcde", "dport": 23 },
                { "dst": "gheif", "dport": 24 }
            ]}
        }"#,
        ),
    );
    // unmatched cases
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(
            r#"{
            "network": { "udp": [
                { "dst": "abcde", "dport": "23" },
                { "dst": false, "dport": 23 },
                { "dst": "abcde", "dport": -23 },
                { "dst": "abcde", "dport": 23.0 },
                { "dst": "gheif", "dport": 23 },
                { "dst": "abcde", "dport": 24 },
                { "dst": "gheif", "dport": 24 }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(
            r#"{
            "network": { "udp": [
                { "dst": "abcde" },
                { "dport": 23 },
                { "dst": "abcde", "dport": "23" }
            ]}
        }"#,
        ),
    );

    // test bad json shape cases
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(r#"{ "network": { "udp": ["abc"] } }"#),
    );
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(r#"{ "network": { "ud": [{ "dst": "abc", "dport": 23 }] } }"#),
    );
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(r#"{ "network": { "udp": { "dst": "abc", "dport": 23 } } }"#),
    );
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(r#"{ "network": { "udp": "abc" } }"#),
    );
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(r#"{ "net": [{ "udp": { "dst": "abc", "dport": 23 } }] }"#),
    );
    test(
        "cuckoo.network.udp(/^a/, 23) == 0",
        Some(r#"[{ "dst": "abc", "dport": 23 }]"#),
    );
}

#[test]
fn test_network_dns_lookup() {
    // undefined if no report is provided
    test("cuckoo.network.dns_lookup(/abc/) == 0", None);

    // valid cases
    test(
        "cuckoo.network.dns_lookup(/^a/) == 1",
        Some(
            r#"{
            "network": { "domains": [
                { "ip": "a", "domain": "gheif" },
                { "ip": "a", "domain": "abcde" }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 1",
        Some(
            r#"{
            "network": { "dns": [
                { "ip": "a", "hostname": "gheif" },
                { "ip": "a", "hostname": "abcde" }
            ]}
        }"#,
        ),
    );
    // unmatched cases
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(
            r#"{
            "network": { "domains": [
                { "ip": "a", "domain": "gheif" },
                { "ip": "a", "hostname": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(
            r#"{
            "network": { "dns": [
                { "ip": "a", "hostname": "gheif" },
                { "ip": "a", "domain": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(
            r#"{
            "network": { "dom": [
                { "ip": "a", "hostname": "abcde" },
                { "ip": "a", "domain": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(
            r#"{
            "network": { "domains": [
                { "domain": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(
            r#"{
            "network": { "dns": [
                { "hostname": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"{ "network": { "domains": [] } }"#),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"{ "network": { "dns": [] } }"#),
    );

    // bad shapes
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"{ "network": { "domains": false } }"#),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"{ "network": { "dns": false } }"#),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"{ "network": true }"#),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"{ "net": { "domains": [{ "domain": "abc" }] } }"#),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(r#"[{ "domain": "abc" }]"#),
    );
}

#[test]
fn test_invalid_data() {
    // YARA makes the scan fail if the module data is not parsable.
    // This is also guaranteed in boreal by the fact a CuckooData object cannot be built.
    assert!(CuckooData::from_json_report(r#"{ "invalid": true "#).is_none());
}
