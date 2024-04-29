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
    let mut scanner = checker.scanner().scanner;
    if let Some(report) = report {
        scanner.set_module_data::<Cuckoo>(CuckooData {
            json_report: report.to_owned(),
        });
    }

    let res = scanner.scan_mem(b"").unwrap();
    assert!(!res.matched_rules.is_empty());
}

#[test]
fn test_registry_key_access() {
    // undefined if no report is provided
    test("not defined cuckoo.registry.key_access(/abc/)", None);

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
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"{ "behavior": { "summary": { "keys": "abcde" } } }"#),
    );
    test(
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"{ "behavior": { "summary": { "key": ["abcde"] } } }"#),
    );
    test(
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"{ "behavior": { "summary": {} } }"#),
    );
    test(
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"{ "behavior": {} }"#),
    );
    test(
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"{ "beh": {} }"#),
    );
    test(
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"["beh"]"#),
    );
    test(
        "not defined cuckoo.registry.key_access(/^a/)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_filesystem_file_access() {
    // undefined if no report is provided
    test("not defined cuckoo.filesystem.file_access(/abc/)", None);

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
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"{ "behavior": { "summary": { "files": "abcde" } } }"#),
    );
    test(
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"{ "behavior": { "summary": { "file": ["abcde"] } } }"#),
    );
    test(
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"{ "behavior": { "summary": {} } }"#),
    );
    test(
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"{ "behavior": {} }"#),
    );
    test(
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"{ "beh": {} }"#),
    );
    test(
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"["beh"]"#),
    );
    test(
        "not defined cuckoo.filesystem.file_access(/^a/)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_sync_mutex() {
    // undefined if no report is provided
    test("not defined cuckoo.sync.mutex(/abc/)", None);

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
        "not defined cuckoo.sync.mutex(/^a/)",
        Some(r#"{ "behavior": { "summary": { "mutexes": "abcde" } } }"#),
    );
    test(
        "not defined cuckoo.sync.mutex(/^a/)",
        Some(r#"{ "behavior": { "summary": { "mutex": ["abcde"] } } }"#),
    );
    test(
        "not defined cuckoo.sync.mutex(/^a/)",
        Some(r#"{ "behavior": { "summary": {} } }"#),
    );
    test(
        "not defined cuckoo.sync.mutex(/^a/)",
        Some(r#"{ "behavior": {} }"#),
    );
    test(
        "not defined cuckoo.sync.mutex(/^a/)",
        Some(r#"{ "beh": {} }"#),
    );
    test("not defined cuckoo.sync.mutex(/^a/)", Some(r#"["beh"]"#));
    test(
        "not defined cuckoo.sync.mutex(/^a/)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_network_http_get() {
    // undefined if no report is provided
    test("not defined cuckoo.network.http_get(/abc/)", None);

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
    test("not defined cuckoo.network.http_post(/abc/)", None);

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
    test("not defined cuckoo.network.http_request(/abc/)", None);

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
    let false_cond = r#"
        cuckoo.network.http_get(/^a/) == 0 and
        cuckoo.network.http_post(/^a/) == 0 and
        cuckoo.network.http_request(/^a/) == 0
    "#;
    let not_defined_cond = r#"
        not defined cuckoo.network.http_get(/^a/) and
        not defined cuckoo.network.http_post(/^a/) and
        not defined cuckoo.network.http_request(/^a/)
    "#;

    // test bad json shape cases
    test(
        false_cond,
        Some(r#"{ "network": { "http": [{ "ura": "abcdef", "method": "get" }] } }"#),
    );
    test(
        false_cond,
        Some(r#"{ "network": { "http": [{ "uri": "abcdef", "metho": "get" }] } }"#),
    );
    test(
        false_cond,
        Some(r#"{ "network": { "http": [{ "uri": "abcdef", "method": true }] } }"#),
    );
    test(
        false_cond,
        Some(r#"{ "network": { "http": [{ "uri": true, "method": "get" }] } }"#),
    );
    test(
        not_defined_cond,
        Some(r#"{ "network": { "http": { "uri": "abc", "method": "get" } } }"#),
    );

    test(
        not_defined_cond,
        Some(r#"{ "network": { "htt": [{ "uri": "abc", "method": "get" }] } }"#),
    );
    test(not_defined_cond, Some(r#"{ "network": true }"#));
    test(
        not_defined_cond,
        Some(r#"{ "net": { "http": [{ "uri": "abc", "method": "get" }] } }"#),
    );
    test(
        not_defined_cond,
        Some(r#"[{ "uri": "abc", "method": "get" }]"#),
    );
    test(not_defined_cond, Some(r#"{ "invalid": true "#));
}

#[test]
fn test_network_http_user_agent() {
    // undefined if no report is provided
    test("not defined cuckoo.network.http_user_agent(/abc/)", None);

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
        "not defined cuckoo.network.http_user_agent(/^a/)",
        Some(r#"{ "network": { "htt": [{ "user-agent": "abc" }] } }"#),
    );
    test(
        "not defined cuckoo.network.http_user_agent(/^a/)",
        Some(r#"{ "network": { "http": "abc" } }"#),
    );
    test(
        "not defined cuckoo.network.http_user_agent(/^a/)",
        Some(r#"{ "net": { "http": [{ "user-agent": "abc" }] } }"#),
    );
    test(
        "not defined cuckoo.network.http_user_agent(/^a/)",
        Some(r#"[{ "user-agent": "abc" }]"#),
    );
    test(
        "not defined cuckoo.network.http_user_agent(/^a/)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_network_host() {
    // undefined if no report is provided
    test("not defined cuckoo.network.host(/abc/)", None);

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
        "not defined cuckoo.network.host(/^a/)",
        Some(r#"{ "network": { "hosts": "abcde" } }"#),
    );
    test(
        "not defined cuckoo.network.host(/^a/)",
        Some(r#"{ "network": { "host": ["abcde"] } }"#),
    );
    test(
        "not defined cuckoo.network.host(/^a/)",
        Some(r#"{ "network": {} }"#),
    );
    test(
        "not defined cuckoo.network.host(/^a/)",
        Some(r#"{ "net": {} }"#),
    );
    test("not defined cuckoo.network.host(/^a/)", Some(r#"["net"]"#));
    test(
        "not defined cuckoo.network.host(/^a/)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_network_tcp() {
    // undefined if no report is provided
    test("not defined cuckoo.network.tcp(/abc/, 23)", None);

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
        "not defined cuckoo.network.tcp(/^a/, 23)",
        Some(r#"{ "network": { "tc": [{ "dst": "abc", "dport": 23 }] } }"#),
    );
    test(
        "not defined cuckoo.network.tcp(/^a/, 23)",
        Some(r#"{ "network": { "tcp": { "dst": "abc", "dport": 23 } } }"#),
    );
    test(
        "not defined cuckoo.network.tcp(/^a/, 23)",
        Some(r#"{ "network": { "tcp": "abc" } }"#),
    );
    test(
        "not defined cuckoo.network.tcp(/^a/, 23)",
        Some(r#"{ "net": [{ "tcp": { "dst": "abc", "dport": 23 } }] }"#),
    );
    test(
        "not defined cuckoo.network.tcp(/^a/, 23)",
        Some(r#"[{ "dst": "abc", "dport": 23 }]"#),
    );
    test(
        "not defined cuckoo.network.tcp(/^a/, 23)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_network_udp() {
    // undefined if no report is provided
    test("not defined cuckoo.network.udp(/abc/, 23)", None);

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
        "not defined cuckoo.network.udp(/^a/, 23)",
        Some(r#"{ "network": { "ud": [{ "dst": "abc", "dport": 23 }] } }"#),
    );
    test(
        "not defined cuckoo.network.udp(/^a/, 23)",
        Some(r#"{ "network": { "udp": { "dst": "abc", "dport": 23 } }] }"#),
    );
    test(
        "not defined cuckoo.network.udp(/^a/, 23)",
        Some(r#"{ "network": { "udp": "abc" } }"#),
    );
    test(
        "not defined cuckoo.network.udp(/^a/, 23)",
        Some(r#"{ "net": [{ "udp": { "dst": "abc", "dport": 23 } }] }"#),
    );
    test(
        "not defined cuckoo.network.udp(/^a/, 23)",
        Some(r#"[{ "dst": "abc", "dport": 23 }]"#),
    );
    test(
        "not defined cuckoo.network.udp(/^a/, 23)",
        Some(r#"{ "invalid": true "#),
    );
}

#[test]
fn test_network_dns_lookup() {
    // undefined if no report is provided
    test("not defined cuckoo.network.dns_lookup(/abc/)", None);

    // valid cases
    test(
        "cuckoo.network.dns_lookup(/^a/) == 1",
        Some(
            r#"{
            "network": { "domains": [
                { "domain": "gheif" },
                { "domain": "abcde" }
            ]}
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 1",
        Some(
            r#"{
            "network": { "dns": [
                { "hostname": "gheif" },
                { "hostname": "abcde" }
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
                { "domain": "gheif" },
                { "hostname": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "cuckoo.network.dns_lookup(/^a/) == 0",
        Some(
            r#"{
            "network": { "dns": [
                { "hostname": "gheif" },
                { "domain": "abcde" }
            ] }
        }"#,
        ),
    );
    test(
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(
            r#"{
            "network": { "dom": [
                { "hostname": "abcde" },
                { "domain": "abcde" }
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
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(r#"{ "network": { "domains": false } }"#),
    );
    test(
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(r#"{ "network": { "dns": false } }"#),
    );
    test(
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(r#"{ "network": true"#),
    );
    test(
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(r#"{ "net": { "domains": [{ "domain": "abc" }] } }"#),
    );
    test(
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(r#"[{ "domain": "abc" }]"#),
    );
    test(
        "not defined cuckoo.network.dns_lookup(/^a/)",
        Some(r#"{ "invalid": true "#),
    );
}
