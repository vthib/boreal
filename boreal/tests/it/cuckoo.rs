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
