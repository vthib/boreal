use std::time::Duration;

use boreal::scanner::{ScanCallbackResult, ScanError, ScanEvent, ScanParams};
use boreal::{Compiler, Scanner};

#[track_caller]
fn check_rule_match(event: &ScanEvent, rule_name: &str, namespace: Option<&str>) {
    let res = match event {
        ScanEvent::RuleMatch(m) => m.name == rule_name && m.namespace == namespace,
    };
    assert!(
        res,
        "event {:?} is not a match for rule {:?}:{}",
        event, namespace, rule_name
    );
}

fn scan_mem<'scanner>(scanner: &'scanner Scanner, mem: &[u8]) -> Vec<ScanEvent<'scanner>> {
    let mut events = Vec::new();
    scanner
        .scan_mem_with_callback(mem, |event| {
            events.push(event);
            ScanCallbackResult::Continue
        })
        .unwrap();
    events
}

#[test]
fn test_scan_mem_with_callback() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
rule a { condition: true }
rule b { condition: false }
rule c {
    strings:
        $ = "abcde"
    condition:
        any of them
}
"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    let events = scan_mem(&scanner, b"<abcdef>");
    assert_eq!(events.len(), 2);
    check_rule_match(&events[0], "a", None);
    check_rule_match(&events[1], "c", None);

    let events = scan_mem(&scanner, b"<abef>");
    assert_eq!(events.len(), 1);
    check_rule_match(&events[0], "a", None);
}

#[test]
fn test_scan_mem_with_callback_global_rule() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
global rule a {
    strings:
        $ = "abc"
    condition:
        any of them
}
global rule b {
    strings:
        $ = "def"
    condition:
        any of them
}
rule c {
    strings:
        $ = "ghi"
    condition:
        any of them
}
"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    let events = scan_mem(&scanner, b"<abc>");
    assert_eq!(events.len(), 0);

    let events = scan_mem(&scanner, b"<abcdef>");
    assert_eq!(events.len(), 2);
    check_rule_match(&events[0], "a", None);
    check_rule_match(&events[1], "b", None);

    let events = scan_mem(&scanner, b"<abcdefghi>");
    assert_eq!(events.len(), 3);
    check_rule_match(&events[0], "a", None);
    check_rule_match(&events[1], "b", None);
    check_rule_match(&events[2], "c", None);

    let events = scan_mem(&scanner, b"<defghi>");
    assert_eq!(events.len(), 0);
}

#[test]
fn test_scan_mem_with_callback_global_rule_no_eval() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
global rule a { condition: filesize >= 5 }
global rule b { condition: filesize >= 3 }
rule c { condition: filesize > 7 }
"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    let events = scan_mem(&scanner, b"12");
    assert_eq!(events.len(), 0);
    let events = scan_mem(&scanner, b"123");
    assert_eq!(events.len(), 0);
    let events = scan_mem(&scanner, b"12345");
    assert_eq!(events.len(), 2);
    check_rule_match(&events[0], "a", None);
    check_rule_match(&events[1], "b", None);

    let events = scan_mem(&scanner, b"12345678");
    assert_eq!(events.len(), 3);
    check_rule_match(&events[0], "a", None);
    check_rule_match(&events[1], "b", None);
    check_rule_match(&events[2], "c", None);
}

#[test]
fn test_scan_mem_with_callback_no_eval_timeout() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
global rule a { condition: true }
rule b { condition: filesize >= 3 }
rule c {
    condition:
        for all i in (0..9223372036854775807) : (
            for all j in (0..9223372036854775807) : (
                for all k in (0..9223372036854775807) : (
                    for all l in (0..9223372036854775807) : (
                        i + j + k + l >= 0
                    )
                )
            )
        )
}"#,
        )
        .unwrap();
    let mut scanner = compiler.into_scanner();
    scanner
        .set_scan_params(ScanParams::default().timeout_duration(Some(Duration::from_millis(100))));

    let mut events = Vec::new();
    let res = scanner.scan_mem_with_callback(b"123", |event| {
        events.push(event);
        ScanCallbackResult::Continue
    });
    assert!(matches!(res, Err(ScanError::Timeout)));
    assert_eq!(events.len(), 2);
    check_rule_match(&events[0], "a", None);
    check_rule_match(&events[1], "b", None);
}
