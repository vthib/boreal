//! Tests for the scanner API.

use std::io::{Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use boreal::compiler::CompilerBuilder;
use boreal::MetadataValue;

// An import is reused in the same namespace
#[test]
fn test_scan_file() {
    let mut compiler = boreal::Compiler::new();
    compiler
        .add_rules_str(
            r#"
rule bar {
    strings:
        $a = "abc"
    condition:
        $a
}"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();
    assert!(scanner.scan_file("not_existing").is_err());

    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().write_all(b"zyxabcxy").unwrap();
    let result = scanner.scan_file(file.path()).unwrap();
    assert_eq!(result.matched_rules.len(), 1);

    file.as_file().rewind().unwrap();
    file.as_file().write_all(b"zyxacxby").unwrap();
    let result = scanner.scan_file(file.path()).unwrap();
    assert_eq!(result.matched_rules.len(), 0);
}

// An import is reused in the same namespace
#[test]
fn test_add_rules_file_err() {
    let mut compiler = boreal::Compiler::new();
    let path = "non_existing";
    let err = compiler.add_rules_file(path).unwrap_err();
    assert!(err
        .to_short_description(path, "")
        .starts_with("error: Cannot read rules file non_existing: "));

    let err = compiler
        .add_rules_file_in_namespace(path, "ns")
        .unwrap_err();
    assert!(err
        .to_short_description(path, "")
        .starts_with("error: Cannot read rules file non_existing: "));
}

// An import is reused in the same namespace
#[test]
fn test_add_rules_str_err() {
    let mut compiler = boreal::Compiler::new();
    assert!(compiler.add_rules_file("z").is_err());
    assert!(compiler.add_rules_file_in_namespace("z", "ns").is_err());
}

#[test]
fn test_compiler_builder_replace_module() {
    static FIRST: AtomicBool = AtomicBool::new(false);
    static SECOND: AtomicBool = AtomicBool::new(false);

    let builder = CompilerBuilder::default();

    // Add the console module twice, to check the second one is used in place of the
    // first one.
    let builder = builder.add_module(boreal::module::Console::with_callback(|_| {
        FIRST.store(true, Ordering::SeqCst)
    }));
    let builder = builder.add_module(boreal::module::Console::with_callback(|_| {
        SECOND.store(true, Ordering::SeqCst)
    }));

    let mut compiler = builder.build();
    compiler
        .add_rules_str(
            r#"import "console"
rule a {
    condition:
        console.log("a")

}"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();
    scanner.scan_mem(b"").unwrap();

    assert!(!FIRST.load(Ordering::SeqCst));
    assert!(SECOND.load(Ordering::SeqCst));
}

#[test]
fn test_scanner_list_rules() {
    let mut compiler = boreal::Compiler::new();

    compiler
        .add_rules_str(
            r#"
global rule g {
    condition: true
}
private rule p: tag {
    meta:
        b = true
    condition: true
}
"#,
        )
        .unwrap();
    compiler
        .add_rules_str_in_namespace(
            r#"
private global rule pg: tag1 tag2 {
    meta:
        s = "str"
        i = -23
    condition: true
}

rule r: tag {
    condition: true
}
"#,
            "namespace",
        )
        .unwrap();

    let scanner = compiler.into_scanner();
    let rules: Vec<_> = scanner.rules().collect();

    assert_eq!(rules.len(), 4);

    let r0 = &rules[0];
    assert_eq!(r0.name, "g");
    assert_eq!(r0.namespace, None);
    assert_eq!(r0.tags.len(), 0);
    assert!(r0.is_global);
    assert!(!r0.is_private);
    assert_eq!(r0.metadatas.len(), 0);

    let r1 = &rules[1];
    assert_eq!(r1.name, "pg");
    assert_eq!(r1.namespace, Some("namespace"));
    assert_eq!(r1.tags, &["tag1", "tag2"]);
    assert!(r1.is_global);
    assert!(r1.is_private);
    assert_eq!(r1.metadatas.len(), 2);
    assert_eq!(scanner.get_string_symbol(r1.metadatas[0].name), "s");
    match r1.metadatas[0].value {
        MetadataValue::Bytes(b) => assert_eq!(scanner.get_bytes_symbol(b), b"str"),
        _ => panic!("invalid metadata {:?}", r1.metadatas[0]),
    };
    assert_eq!(scanner.get_string_symbol(r1.metadatas[1].name), "i");
    match r1.metadatas[1].value {
        MetadataValue::Integer(i) => assert_eq!(i, -23),
        _ => panic!("invalid metadata {:?}", r1.metadatas[1]),
    };

    let r2 = &rules[2];
    assert_eq!(r2.name, "p");
    assert_eq!(r2.namespace, None);
    assert_eq!(r2.tags, &["tag"]);
    assert!(!r2.is_global);
    assert!(r2.is_private);
    assert_eq!(r2.metadatas.len(), 1);
    assert_eq!(scanner.get_string_symbol(r2.metadatas[0].name), "b");
    match r2.metadatas[0].value {
        MetadataValue::Boolean(b) => assert!(b),
        _ => panic!("invalid metadata {:?}", r1.metadatas[0]),
    };

    let r3 = &rules[3];
    assert_eq!(r3.name, "r");
    assert_eq!(r3.namespace, Some("namespace"));
    assert_eq!(r3.tags, &["tag"]);
    assert!(!r3.is_global);
    assert!(!r3.is_private);
    assert_eq!(r3.metadatas.len(), 0);
}
