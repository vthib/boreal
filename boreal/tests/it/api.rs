//! Tests for the scanner API.

use std::io::{Seek, Write};

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
        .starts_with("error: IO error: "));

    let err = compiler
        .add_rules_file_in_namespace(path, "ns")
        .unwrap_err();
    assert!(err
        .to_short_description(path, "")
        .starts_with("error: IO error: "));
}

// An import is reused in the same namespace
#[test]
fn test_add_rules_str_err() {
    let mut compiler = boreal::Compiler::new();
    assert!(compiler.add_rules_file("z").is_err());
    assert!(compiler.add_rules_file_in_namespace("z", "ns").is_err());
}

#[test]
fn test_compiler_api() {
    let mut compiler = boreal::Compiler::default();
    assert!(compiler.add_module(boreal::module::Time));
    assert!(!compiler.add_module(boreal::module::Time));
}
