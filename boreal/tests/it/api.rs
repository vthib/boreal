//! Tests for the scanner API.

use std::io::{Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use boreal::compiler::CompilerBuilder;

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
