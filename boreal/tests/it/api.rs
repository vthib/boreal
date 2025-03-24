//! Tests for the scanner API.

use std::io::{Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use boreal::compiler::CompilerBuilder;
use boreal::module::Console;
use boreal::{MetadataValue, Scanner};

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
    assert_eq!(result.rules.len(), 1);

    file.as_file().rewind().unwrap();
    file.as_file().write_all(b"zyxacxby").unwrap();
    let result = scanner.scan_file(file.path()).unwrap();
    assert_eq!(result.rules.len(), 0);
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
    let builder = builder.add_module(Console::with_callback(|_| {
        FIRST.store(true, Ordering::SeqCst)
    }));
    let builder = builder.add_module(Console::with_callback(|_| {
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

#[test]
// TODO: check against yara as well
fn test_include_not_matched_rules() {
    let mut compiler = boreal::Compiler::new();
    compiler
        .add_rules_str(
            r#"
global rule ga {
    strings:
        $ = "a"
    condition:
        any of them
}
global rule gb {
    strings:
        $ = "b"
    condition:
        any of them
}
rule yes1 { condition: true }
rule no { condition: false }
"#,
        )
        .unwrap();
    compiler
        .add_rules_str_in_namespace(
            r#"
global rule gc {
    strings:
        $ = "c"
    condition:
        any of them
}
rule yes2 { condition: true }
"#,
            "ns2",
        )
        .unwrap();
    let mut scanner = compiler.into_scanner();

    scanner.set_scan_params(
        scanner
            .scan_params()
            .clone()
            .include_not_matched_rules(true),
    );

    #[track_caller]
    fn check_scan(scanner: &Scanner, mem: &[u8], expected_matches: &[(&str, bool)]) {
        let scan_res = scanner.scan_mem(mem).unwrap();
        let res: Vec<(String, bool)> = scan_res
            .rules
            .iter()
            .map(|v| {
                let name = if let Some(ns) = &v.namespace {
                    format!("{}:{}", ns, v.name)
                } else {
                    format!("default:{}", v.name)
                };
                (name, v.matched)
            })
            .collect();
        let expected_matches: Vec<_> = expected_matches
            .iter()
            .map(|(a, b)| (a.to_string(), *b))
            .collect();
        assert_eq!(res, expected_matches);
    }

    // Nothing matches
    check_scan(
        &scanner,
        b"",
        &[
            ("default:ga", false),
            ("default:gb", false),
            ("ns2:gc", false),
            ("default:yes1", false),
            ("default:no", false),
            ("ns2:yes2", false),
        ],
    );

    // Namespace ns2 matches
    check_scan(
        &scanner,
        b"c",
        &[
            ("default:ga", false),
            ("default:gb", false),
            ("ns2:gc", true),
            ("default:yes1", false),
            ("default:no", false),
            ("ns2:yes2", true),
        ],
    );

    // gc1 matches in theory but is invalidated by the other global rule
    check_scan(
        &scanner,
        b"a",
        &[
            ("default:ga", false),
            ("default:gb", false),
            ("ns2:gc", false),
            ("default:yes1", false),
            ("default:no", false),
            ("ns2:yes2", false),
        ],
    );

    // Both matches, this is now ok
    check_scan(
        &scanner,
        b"ab",
        &[
            ("default:ga", true),
            ("default:gb", true),
            ("ns2:gc", false),
            ("default:yes1", true),
            ("default:no", false),
            ("ns2:yes2", false),
        ],
    );
}

#[test]
#[cfg(feature = "serialize")]
fn test_scanner_serialize_module_use() {
    use boreal::module::ConsoleData;
    use boreal::scanner::DeserializeParams;
    use std::sync::Mutex;

    static LOGS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    // Build a scanner using the console module
    let mut compiler = CompilerBuilder::new()
        .add_module(Console::with_callback(|_| LOGS.lock().unwrap().push(1)))
        .build();
    let _r = compiler
        .add_rules_str(
            r#"
    import "console"

    rule a {
        condition:
            console.log("poof")
    }"#,
        )
        .unwrap();
    let mut scanner = compiler.into_scanner();

    let _r = scanner.scan_mem(b"").unwrap();
    assert_eq!(&*LOGS.lock().unwrap(), &[1]);

    scanner.set_module_data::<Console>(ConsoleData::new(|_| {
        LOGS.lock().unwrap().push(2);
    }));
    let _r = scanner.scan_mem(b"").unwrap();
    assert_eq!(&*LOGS.lock().unwrap(), &[1, 2]);

    let mut buf = Vec::new();
    scanner.to_bytes(&mut buf).unwrap();
    // Missing console module
    assert!(Scanner::from_bytes_unchecked(&buf, DeserializeParams::default()).is_err());

    let mut params = DeserializeParams::default();
    params.add_module(Console::with_callback(|_| LOGS.lock().unwrap().push(3)));
    let mut scanner2 = Scanner::from_bytes_unchecked(&buf, params).unwrap();

    let _r = scanner2.scan_mem(b"").unwrap();
    assert_eq!(&*LOGS.lock().unwrap(), &[1, 2, 3]);

    scanner2.set_module_data::<Console>(ConsoleData::new(|_| {
        LOGS.lock().unwrap().push(4);
    }));
    let _r = scanner2.scan_mem(b"").unwrap();
    assert_eq!(&*LOGS.lock().unwrap(), &[1, 2, 3, 4]);
}

#[test]
fn test_compiler_set_include_callback() {
    let mut compiler = crate::utils::Compiler::new_without_yara();

    // TODO: make it work with yara as well?
    compiler
        .compiler
        .set_include_callback(|include_name, current_path, namespace| {
            let current_path = current_path.map(|v| v.display().to_string());

            if namespace.is_none() {
                match (include_name, current_path.as_deref()) {
                    ("first.yar", None) => Ok(r#"
                        include "second/../boo.yar"
                        rule first { condition: true }
                    "#
                    .to_owned()),
                    ("second/../boo.yar", Some("first.yar")) => Ok(r#"
                        include "first.yar"
                        rule second { condition: true }
                    "#
                    .to_owned()),
                    ("first.yar", Some("second/../boo.yar")) => Ok(r#"
                        rule third { condition: true }
                    "#
                    .to_owned()),
                    _ => panic!(
                        "unexpected include on {} from {:?}",
                        include_name, current_path
                    ),
                }
            } else if namespace == Some("ns") {
                match (include_name, current_path.as_deref()) {
                    ("first.yar", _) => {
                        // Check the end of the path, but the rest is from a tempdir.
                        assert!(current_path
                            .as_ref()
                            .unwrap()
                            .ends_with(&format!("subdir{}initial.yar", std::path::MAIN_SEPARATOR)));
                        Ok(r#"
                            include "second/../boo.yar"
                            rule r1 { condition: true }
                        "#
                        .to_owned())
                    }
                    ("second/../boo.yar", Some("first.yar")) => Ok(r#"
                        include "../../../grandparent.yar"
                        rule r2 { condition: true }
                    "#
                    .to_owned()),
                    ("../../../grandparent.yar", Some("second/../boo.yar")) => Ok(r#"
                        include "a/../b/./boo.yar"
                        rule r3 { condition: true }
                    "#
                    .to_owned()),
                    ("a/../b/./boo.yar", Some("../../../grandparent.yar")) => Ok(r#"
                        rule r4 { condition: true }
                    "#
                    .to_owned()),
                    _ => panic!(
                        "unexpected include on {} from {:?}",
                        include_name, current_path
                    ),
                }
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("unknown namespace {namespace:?}"),
                ))
            }
        });

    // Trigger first include chain, should add rules "first", "second" and "third".
    compiler
        .compiler
        .add_rules_str(r#"include "first.yar""#)
        .unwrap();

    // Trigger second include chain, should add rules "r0", "r1", "r2", "r3" and "r4".
    let test_dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(test_dir.path().join("subdir")).unwrap();
    let file_path = test_dir.path().join("subdir").join("initial.yar");
    std::fs::write(
        &file_path,
        r#"
        include "first.yar"
        rule r0 { condition: true }
    "#,
    )
    .unwrap();
    compiler
        .compiler
        .add_rules_file_in_namespace(file_path, "ns")
        .unwrap();

    // Third chain returns an error.
    let contents = r#"include "first.yar""#;
    let err = compiler
        .compiler
        .add_rules_str_in_namespace(contents, "ns2")
        .unwrap_err();
    assert_eq!(
        err.to_short_description("input", contents),
        "input:1:1: error: cannot include `first.yar`: unknown namespace Some(\"ns2\")\n"
    );

    let mut checker = compiler.into_checker();
    checker.check_rule_matches(
        b"",
        &[
            "default:first",
            "default:second",
            "default:third",
            "ns:r0",
            "ns:r1",
            "ns:r2",
            "ns:r3",
            "ns:r4",
        ],
    );
}
