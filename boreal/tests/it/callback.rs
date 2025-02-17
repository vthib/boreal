use std::time::Duration;

use boreal::scanner::{ScanCallbackResult, ScanError, ScanEvent, ScanParams};
use boreal::{Compiler, Scanner};

use crate::utils::FragmentedSlices;

const TIMEOUT_COND: &str = r#"
    for all i in (0..9223372036854775807) : (
        for all j in (0..9223372036854775807) : (
            for all k in (0..9223372036854775807) : (
                for all l in (0..9223372036854775807) : (
                    i + j + k + l >= 0
                )
            )
        )
    )
"#;

#[track_caller]
fn check_rule_match(event: ScanEvent, rule_name: &str, namespace: Option<&str>) {
    let res = match &event {
        ScanEvent::RuleMatch(m) => m.name == rule_name && m.namespace == namespace,
        evt => panic!("unexpected event {:?}", evt),
    };
    assert!(
        res,
        "event {:?} is not a match for rule {:?}:{}",
        event, namespace, rule_name
    );
}

fn scan_mem<F>(scanner: &Scanner, mem: &[u8], expected_number: u32, checker: F)
where
    F: Fn(ScanEvent, u32) + Sync,
{
    let mut counter = 0;
    scanner
        .scan_mem_with_callback(mem, |event| {
            checker(event, counter);
            counter += 1;
            ScanCallbackResult::Continue
        })
        .unwrap();
    assert_eq!(counter, expected_number);
}

fn scan_mem_with_abort<F>(scanner: &Scanner, mem: &[u8], abort_on_event_number: u32, checker: F)
where
    F: Fn(ScanEvent, u32) + Sync,
{
    let mut counter = 0;
    let res = scanner.scan_mem_with_callback(mem, |event| {
        checker(event, counter);
        if counter < abort_on_event_number {
            counter += 1;
            ScanCallbackResult::Continue
        } else {
            ScanCallbackResult::Abort
        }
    });
    assert!(matches!(res, Err(ScanError::CallbackAbort)));
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

    scan_mem(&scanner, b"<abcdef>", 2, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "c", None);
        }
    });

    scan_mem(&scanner, b"<abef>", 1, |event, _nb| {
        check_rule_match(event, "a", None);
    });
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

    scan_mem(&scanner, b"<abc>", 0, |_, _| panic!());

    scan_mem(&scanner, b"<abcdef>", 2, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        }
    });

    scan_mem(&scanner, b"<abcdefghi>", 3, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        } else if nb == 2 {
            check_rule_match(event, "c", None);
        }
    });

    scan_mem(&scanner, b"<defghi>", 0, |_, _| panic!());
}

#[test]
fn test_scan_mem_with_callback_global_rule_no_ac() {
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

    scan_mem(&scanner, b"12", 0, |_, _| panic!());
    scan_mem(&scanner, b"123", 0, |_, _| panic!());

    scan_mem(&scanner, b"12345", 2, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        }
    });

    scan_mem(&scanner, b"12345678", 3, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        } else if nb == 2 {
            check_rule_match(event, "c", None);
        }
    });
}

#[test]
fn test_scan_mem_with_callback_no_ac_timeout() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r"
global rule a { condition: true }
rule b { condition: filesize >= 3 }
    ",
        )
        .unwrap();
    compiler
        .add_rules_str(format!("rule c {{ condition: {} }}", TIMEOUT_COND))
        .unwrap();
    let mut scanner = compiler.into_scanner();
    scanner
        .set_scan_params(ScanParams::default().timeout_duration(Some(Duration::from_millis(100))));

    let mut counter = 0;
    let res = scanner.scan_mem_with_callback(b"123", |event| {
        if counter == 0 {
            check_rule_match(event, "a", None);
        } else if counter == 1 {
            check_rule_match(event, "b", None);
        }
        counter += 1;
        ScanCallbackResult::Continue
    });
    assert!(matches!(res, Err(ScanError::Timeout)));
    assert_eq!(counter, 2);
}

#[test]
fn test_scan_mem_with_callback_abort() {
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
global rule b { condition: true }
rule c { condition: true }
rule d { condition: true }
"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    scan_mem_with_abort(&scanner, b"abc", 0, |event, _nb| {
        check_rule_match(event, "a", None);
    });

    scan_mem_with_abort(&scanner, b"abc", 1, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        }
    });

    scan_mem_with_abort(&scanner, b"abc", 2, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        } else if nb == 2 {
            check_rule_match(event, "c", None);
        }
    });

    scan_mem_with_abort(&scanner, b"abc", 3, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        } else if nb == 2 {
            check_rule_match(event, "c", None);
        } else if nb == 3 {
            check_rule_match(event, "d", None);
        }
    });
}

#[test]
fn test_scan_mem_with_callback_abort_no_ac() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
global rule a { condition: true }
global rule b { condition: true }
rule c { condition: true }
rule d { condition: true }
"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    scan_mem_with_abort(&scanner, b"", 0, |event, _nb| {
        check_rule_match(event, "a", None);
    });

    scan_mem_with_abort(&scanner, b"", 1, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        }
    });

    scan_mem_with_abort(&scanner, b"", 2, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        } else if nb == 2 {
            check_rule_match(event, "c", None);
        }
    });

    scan_mem_with_abort(&scanner, b"", 3, |event, nb| {
        if nb == 0 {
            check_rule_match(event, "a", None);
        } else if nb == 1 {
            check_rule_match(event, "b", None);
        } else if nb == 2 {
            check_rule_match(event, "c", None);
        } else if nb == 3 {
            check_rule_match(event, "d", None);
        }
    });
}

#[test]
fn test_scan_mem_with_callback_abort_timeout() {
    // If the scan timeouts but the callback aborts, the abort
    // status is returned.
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str("rule a { condition: true }")
        .unwrap();
    compiler
        .add_rules_str(format!("rule c {{ condition: {} }}", TIMEOUT_COND))
        .unwrap();
    let mut scanner = compiler.into_scanner();
    scanner
        .set_scan_params(ScanParams::default().timeout_duration(Some(Duration::from_millis(100))));

    scan_mem_with_abort(&scanner, b"", 0, |event, _nb| {
        check_rule_match(event, "a", None);
    });
}

#[test]
fn test_scan_file_with_callback() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str("rule a { condition: true }")
        .unwrap();
    let scanner = compiler.into_scanner();

    let mut counter = 0;
    let res = scanner.scan_file_with_callback("not_existing", |_event| {
        counter += 1;
        ScanCallbackResult::Continue
    });
    assert!(matches!(res, Err(ScanError::CannotReadFile(_))));
    assert_eq!(counter, 0);

    let file = tempfile::NamedTempFile::new().unwrap();
    let mut counter = 0;
    scanner
        .scan_file_with_callback(&file, |event| {
            check_rule_match(event, "a", None);
            counter += 1;
            ScanCallbackResult::Continue
        })
        .unwrap();
    assert_eq!(counter, 1);
}

#[test]
#[cfg(feature = "memmap")]
fn test_scan_file_memmap_with_callback() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str("rule a { condition: true }")
        .unwrap();
    let scanner = compiler.into_scanner();

    let mut counter = 0;
    // Safety: testing
    let res = unsafe {
        scanner.scan_file_memmap_with_callback("not_existing", |_event| {
            counter += 1;
            ScanCallbackResult::Continue
        })
    };
    assert!(matches!(res, Err(ScanError::CannotReadFile(_))));
    assert_eq!(counter, 0);

    let file = tempfile::NamedTempFile::new().unwrap();
    let mut counter = 0;
    // Safety: testing
    unsafe {
        scanner.scan_file_memmap_with_callback(&file, |event| {
            check_rule_match(event, "a", None);
            counter += 1;
            ScanCallbackResult::Continue
        })
    }
    .unwrap();
    assert_eq!(counter, 1);
}

#[test]
fn test_scan_fragmented_with_callback() {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
rule a {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        $a and $b
}"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    let regions = &[
        (0, Some(b"zyx".as_slice())),
        (0x1000, Some(b"<abc>")),
        (0x2000, Some(b"def")),
    ];
    let mut counter = 0;
    scanner
        .scan_fragmented_with_callback(FragmentedSlices::new(regions), |event| {
            check_rule_match(event, "a", None);
            counter += 1;
            ScanCallbackResult::Continue
        })
        .unwrap();
    assert_eq!(counter, 1);
}

#[test]
#[cfg(feature = "process")]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_scan_process_with_callback() {
    // Scan for strings found in the bss and the stack of the test process.

    use crate::utils::BinHelper;
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(
            r#"
rule a {
    strings:
        $a = "PAYLOAD_ON_STACK"
    condition:
        all of them
}"#,
        )
        .unwrap();
    let scanner = compiler.into_scanner();

    let helper = BinHelper::run("stack");
    let mut counter = 0;
    scanner
        .scan_process_with_callback(helper.pid(), |event| {
            check_rule_match(event, "a", None);
            counter += 1;
            ScanCallbackResult::Continue
        })
        .unwrap();
    assert_eq!(counter, 1);
}
