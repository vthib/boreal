use boreal::Scanner;

// Parse and compile `rule`, then for each test,
// check that when running the rule on the given byte string, the
// result is the given bool value.
#[track_caller]
fn check(rule: &str, mem: &[u8], expected_res: bool) {
    let mut scanner = Scanner::new();
    scanner
        .add_rules_from_str(&rule)
        .unwrap_or_else(|err| panic!("parsing failed: {}", err.to_short_description("mem", rule)));
    let res = scanner.scan_mem(mem);
    let res = res.matching_rules.len() > 0;
    assert_eq!(res, expected_res);
}

#[test]
fn test_variable() {
    let rule = r#"
rule a {
    strings:
        $a = "X"
        $b = "foo"
        $c = /re+xv?/
        $d = /^bav/
        $e = { FF ( ?A | B? [1-3] ?? ) FF }
    condition:
        $a or $b or $c or $d or $e
}"#;
    check(rule, b"nothing", false);
    check(rule, b"i Xm", true);
    check(rule, b"barfool", true);
    check(rule, b"greeex", true);
    check(rule, b"bZv", false);
    check(rule, b"bavaoze", true);
    check(rule, b"abavaoze", false);
    check(rule, b"a\xFF\xDC\xFFp", false);
    check(rule, b"dbaz\xFF\xDA\xFFeaz", true);
    check(rule, b"dbaz\xFF\xBFer\xFFeaz", true);
    check(rule, b"dbaz\xFF\xBFerdf\xFFeaz", true);
}
