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

#[track_caller]
fn check_err(rule: &str, expected_prefix: &str) {
    let mut scanner = Scanner::new();
    let err = scanner.add_rules_from_str(&rule).unwrap_err();
    let desc = err.to_short_description("mem", rule);
    assert!(
        desc.starts_with(expected_prefix),
        "error: {}\nexpected prefix: {}",
        desc,
        expected_prefix
    );
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
        any of them
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

fn build_rule(condition: &str) -> String {
    format!(
        r#"
rule a {{
    strings:
        $a0 = "a0"
        $a1 = "a1"
        $a2 = "a2"
        $b0 = "b0"
        $b1 = "b1"
        $c  = "c"
    condition:
        {}
}}"#,
        condition
    )
}

#[test]
fn test_for_expression_all() {
    check(&build_rule("all of them"), b"", false);
    check(&build_rule("all of them"), b"a0", false);
    check(&build_rule("all of them"), b"a1", false);
    check(&build_rule("all of them"), b"a2", false);
    check(&build_rule("all of them"), b"b0", false);
    check(&build_rule("all of them"), b"b1", false);
    check(&build_rule("all of them"), b"c", false);
    check(&build_rule("all of them"), b"a0b1c", false);
    check(&build_rule("all of them"), b"a0a1a2b0b1", false);
    check(&build_rule("all of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("all of ($*)"), b"", false);
    check(&build_rule("all of ($*)"), b"a0", false);
    check(&build_rule("all of ($*)"), b"a1", false);
    check(&build_rule("all of ($*)"), b"a2", false);
    check(&build_rule("all of ($*)"), b"b0", false);
    check(&build_rule("all of ($*)"), b"b1", false);
    check(&build_rule("all of ($*)"), b"c", false);
    check(&build_rule("all of ($*)"), b"a0b1c", false);
    check(&build_rule("all of ($*)"), b"a0a1a2b0b1", false);
    check(&build_rule("all of ($*)"), b"a0a1a2b0b1c", true);

    check(&build_rule("all of ($a0, $b1, $c)"), b"", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"a0", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"a1", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"a2", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"b0", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"b1", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"c", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"a0b1c", true);
    check(&build_rule("all of ($a0, $b1, $c)"), b"a0a1a2b0b1", false);
    check(&build_rule("all of ($a0, $b1, $c)"), b"a0a1a2b0b1c", true);

    check(&build_rule("all of ($a*)"), b"", false);
    check(&build_rule("all of ($a*)"), b"a0", false);
    check(&build_rule("all of ($a*)"), b"a1", false);
    check(&build_rule("all of ($a*)"), b"a2", false);
    check(&build_rule("all of ($a*)"), b"b0", false);
    check(&build_rule("all of ($a*)"), b"b1", false);
    check(&build_rule("all of ($a*)"), b"c", false);
    check(&build_rule("all of ($a*)"), b"a0b1c", false);
    check(&build_rule("all of ($a*)"), b"a0a1", false);
    check(&build_rule("all of ($a*)"), b"a0a1a2", true);
    check(&build_rule("all of ($a*)"), b"a0a1a2b0b1", true);
    check(&build_rule("all of ($a*)"), b"a0a1a2b0b1c", true);
}

#[test]
fn test_for_expression_any() {
    check(&build_rule("any of them"), b"", false);
    check(&build_rule("any of them"), b"a0", true);
    check(&build_rule("any of them"), b"a1", true);
    check(&build_rule("any of them"), b"a2", true);
    check(&build_rule("any of them"), b"b0", true);
    check(&build_rule("any of them"), b"b1", true);
    check(&build_rule("any of them"), b"c", true);
    check(&build_rule("any of them"), b"a0b1c", true);
    check(&build_rule("any of them"), b"a0a1a2b0b1", true);
    check(&build_rule("any of them"), b"a0a1a2b0b1c", true);
}

#[test]
fn test_for_expression_none() {
    check(&build_rule("none of them"), b"", true);
    check(&build_rule("none of them"), b"a0", false);
    check(&build_rule("none of them"), b"a1", false);
    check(&build_rule("none of them"), b"a2", false);
    check(&build_rule("none of them"), b"b0", false);
    check(&build_rule("none of them"), b"b1", false);
    check(&build_rule("none of them"), b"c", false);
    check(&build_rule("none of them"), b"a0b1c", false);
    check(&build_rule("none of them"), b"a0a1a2b0b1", false);
    check(&build_rule("none of them"), b"a0a1a2b0b1c", false);

    check(&build_rule("none of ($b*)"), b"", true);
    check(&build_rule("none of ($b*)"), b"a0", true);
    check(&build_rule("none of ($b*)"), b"a1", true);
    check(&build_rule("none of ($b*)"), b"a2", true);
    check(&build_rule("none of ($b*)"), b"b0", false);
    check(&build_rule("none of ($b*)"), b"b1", false);
    check(&build_rule("none of ($b*)"), b"c", true);
    check(&build_rule("none of ($b*)"), b"a0b1c", false);
    check(&build_rule("none of ($b*)"), b"a0a1a2b0b1", false);
    check(&build_rule("none of ($b*)"), b"a0a1a2b0b1c", false);
}

#[test]
fn test_for_expression_number() {
    check(&build_rule("-1 of them"), b"", true);
    check(&build_rule("-1 of them"), b"a0", true);
    check(&build_rule("-1 of them"), b"a1", true);
    check(&build_rule("-1 of them"), b"a2", true);
    check(&build_rule("-1 of them"), b"b0", true);
    check(&build_rule("-1 of them"), b"b1", true);
    check(&build_rule("-1 of them"), b"c", true);
    check(&build_rule("-1 of them"), b"a0b1", true);
    check(&build_rule("-1 of them"), b"a0b1c", true);
    check(&build_rule("-1 of them"), b"a0a1a2b0b1", true);
    check(&build_rule("-1 of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("0 of them"), b"", true);
    check(&build_rule("0 of them"), b"a0", true);
    check(&build_rule("0 of them"), b"a1", true);
    check(&build_rule("0 of them"), b"a2", true);
    check(&build_rule("0 of them"), b"b0", true);
    check(&build_rule("0 of them"), b"b1", true);
    check(&build_rule("0 of them"), b"c", true);
    check(&build_rule("0 of them"), b"a0b1", true);
    check(&build_rule("0 of them"), b"a0b1c", true);
    check(&build_rule("0 of them"), b"a0a1a2b0b1", true);
    check(&build_rule("0 of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("3 of them"), b"", false);
    check(&build_rule("3 of them"), b"a0", false);
    check(&build_rule("3 of them"), b"a1", false);
    check(&build_rule("3 of them"), b"a2", false);
    check(&build_rule("3 of them"), b"b0", false);
    check(&build_rule("3 of them"), b"b1", false);
    check(&build_rule("3 of them"), b"c", false);
    check(&build_rule("3 of them"), b"a0b1", false);
    check(&build_rule("3 of them"), b"a0b1c", true);
    check(&build_rule("3 of them"), b"a0a1a2b0b1", true);
    check(&build_rule("3 of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("6 of them"), b"", false);
    check(&build_rule("6 of them"), b"a0", false);
    check(&build_rule("6 of them"), b"a1", false);
    check(&build_rule("6 of them"), b"a2", false);
    check(&build_rule("6 of them"), b"b0", false);
    check(&build_rule("6 of them"), b"b1", false);
    check(&build_rule("6 of them"), b"c", false);
    check(&build_rule("6 of them"), b"a0b1", false);
    check(&build_rule("6 of them"), b"a0b1c", false);
    check(&build_rule("6 of them"), b"a0a1a2b0b1", false);
    check(&build_rule("6 of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("7 of them"), b"", false);
    check(&build_rule("7 of them"), b"a0", false);
    check(&build_rule("7 of them"), b"a1", false);
    check(&build_rule("7 of them"), b"a2", false);
    check(&build_rule("7 of them"), b"b0", false);
    check(&build_rule("7 of them"), b"b1", false);
    check(&build_rule("7 of them"), b"c", false);
    check(&build_rule("7 of them"), b"a0b1", false);
    check(&build_rule("7 of them"), b"a0b1c", false);
    check(&build_rule("7 of them"), b"a0a1a2b0b1", false);
    check(&build_rule("7 of them"), b"a0a1a2b0b1c", false);
}

#[test]
fn test_for_expression_percent() {
    check(&build_rule("-1% of them"), b"", true);
    check(&build_rule("-1% of them"), b"a0", true);
    check(&build_rule("-1% of them"), b"a1", true);
    check(&build_rule("-1% of them"), b"a2", true);
    check(&build_rule("-1% of them"), b"b0", true);
    check(&build_rule("-1% of them"), b"b1", true);
    check(&build_rule("-1% of them"), b"c", true);
    check(&build_rule("-1% of them"), b"a0b1", true);
    check(&build_rule("-1% of them"), b"a0b1c", true);
    check(&build_rule("-1% of them"), b"a0a1a2b0b1", true);
    check(&build_rule("-1% of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("0% of them"), b"", true);
    check(&build_rule("0% of them"), b"a0", true);
    check(&build_rule("0% of them"), b"a1", true);
    check(&build_rule("0% of them"), b"a2", true);
    check(&build_rule("0% of them"), b"b0", true);
    check(&build_rule("0% of them"), b"b1", true);
    check(&build_rule("0% of them"), b"c", true);
    check(&build_rule("0% of them"), b"a0b1", true);
    check(&build_rule("0% of them"), b"a0b1c", true);
    check(&build_rule("0% of them"), b"a0a1a2b0b1", true);
    check(&build_rule("0% of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("50% of them"), b"", false);
    check(&build_rule("50% of them"), b"a0", false);
    check(&build_rule("50% of them"), b"a1", false);
    check(&build_rule("50% of them"), b"a2", false);
    check(&build_rule("50% of them"), b"b0", false);
    check(&build_rule("50% of them"), b"b1", false);
    check(&build_rule("50% of them"), b"c", false);
    check(&build_rule("50% of them"), b"a0b1", false);
    check(&build_rule("50% of them"), b"a0b1c", true);
    check(&build_rule("50% of them"), b"a0a1a2b0b1", true);
    check(&build_rule("50% of them"), b"a0a1a2b0b1c", true);

    // Gets rounded up to 4 of them
    check(&build_rule("51% of them"), b"", false);
    check(&build_rule("51% of them"), b"a0", false);
    check(&build_rule("51% of them"), b"a1", false);
    check(&build_rule("51% of them"), b"a2", false);
    check(&build_rule("51% of them"), b"b0", false);
    check(&build_rule("51% of them"), b"b1", false);
    check(&build_rule("51% of them"), b"c", false);
    check(&build_rule("51% of them"), b"a0b1", false);
    check(&build_rule("51% of them"), b"a0b1c", false);
    check(&build_rule("51% of them"), b"a0b0b1c", true);
    check(&build_rule("51% of them"), b"a0a1a2b0b1", true);
    check(&build_rule("51% of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("100% of them"), b"", false);
    check(&build_rule("100% of them"), b"a0", false);
    check(&build_rule("100% of them"), b"a1", false);
    check(&build_rule("100% of them"), b"a2", false);
    check(&build_rule("100% of them"), b"b0", false);
    check(&build_rule("100% of them"), b"b1", false);
    check(&build_rule("100% of them"), b"c", false);
    check(&build_rule("100% of them"), b"a0b1", false);
    check(&build_rule("100% of them"), b"a0b1c", false);
    check(&build_rule("100% of them"), b"a0a1a2b0b1", false);
    check(&build_rule("100% of them"), b"a0a1a2b0b1c", true);

    check(&build_rule("101% of them"), b"", false);
    check(&build_rule("101% of them"), b"a0", false);
    check(&build_rule("101% of them"), b"a1", false);
    check(&build_rule("101% of them"), b"a2", false);
    check(&build_rule("101% of them"), b"b0", false);
    check(&build_rule("101% of them"), b"b1", false);
    check(&build_rule("101% of them"), b"c", false);
    check(&build_rule("101% of them"), b"a0b1", false);
    check(&build_rule("101% of them"), b"a0b1c", false);
    check(&build_rule("101% of them"), b"a0a1a2b0b1", false);
    check(&build_rule("101% of them"), b"a0a1a2b0b1c", false);
}

#[test]
fn test_for_expression_err() {
    check_err(
        &build_rule("all of ($d)"),
        "mem:11:9: error: unknown variable $d",
    );
    check_err(
        &build_rule("all of ($d*)"),
        "mem:11:9: error: unknown variable $d",
    );
}
