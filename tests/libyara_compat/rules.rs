//! Tests imported from test_rules.c in YARA codebase.

#[track_caller]
fn test_exec(rule: &str, input: &[u8], expected_res: bool) {
    let mut scanner = boreal::scanner::Scanner::default();
    let rules = boreal::parser::parse_str(rule).unwrap();
    scanner.add_rules(rules);
    let res = scanner.scan_mem(input);
    assert_eq!(res.len() == 1, expected_res);
}

#[test]
fn test_boolean_operators() {
    test_exec("rule test { condition: not false }", &[], true);
    test_exec("rule test { condition: not true }", &[], false);
    test_exec("rule test { condition: not (false or true) }", &[], false);
    test_exec("rule test { condition: not (true or false) }", &[], false);
    test_exec("rule test { condition: not (false and true) }", &[], true);
    test_exec("rule test { condition: not (true and false) }", &[], true);
    test_exec("rule test { condition: not (true and false) }", &[], true);
    test_exec("rule test { condition: true }", &[], true);
    test_exec("rule test { condition: true or false }", &[], true);
    test_exec("rule test { condition: true and true }", &[], true);
    test_exec("rule test { condition: 0x1 and 0x2}", &[], true);
    test_exec("rule test { condition: false }", &[], false);
    test_exec("rule test { condition: true and false }", &[], false);
    test_exec("rule test { condition: false or false }", &[], false);

    // Added tests: test cast to bool
    test_exec("rule test { condition: 0.0 }", &[], false);
    test_exec("rule test { condition: 1.3 }", &[], true);
    test_exec("rule test { condition: \"\" }", &[], false);
    test_exec("rule test { condition: \"a\" }", &[], true);
    test_exec("rule test { condition: 0 }", &[], false);
    test_exec("rule test { condition: 1 }", &[], true);
    test_exec("rule test { condition: /a/ }", &[], true);
}

#[test]
#[ignore]
fn test_boolean_operators_with_identifiers() {
    test_exec(
        "import \"tests\" rule test { condition: not tests.undefined.i }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" rule test { condition: tests.undefined.i }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" rule test { condition: tests.undefined.i and true }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" rule test { condition: true and tests.undefined.i }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" rule test { condition: tests.undefined.i or true }",
        &[],
        true,
    );

    test_exec(
        "import \"tests\" rule test { condition: true or tests.undefined.i }",
        &[],
        true,
    );

    test_exec(
        "import \"tests\" \
    rule test { \
        condition: \
        not (tests.undefined.i and true) \
    }",
        &[],
        true,
    );

    test_exec(
        "import \"tests\" \
    rule test { \
        condition: \
        not (true and tests.undefined.i) \
    }",
        &[],
        true,
    );

    test_exec(
        "import \"tests\" \
    rule test { \
        condition: \
        not tests.string_array[4] contains \"foo\" \
    }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" \
    rule test { \
        condition: \
        not tests.string_dict[\"undefined\"] matches /foo/ \
    }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" \
    rule test { \
        condition: \
        not tests.undefined.i \
    }",
        &[],
        false,
    );

    test_exec(
        "import \"tests\" \
    rule test { \
        condition: \
        not (tests.undefined.i) \
    }",
        &[],
        false,
    );
}

#[test]
fn test_comparison_operators() {
    test_exec("rule test { condition: 2 > 1 }", &[], true);
    test_exec("rule test { condition: 1 < 2 }", &[], true);
    test_exec("rule test { condition: 2 >= 1 }", &[], true);
    test_exec("rule test { condition: 1 <= 1 }", &[], true);
    test_exec("rule test { condition: 1 == 1 }", &[], true);
    test_exec("rule test { condition: 1.5 == 1.5}", &[], true);
    test_exec("rule test { condition: 1.0 == 1}", &[], true);
    test_exec("rule test { condition: 1.5 >= 1.0}", &[], true);
    test_exec(
        "rule test { condition: 1.0 != 1.000000000000001 }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: 1.0 < 1.000000000000001 }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: 1.0 >= 1.000000000000001 }",
        &[],
        false,
    );
    test_exec("rule test { condition: 1.000000000000001 > 1 }", &[], true);
    test_exec(
        "rule test { condition: 1.000000000000001 <= 1 }",
        &[],
        false,
    );
    test_exec(
        "rule test { condition: 1.0 == 1.0000000000000001 }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: 1.0 >= 1.0000000000000001 }",
        &[],
        true,
    );
    test_exec("rule test { condition: 1.5 >= 1}", &[], true);
    test_exec("rule test { condition: 1.0 >= 1}", &[], true);
    test_exec("rule test { condition: 0.5 < 1}", &[], true);
    test_exec("rule test { condition: 0.5 <= 1}", &[], true);
    test_exec("rule test { condition: 1.0 <= 1}", &[], true);
    test_exec("rule test { condition: \"abc\" == \"abc\"}", &[], true);
    test_exec("rule test { condition: \"abc\" <= \"abc\"}", &[], true);
    test_exec("rule test { condition: \"abc\" >= \"abc\"}", &[], true);
    test_exec("rule test { condition: \"ab\" < \"abc\"}", &[], true);
    test_exec("rule test { condition: \"abc\" > \"ab\"}", &[], true);
    test_exec("rule test { condition: \"abc\" < \"abd\"}", &[], true);
    test_exec("rule test { condition: \"abd\" > \"abc\"}", &[], true);
    test_exec("rule test { condition: 1 != 1}", &[], false);
    test_exec("rule test { condition: 1 != 1.0}", &[], false);
    test_exec("rule test { condition: 2 > 3}", &[], false);
    test_exec("rule test { condition: 2.1 < 2}", &[], false);
    test_exec("rule test { condition: \"abc\" != \"abc\"}", &[], false);
    test_exec("rule test { condition: \"abc\" > \"abc\"}", &[], false);
    test_exec("rule test { condition: \"abc\" < \"abc\"}", &[], false);
}
