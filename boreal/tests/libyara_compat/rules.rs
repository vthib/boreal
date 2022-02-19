//! Tests imported from test_rules.c in YARA codebase.
use boreal::{scanner::Scanner, ScanError};
use boreal_parser::parse_str;

#[track_caller]
fn test_exec(rule: &str, input: &[u8], expected_res: bool) {
    let rules = match parse_str(rule) {
        Ok(rules) => rules,
        Err(err) => panic!("parsing failed: {}", err.to_short_description("mem", rule)),
    };
    let mut scanner = Scanner::default();
    scanner.add_rules(rules);
    let res = scanner.scan_mem(input);
    assert_eq!(res.matching_rules.len() == 1, expected_res);
}

#[track_caller]
fn test_exec_error(rule: &str, input: &[u8], expected_err: ScanError) {
    let rules = match parse_str(rule) {
        Ok(rules) => rules,
        Err(err) => panic!("parsing failed: {}", err.to_short_description("mem", rule)),
    };
    let rule_name = rules[0].name.clone();

    let mut scanner = Scanner::default();
    scanner.add_rules(rules);
    let res = scanner.scan_mem(input);
    assert!(res.matching_rules.is_empty());
    assert_eq!(res.scan_errors.len(), 1);
    assert_eq!(res.scan_errors[0].rule.name, rule_name);
    assert_eq!(res.scan_errors[0].error, expected_err);
}

#[track_caller]
fn test_parse_error(rule: &str, expected_prefix: &str) {
    let err = parse_str(rule).unwrap_err();
    let desc = err.to_short_description("mem", rule);
    assert!(
        desc.starts_with(expected_prefix),
        "error: {}\nexpected prefix: {}",
        desc,
        expected_prefix
    );
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
// TODO: Implement identifiers
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

#[test]
fn test_arithmetic_operators() {
    test_exec(
        "rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }",
        &[],
        true,
    );
    test_exec("rule test { condition: 5 % 2 == 1 }", &[], true);
    test_exec("rule test { condition: 1.5 + 1.5 == 3}", &[], true);
    test_exec("rule test { condition: 3 \\ 2 == 1}", &[], true);
    test_exec("rule test { condition: 3.0 \\ 2 == 1.5}", &[], true);
    test_exec("rule test { condition: 1 + -1 == 0}", &[], true);
    test_exec("rule test { condition: -1 + -1 == -2}", &[], true);
    test_exec("rule test { condition: 4 --2 * 2 == 8}", &[], true);
    test_exec("rule test { condition: -1.0 * 1 == -1.0}", &[], true);
    test_exec("rule test { condition: 1-1 == 0}", &[], true);
    test_exec("rule test { condition: -2.0-3.0 == -5}", &[], true);
    test_exec("rule test { condition: --1 == 1}", &[], true);
    test_exec("rule test { condition: 1--1 == 2}", &[], true);
    test_exec("rule test { condition: 2 * -2 == -4}", &[], true);
    test_exec("rule test { condition: -4 * 2 == -8}", &[], true);
    test_exec("rule test { condition: -4 * -4 == 16}", &[], true);
    test_exec("rule test { condition: -0x01 == -1}", &[], true);
    test_exec("rule test { condition: 0o10 == 8 }", &[], true);
    test_exec("rule test { condition: 0o100 == 64 }", &[], true);
    test_exec("rule test { condition: 0o755 == 493 }", &[], true);

    test_parse_error(
        "rule test { condition: 9223372036854775808 > 0 }",
        "mem:1:24: error: syntax error\n",
    );

    test_parse_error(
        "rule test { condition: 9007199254740992KB > 0 }",
        "mem:1:24: error: multiplication 9007199254740992 * 1024 overflows\n",
    );

    test_parse_error(
        // integer too long
        "rule test { condition: 8796093022208MB > 0 }",
        "mem:1:24: error: multiplication 8796093022208 * 1048576 overflows\n",
    );

    test_parse_error(
        // integer too long
        "rule test { condition: 0x8000000000000000 > 0 }",
        "mem:1:26: error: error converting hexadecimal notation to integer",
    );

    test_parse_error(
        // integer too long
        "rule test { condition: 0o1000000000000000000000 > 0 }",
        "mem:1:26: error: error converting octal notation to integer",
    );
}

#[test]
// TODO: ideally, catch those in future simplifying step.
fn test_arithmetic_operators_runtime_errors() {
    test_exec_error(
        "rule test { condition: 0x7FFFFFFFFFFFFFFF + 1 > 0 }",
        &[],
        ScanError::Overflow {
            left_value: 0x7FFFFFFFFFFFFFFF,
            right_value: 1,
            operator: "+".to_owned(),
        },
    );

    test_exec_error(
        "rule test { condition: 9223372036854775807 + 1 > 0 }",
        &[],
        ScanError::Overflow {
            left_value: 9223372036854775807,
            right_value: 1,
            operator: "+".to_owned(),
        },
    );

    test_exec_error(
        "rule test { condition: -9223372036854775807 - 2 > 0 }",
        &[],
        ScanError::Overflow {
            left_value: -9223372036854775807,
            right_value: 2,
            operator: "-".to_owned(),
        },
    );

    test_exec_error(
        "rule test { condition: -2 + -9223372036854775807 > 0 }",
        &[],
        ScanError::Overflow {
            left_value: -2,
            right_value: -9223372036854775807,
            operator: "+".to_owned(),
        },
    );

    test_exec_error(
        "rule test { condition: 1 - -9223372036854775807 > 0 }",
        &[],
        ScanError::Overflow {
            left_value: 1,
            right_value: -9223372036854775807,
            operator: "-".to_owned(),
        },
    );

    test_exec_error(
        "rule test { condition: 0x4000000000000000 * 2 }",
        &[],
        ScanError::Overflow {
            left_value: 0x4000000000000000,
            right_value: 2,
            operator: "*".to_owned(),
        },
    );

    test_exec_error(
        "rule test { condition: 4611686018427387904 * 2 }",
        &[],
        ScanError::Overflow {
            left_value: 4611686018427387904,
            right_value: 2,
            operator: "*".to_owned(),
        },
    );

    // CHANGE: Those two return OVERFLOW on libyara due to how
    // overflow is detected. However, they do NOT actually overflow.
    test_exec(
        "rule test { condition: 4611686018427387904 * -2 < 0 }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: -4611686018427387904 * 2 < 0 }",
        &[],
        true,
    );

    test_exec_error(
        "rule test { condition: -4611686018427387904 * -2 }",
        &[],
        ScanError::Overflow {
            left_value: -4611686018427387904,
            right_value: -2,
            operator: "*".to_owned(),
        },
    );
}

#[test]
fn test_bitwise_operators() {
    test_exec("rule test { condition: 0x55 | 0xAA == 0xFF }", &[], true);
    test_exec(
        "rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }",
        &[],
        true,
    );
    test_exec("rule test { condition: ~0x55 & 0xFF == 0xAA }", &[], true);
    test_exec("rule test { condition: 8 >> 2 == 2 }", &[], true);
    test_exec("rule test { condition: 1 << 3 == 8 }", &[], true);

    test_exec("rule test { condition: 1 << 64 == 0 }", &[], true);
    test_exec("rule test { condition: 1 >> 64 == 0 }", &[], true);
    test_exec_error(
        "rule test { condition: 1 << -1 == 0 }",
        &[],
        ScanError::Overflow {
            left_value: 1,
            right_value: -1,
            operator: "<<".to_owned(),
        },
    );
    test_exec_error(
        "rule test { condition: 1 >> -1 == 0 }",
        &[],
        ScanError::Overflow {
            left_value: 1,
            right_value: -1,
            operator: ">>".to_owned(),
        },
    );
    test_exec(
        "rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }",
        &[],
        false,
    );
    test_exec(
        "rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}",
        &[],
        false,
    );
}

#[test]
fn test_string_operators() {
    test_exec(
        "rule test { condition: \"foobarbaz\" contains \"bar\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" contains \"foo\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" contains \"baz\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" icontains \"BAR\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" icontains \"BaR\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"FooBarBaz\" icontains \"bar\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"FooBarBaz\" icontains \"baz\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"FooBarBaz\" icontains \"FOO\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" contains \"foo\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" contains \"baz\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" contains \"baq\" }",
        &[],
        false,
    );
    test_exec(
        "rule test { condition: \"foo\" contains \"foob\" }",
        &[],
        false,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" startswith \"foo\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" istartswith \"Foo\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"FooBarBaz\" istartswith \"fOO\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" startswith \"fob\" }",
        &[],
        false,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" endswith \"baz\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" iendswith \"baZ\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" iendswith \"BaZ\" }",
        &[],
        true,
    );
    test_exec(
        "rule test { condition: \"foobarbaz\" endswith \"ba\" }",
        &[],
        false,
    );
}

#[test]
fn test_syntax() {
    test_parse_error(
        "rule test { strings: $a = \"a\" $a = \"a\" condition: all of them }",
        "mem:1:31: error: multiple strings named a declared",
    );

    test_parse_error(
        "rule test { strings: $a = /a.c/ xor condition: $a }",
        "mem:1:33: error: syntax error",
    );

    test_parse_error(
        "rule test { strings: $a = /abc/ xor condition: $a }",
        "mem:1:33: error: syntax error",
    );

    test_parse_error(
        "rule test { strings: $a = {01 02 ?? 03 04} xor condition: $a }",
        "mem:1:44: error: syntax error",
    );

    test_parse_error(
        "rule test { strings: $a = {01 02 0? 03 04} xor condition: $a }",
        "mem:1:44: error: syntax error",
    );

    test_parse_error(
        "rule test { strings: $a = {01 02 03 04} xor condition: $a }",
        "mem:1:41: error: syntax error",
    );

    test_parse_error("rule test rule test", "mem:1:11: error: syntax error");
}
