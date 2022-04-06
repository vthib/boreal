//! Tests imported from test_rules.c in YARA codebase.
use crate::utils::{check, check_err};

#[test]
fn test_boolean_operators() {
    check("rule test { condition: not false }", &[], true);
    check("rule test { condition: not true }", &[], false);
    check("rule test { condition: not (false or true) }", &[], false);
    check("rule test { condition: not (true or false) }", &[], false);
    check("rule test { condition: not (false and true) }", &[], true);
    check("rule test { condition: not (true and false) }", &[], true);
    check("rule test { condition: not (true and false) }", &[], true);
    check("rule test { condition: true }", &[], true);
    check("rule test { condition: true or false }", &[], true);
    check("rule test { condition: true and true }", &[], true);
    check("rule test { condition: 0x1 and 0x2}", &[], true);
    check("rule test { condition: false }", &[], false);
    check("rule test { condition: true and false }", &[], false);
    check("rule test { condition: false or false }", &[], false);

    // Added tests: test cast to bool
    check("rule test { condition: 0.0 }", &[], false);
    check("rule test { condition: 1.3 }", &[], true);
    check("rule test { condition: \"\" }", &[], false);
    check("rule test { condition: \"a\" }", &[], true);
    check("rule test { condition: 0 }", &[], false);
    check("rule test { condition: 1 }", &[], true);
    check("rule test { condition: /a/ }", &[], true);
}

#[test]
// TODO: Implement identifiers
#[ignore]
fn test_boolean_operators_with_identifiers() {
    check(
        "import \"tests\" rule test { condition: not tests.undefined.i }",
        &[],
        false,
    );

    check(
        "import \"tests\" rule test { condition: tests.undefined.i }",
        &[],
        false,
    );

    check(
        "import \"tests\" rule test { condition: tests.undefined.i and true }",
        &[],
        false,
    );

    check(
        "import \"tests\" rule test { condition: true and tests.undefined.i }",
        &[],
        false,
    );

    check(
        "import \"tests\" rule test { condition: tests.undefined.i or true }",
        &[],
        true,
    );

    check(
        "import \"tests\" rule test { condition: true or tests.undefined.i }",
        &[],
        true,
    );

    check(
        "import \"tests\" \
    rule test { \
        condition: \
        not (tests.undefined.i and true) \
    }",
        &[],
        true,
    );

    check(
        "import \"tests\" \
    rule test { \
        condition: \
        not (true and tests.undefined.i) \
    }",
        &[],
        true,
    );

    check(
        "import \"tests\" \
    rule test { \
        condition: \
        not tests.string_array[4] contains \"foo\" \
    }",
        &[],
        false,
    );

    check(
        "import \"tests\" \
    rule test { \
        condition: \
        not tests.string_dict[\"undefined\"] matches /foo/ \
    }",
        &[],
        false,
    );

    check(
        "import \"tests\" \
    rule test { \
        condition: \
        not tests.undefined.i \
    }",
        &[],
        false,
    );

    check(
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
    check("rule test { condition: 2 > 1 }", &[], true);
    check("rule test { condition: 1 < 2 }", &[], true);
    check("rule test { condition: 2 >= 1 }", &[], true);
    check("rule test { condition: 1 <= 1 }", &[], true);
    check("rule test { condition: 1 == 1 }", &[], true);
    check("rule test { condition: 1.5 == 1.5}", &[], true);
    check("rule test { condition: 1.0 == 1}", &[], true);
    check("rule test { condition: 1.5 >= 1.0}", &[], true);
    check(
        "rule test { condition: 1.0 != 1.000000000000001 }",
        &[],
        true,
    );
    check(
        "rule test { condition: 1.0 < 1.000000000000001 }",
        &[],
        true,
    );
    check(
        "rule test { condition: 1.0 >= 1.000000000000001 }",
        &[],
        false,
    );
    check("rule test { condition: 1.000000000000001 > 1 }", &[], true);
    check(
        "rule test { condition: 1.000000000000001 <= 1 }",
        &[],
        false,
    );
    check(
        "rule test { condition: 1.0 == 1.0000000000000001 }",
        &[],
        true,
    );
    check(
        "rule test { condition: 1.0 >= 1.0000000000000001 }",
        &[],
        true,
    );
    check("rule test { condition: 1.5 >= 1}", &[], true);
    check("rule test { condition: 1.0 >= 1}", &[], true);
    check("rule test { condition: 0.5 < 1}", &[], true);
    check("rule test { condition: 0.5 <= 1}", &[], true);
    check("rule test { condition: 1.0 <= 1}", &[], true);
    check("rule test { condition: \"abc\" == \"abc\"}", &[], true);
    check("rule test { condition: \"abc\" <= \"abc\"}", &[], true);
    check("rule test { condition: \"abc\" >= \"abc\"}", &[], true);
    check("rule test { condition: \"ab\" < \"abc\"}", &[], true);
    check("rule test { condition: \"abc\" > \"ab\"}", &[], true);
    check("rule test { condition: \"abc\" < \"abd\"}", &[], true);
    check("rule test { condition: \"abd\" > \"abc\"}", &[], true);
    check("rule test { condition: 1 != 1}", &[], false);
    check("rule test { condition: 1 != 1.0}", &[], false);
    check("rule test { condition: 2 > 3}", &[], false);
    check("rule test { condition: 2.1 < 2}", &[], false);
    check("rule test { condition: \"abc\" != \"abc\"}", &[], false);
    check("rule test { condition: \"abc\" > \"abc\"}", &[], false);
    check("rule test { condition: \"abc\" < \"abc\"}", &[], false);
}

#[test]
fn test_arithmetic_operators() {
    check(
        "rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }",
        &[],
        true,
    );
    check("rule test { condition: 5 % 2 == 1 }", &[], true);
    check("rule test { condition: 1.5 + 1.5 == 3}", &[], true);
    check("rule test { condition: 3 \\ 2 == 1}", &[], true);
    check("rule test { condition: 3.0 \\ 2 == 1.5}", &[], true);
    check("rule test { condition: 1 + -1 == 0}", &[], true);
    check("rule test { condition: -1 + -1 == -2}", &[], true);
    check("rule test { condition: 4 --2 * 2 == 8}", &[], true);
    check("rule test { condition: -1.0 * 1 == -1.0}", &[], true);
    check("rule test { condition: 1-1 == 0}", &[], true);
    check("rule test { condition: -2.0-3.0 == -5}", &[], true);
    check("rule test { condition: --1 == 1}", &[], true);
    check("rule test { condition: 1--1 == 2}", &[], true);
    check("rule test { condition: 2 * -2 == -4}", &[], true);
    check("rule test { condition: -4 * 2 == -8}", &[], true);
    check("rule test { condition: -4 * -4 == 16}", &[], true);
    check("rule test { condition: -0x01 == -1}", &[], true);
    check("rule test { condition: 0o10 == 8 }", &[], true);
    check("rule test { condition: 0o100 == 64 }", &[], true);
    check("rule test { condition: 0o755 == 493 }", &[], true);

    check_err(
        "rule test { condition: 9223372036854775808 > 0 }",
        "mem:1:24: error: syntax error\n",
    );

    check_err(
        "rule test { condition: 9007199254740992KB > 0 }",
        "mem:1:24: error: multiplication 9007199254740992 * 1024 overflows\n",
    );

    check_err(
        // integer too long
        "rule test { condition: 8796093022208MB > 0 }",
        "mem:1:24: error: multiplication 8796093022208 * 1048576 overflows\n",
    );

    check_err(
        // integer too long
        "rule test { condition: 0x8000000000000000 > 0 }",
        "mem:1:26: error: error converting hexadecimal notation to integer",
    );

    check_err(
        // integer too long
        "rule test { condition: 0o1000000000000000000000 > 0 }",
        "mem:1:26: error: error converting octal notation to integer",
    );
}

#[test]
// TODO: ideally, catch those in future simplifying step.
#[ignore]
fn test_arithmetic_operators_runtimes() {
    check(
        "rule test { condition: 0x7FFFFFFFFFFFFFFF + 1 > 0 }",
        &[],
        false,
    );

    check(
        "rule test { condition: 9223372036854775807 + 1 > 0 }",
        &[],
        false,
    );

    check(
        "rule test { condition: -9223372036854775807 - 2 > 0 }",
        &[],
        false,
    );

    check(
        "rule test { condition: -2 + -9223372036854775807 > 0 }",
        &[],
        false,
    );

    check(
        "rule test { condition: 1 - -9223372036854775807 > 0 }",
        &[],
        false,
    );

    check(
        "rule test { condition: 0x4000000000000000 * 2 }",
        &[],
        false,
    );

    check(
        "rule test { condition: 4611686018427387904 * 2 }",
        &[],
        false,
    );

    // CHANGE: Those two return OVERFLOW on libyara due to how
    // overflow is detected. However, they do NOT actually overflow.
    check(
        "rule test { condition: 4611686018427387904 * -2 < 0 }",
        &[],
        true,
    );
    check(
        "rule test { condition: -4611686018427387904 * 2 < 0 }",
        &[],
        true,
    );

    check(
        "rule test { condition: -4611686018427387904 * -2 }",
        &[],
        false,
    );
}

#[test]
fn test_bitwise_operators() {
    check("rule test { condition: 0x55 | 0xAA == 0xFF }", &[], true);
    check(
        "rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }",
        &[],
        true,
    );
    check("rule test { condition: ~0x55 & 0xFF == 0xAA }", &[], true);
    check("rule test { condition: 8 >> 2 == 2 }", &[], true);
    check("rule test { condition: 1 << 3 == 8 }", &[], true);

    check("rule test { condition: 1 << 64 == 0 }", &[], true);
    check("rule test { condition: 1 >> 64 == 0 }", &[], true);

    // TODO: generate parsing error to align on libyara?
    if false {
        check("rule test { condition: 1 << -1 == 0 }", &[], false);
        check("rule test { condition: 1 >> -1 == 0 }", &[], false);
    }
    check(
        "rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }",
        &[],
        true,
    );
    check(
        "rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }",
        &[],
        false,
    );
    check(
        "rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}",
        &[],
        false,
    );
}

#[test]
fn test_string_operators() {
    check(
        "rule test { condition: \"foobarbaz\" contains \"bar\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" contains \"foo\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" contains \"baz\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" icontains \"BAR\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" icontains \"BaR\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"FooBarBaz\" icontains \"bar\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"FooBarBaz\" icontains \"baz\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"FooBarBaz\" icontains \"FOO\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" contains \"foo\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" contains \"baz\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" contains \"baq\" }",
        &[],
        false,
    );
    check(
        "rule test { condition: \"foo\" contains \"foob\" }",
        &[],
        false,
    );
    check(
        "rule test { condition: \"foobarbaz\" startswith \"foo\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" istartswith \"Foo\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"FooBarBaz\" istartswith \"fOO\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" startswith \"fob\" }",
        &[],
        false,
    );
    check(
        "rule test { condition: \"foobarbaz\" endswith \"baz\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" iendswith \"baZ\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" iendswith \"BaZ\" }",
        &[],
        true,
    );
    check(
        "rule test { condition: \"foobarbaz\" endswith \"ba\" }",
        &[],
        false,
    );
}

#[test]
fn test_syntax() {
    check_err(
        "rule test { strings: $a = \"a\" $a = \"a\" condition: all of them }",
        "error: variable $a is declared more than once",
    );

    check_err(
        "rule test { strings: $a = /a.c/ xor condition: $a }",
        "mem:1:33: error: syntax error",
    );

    check_err(
        "rule test { strings: $a = /abc/ xor condition: $a }",
        "mem:1:33: error: syntax error",
    );

    check_err(
        "rule test { strings: $a = {01 02 ?? 03 04} xor condition: $a }",
        "mem:1:44: error: syntax error",
    );

    check_err(
        "rule test { strings: $a = {01 02 0? 03 04} xor condition: $a }",
        "mem:1:44: error: syntax error",
    );

    check_err(
        "rule test { strings: $a = {01 02 03 04} xor condition: $a }",
        "mem:1:41: error: syntax error",
    );

    check_err("rule test rule test", "mem:1:11: error: syntax error");
}
