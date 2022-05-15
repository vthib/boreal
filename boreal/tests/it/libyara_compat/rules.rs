//! Tests imported from test_rules.c in YARA codebase.
//!
//! Those tests are directly copied from the yara codebase, and adapted to test them using boreal
//! as well. Do not modify those tests in any way. Custom tests should go in the other integration
//! tests, outside of the `libyara` directory.
use const_format::concatcp;

use super::util::{PE32_FILE, TEXT_1024_BYTES};
use crate::utils::{check, check_boreal, check_err, check_file};

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
        "import \"tests\"
    rule test {
        condition:
        not (tests.undefined.i and true)
    }",
        &[],
        true,
    );

    check(
        "import \"tests\"
    rule test {
        condition:
        not (true and tests.undefined.i)
    }",
        &[],
        true,
    );

    check(
        "import \"tests\"
    rule test {
        condition:
        not tests.string_array[4] contains \"foo\"
    }",
        &[],
        false,
    );

    // TODO: implement dictionaries
    // check(
    //     "import \"tests\"
    // rule test {
    //     condition:
    //     not tests.string_dict[\"undefined\"] matches /foo/
    // }",
    //     &[],
    //     false,
    // );

    check(
        "import \"tests\"
    rule test {
        condition:
        not tests.undefined.i
    }",
        &[],
        false,
    );

    check(
        "import \"tests\"
    rule test {
        condition:
        not (tests.undefined.i)
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

#[test]
fn test_anonymous_strings() {
    check(
        "rule test { strings: $ = \"a\" $ = \"b\" condition: all of them }",
        b"ab",
        true,
    );
}

#[test]
fn test_strings() {
    let s = concatcp!(TEXT_1024_BYTES, "---- abc ---- xyz").as_bytes();
    let blob = concatcp!(TEXT_1024_BYTES, "---- a\0b\0c\0 -\0-\0-\0-\0x\0y\0z\0").as_bytes();

    check("rule test { strings: $a = \"a\" condition: $a }", s, true);

    check("rule test { strings: $a = \"ab\" condition: $a }", s, true);

    check("rule test { strings: $a = \"abc\" condition: $a }", s, true);

    check("rule test { strings: $a = \"xyz\" condition: $a }", s, true);

    check(
        "rule test { strings: $a = \"abc\" nocase fullword condition: $a }",
        s,
        true,
    );

    check(
        "rule test { strings: $a = \"aBc\" nocase  condition: $a }",
        s,
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        s,
        true,
    );

    check(
        "rule test { strings: $a = \"a\" fullword condition: $a }",
        s,
        false,
    );

    check(
        "rule test { strings: $a = \"ab\" fullword condition: $a }",
        s,
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        s,
        false,
    );

    check(
        "rule test { strings: $a = \"a\" wide condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"a\" wide ascii condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"ab\" wide condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"ab\" wide ascii condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" wide condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" wide nocase fullword condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"aBc\" wide nocase condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"aBc\" wide ascii nocase condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"---xyz\" wide nocase condition: $a }",
        blob,
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abc").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "xabcx").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "xabc").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcx").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" wide condition: $a }",
        concatcp!(TEXT_1024_BYTES, "a\x01b\0c\0d\0e\0f\0").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abcdef\" wide condition: $a }",
        concatcp!(TEXT_1024_BYTES, "a\0b\0c\0d\0e\0f\x01").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcx").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" ascii wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "a\0abc").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "a\0b\0c\0").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "x\0a\0b\0c\0x\0").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"ab\" wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "x\0a\0b\0").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "x\0a\0b\0c\0").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = \"abc\" wide fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "x\x01a\0b\0c\0").as_bytes(),
        true,
    );

    check(
        r#"rule test { strings: $a = "\t\r\n\"\\" condition: $a }"#,
        concatcp!(TEXT_1024_BYTES, "\t\r\n\"\\").as_bytes(),
        true,
    );

    check(
        "rule test {
         strings:
             $a = \"abcdef\"
             $b = \"cdef\"
             $c = \"ef\"
         condition:
             all of them
       }",
        concatcp!(TEXT_1024_BYTES, "abcdef").as_bytes(),
        true,
    );

    // TODO: test with libyara when yara-rust is update to 4.2.0
    check_boreal(
        "rule test {
         strings:
             $a = \"foo\"
             $b = \"bar\"
             $c = \"baz\"
         condition:
             all of them in (0..10)
       }",
        concatcp!("foobarbaz", TEXT_1024_BYTES).as_bytes(),
        true,
    );

    // TODO: test with libyara when yara-rust is update to 4.2.0
    check_boreal(
        "rule test {
         strings:
             $a = \"foo\"
         condition:
             #a == 3 and #a in (0..10) == 2
       }",
        concatcp!("foofoo", TEXT_1024_BYTES, "foo").as_bytes(),
        true,
    );

    // xor by itself will match the plaintext version of the string too.
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor
      condition:
        #a == 256
    }",
        "assets/libyara/data/xor.out",
        true,
    );

    // Make sure the combination of xor and ascii behaves the same as just xor.
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor ascii
      condition:
        #a == 256
    }",
        "assets/libyara/data/xor.out",
        true,
    );

    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor(1-0x10)
      condition:
        #a == 16
    }",
        "assets/libyara/data/xor.out",
        true,
    );

    // We should have no matches here because we are not generating the ascii
    // string, just the wide one, and the test data contains no wide strings.
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor wide
      condition:
        #a == 0
    }",
        "assets/libyara/data/xor.out",
        true,
    );

    // xor by itself is equivalent to xor(0-255).
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor wide
      condition:
        #a == 256
    }",
        "assets/libyara/data/xorwide.out",
        true,
    );

    // This DOES NOT look for the plaintext wide version by itself.
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor(1-16) wide
      condition:
        #a == 16
    }",
        "assets/libyara/data/xorwide.out",
        true,
    );

    // Check the location of the match to make sure we match on the correct one.
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor(1) wide
      condition:
        #a == 1 and @a == 0x2f
    }",
        "assets/libyara/data/xorwide.out",
        true,
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"This program cannot\" xor(300)
      condition:
        $a
    }",
        "mem:3:40: error: xor range value 300 invalid, must be in [0-255]",
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"This program cannot\" xor(200-10)
      condition:
        $a
    }",
        "mem:3:39: error: xor range invalid: 200 > 10",
    );

    // ERROR_SYNTAX_ERROR
    check_err(
        "rule test {
      strings:
        $a = {00 11 22 33} xor
      condition:
        $a
    }",
        "mem:3:28: error: syntax error",
    );

    // ERROR_SYNTAX_ERROR
    check_err(
        "rule test {
      strings:
        $a = /foo(bar|baz)/ xor
      condition:
        $a
    }",
        "mem:3:29: error: syntax error",
    );

    // ERROR_DUPLICATED_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" xor xor
      condition:
        $a
    }",
        "mem:3:19: error: string modifier XOR appears multiple times",
    );

    // We should have no matches here because we are not generating the wide
    // string, just the ascii one, and the test data contains no ascii strings.
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor ascii
      condition:
        #a == 0
    }",
        "assets/libyara/data/xorwide.out",
        true,
    );

    // This should match 512 times because we are looking for the wide and ascii
    // versions in plaintext and doing xor(0-255) (implicitly)
    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" xor wide ascii
      condition:
        #a == 512
    }",
        "assets/libyara/data/xorwideandascii.out",
        true,
    );

    check_file(
        "rule test {
      strings:
        $a = \"This program cannot\" wide ascii
      condition:
        #a == 2
    }",
        "assets/libyara/data/xorwideandascii.out",
        true,
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" xor nocase
      condition:
        true
    }",
        "mem:3:19: error: string modifiers xor and nocase are incompatible",
    );

    check(
        "rule test {
        strings:
          $a = \"AXS\" private
      condition:
        all of them
      }",
        concatcp!(TEXT_1024_BYTES, "AXS").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings:
          $a = { 45 52 53 } private
      condition:
        all of them
      }",
        concatcp!(TEXT_1024_BYTES, "ERS").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings:
          $a = /AXS[0-9]{4}ERS[0-9]{4}/ private
      condition:
        all of them
      }",
        concatcp!(TEXT_1024_BYTES, "AXS1111ERS2222").as_bytes(),
        true,
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" base64 nocase
      condition:
        true
    }",
        "mem:3:19: error: string modifiers base64 and nocase are incompatible",
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" base64 xor
      condition:
        true
    }",
        "mem:3:19: error: string modifiers base64 and xor are incompatible",
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" base64 fullword
      condition:
        true
    }",
        "mem:3:19: error: string modifiers base64 and fullword are incompatible",
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" base64(\"AXS\")
      condition:
        true
    }",
        "mem:3:26: error: base64 modifier alphabet must contain exactly 64 characters",
    );

    // ERROR_INVALID_MODIFIER
    check_err(
        "rule test {
      strings:
        $a = \"ab\" base64wide(\"ERS\")
      condition:
        true
    }",
        "mem:3:30: error: base64 modifier alphabet must contain exactly 64 characters",
    );

    // Specifying different alphabets is an error.
    // ERROR_INVALID_MODIFIER
    check_err(
      "rule test {
      strings:
        $a = \"ab\" base64 base64wide(\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ,.\")
      condition:
        true
    }", "mem:3:19: error: alphabets used for base64 and base64wide must be identical");

    // Be specific about the offsets in these tests to make sure we are matching
    // the correct strings. Also be specific about the length because we want to
    // make sure the match is not the entire base64 string, but just the
    // substrings which are not dependent upon leading or trailing bytes.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64
        condition:
          #a == 6 and
          @a[1] == 0x53 and
          !a[1] == 25 and
          @a[2] == 0x70 and
          !a[2] == 25 and
          @a[3] == 0xa2 and
          !a[3] == 24 and
          @a[4] == 0xbd and
          !a[4] == 24 and
          @a[5] == 0xef and
          !a[5] == 25 and
          @a[6] == 0x109 and
          !a[6] == 25
      }",
        "assets/libyara/data/base64",
        true,
    );

    // This is identical to "base64" alone, but test it to make sure we don't
    // accidentally include the plaintext in the base64 search.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64 ascii
        condition:
          #a == 6 and
          @a[1] == 0x53 and
          !a[1] == 25 and
          @a[2] == 0x70 and
          !a[2] == 25 and
          @a[3] == 0xa2 and
          !a[3] == 24 and
          @a[4] == 0xbd and
          !a[4] == 24 and
          @a[5] == 0xef and
          !a[5] == 25 and
          @a[6] == 0x109 and
          !a[6] == 25
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Make sure the wide modifier is applied BEFORE the base64 and we do NOT
    // include the wide plaintext string.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64 wide
        condition:
          #a == 6 and
          @a[1] == 0x1b5 and
          !a[1] == 50 and
          @a[2] == 0x1ea and
          !a[2] == 50 and
          @a[3] == 0x248 and
          !a[3] == 50 and
          @a[4] == 0x27b and
          !a[4] == 50 and
          @a[5] == 0x2db and
          !a[5] == 50 and
          @a[6] == 0x311 and
          !a[6] == 50
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Make sure that both wide and ascii are base64 encoded. We can skip the
    // verbose length and offset check_files, since the previous tests cover that.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64 wide ascii
        condition:
          #a == 12
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Make sure that the two strings are generated when one ascii byte is
    // base64 encoded. When stripped, third base64 encoded is null.
    check_file(
        "rule test {
        strings:
          $a = \"a\" base64
          $b = \"a\" base64wide
        condition:
          @a[58] == 0x6ac and
          @a[59] == 0x6b9 and
          @b[15] == 0x6f7 and
          @b[16] == 0x711
      }",
        "assets/libyara/data/base64",
        true,
    );

    // In the future, assert false if character classes are generated instead
    // of stripping the leading and trailing characters
    check_file(
        "rule test {
        strings:
          $a = \"Dhis program cannow\" base64
        condition:
          #a == 2 and
          @a[1] == 0xa2 and
          @a[2] == 0xbd
      }",
        "assets/libyara/data/base64",
        true,
    );

    // This check_files for the ascii string in base64 form then widened.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64wide
        condition:
          #a == 3 and
          @a[1] == 0x379 and
          !a[1] == 50 and
          @a[2] == 0x3b6 and
          !a[2] == 48 and
          @a[3] == 0x3f1 and
          !a[3] == 50
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Logically identical to the test above but include it to make sure we don't
    // accidentally include the plaintext in the future.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64wide ascii
        condition:
          #a == 3 and
          @a[1] == 0x379 and
          !a[1] == 50 and
          @a[2] == 0x3b6 and
          !a[2] == 48 and
          @a[3] == 0x3f1 and
          !a[3] == 50
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Make sure the wide string is base64wide encoded.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64wide wide
        condition:
          #a == 3 and
          @a[1] == 0x458 and
          !a[1] == 100 and
          @a[2] == 0x4c5 and
          !a[2] == 100 and
          @a[3] == 0x530 and
          !a[3] == 100
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Make sure both ascii and wide strings are base64wide encoded properly.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64wide wide ascii
        condition:
          #a == 6 and
          @a[1] == 0x379 and
          !a[1] == 50 and
          @a[2] == 0x3b6 and
          !a[2] == 48 and
          @a[3] == 0x3f1 and
          !a[3] == 50 and
          @a[4] == 0x458 and
          !a[4] == 100 and
          @a[5] == 0x4c5 and
          !a[5] == 100 and
          @a[6] == 0x530 and
          !a[6] == 100
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Make sure base64 and base64wide together work.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64 base64wide
        condition:
          #a == 9 and
          @a[1] == 0x53 and
          !a[1] == 25 and
          @a[2] == 0x70 and
          !a[2] == 25 and
          @a[3] == 0xa2 and
          !a[3] == 24 and
          @a[4] == 0xbd and
          !a[4] == 24 and
          @a[5] == 0xef and
          !a[5] == 25 and
          @a[6] == 0x109 and
          !a[6] == 25 and
          @a[7] == 0x379 and
          !a[7] == 50 and
          @a[8] == 0x3b6 and
          !a[8] == 48 and
          @a[9] == 0x3f1 and
          !a[9] == 50
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Identical to the test above but useful to make sure we don't accidentally
    // include the ascii plaintext in the future.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64 base64wide ascii
        condition:
          #a == 9
      }",
        "assets/libyara/data/base64",
        true,
    );

    // Making sure we don't accidentally include the wide plaintext in the future.
    check_file(
        "rule test {
        strings:
          $a = \"This program cannot\" base64 base64wide wide
        condition:
          #a == 9
      }",
        "assets/libyara/data/base64",
        true,
    );

    check_file(
        r#"rule test {
        strings:
          $a = "This program cannot" base64("!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
        condition:
          #a == 3 and
          @a[1] == 0x619 and
          !a[1] == 25 and
          @a[2] == 0x638 and
          !a[2] == 24 and
          @a[3] == 0x656 and
          !a[3] == 25
      }"#,
        "assets/libyara/data/base64",
        true,
    );
}

#[test]
fn test_wildcard_strings() {
    check(
        "rule test {
         strings:
             $s1 = \"abc\"
             $s2 = \"xyz\"
         condition:
             for all of ($*) : ($)
      }",
        concatcp!(TEXT_1024_BYTES, "---- abc ---- A\x00B\x00C\x00 ---- xyz").as_bytes(),
        true,
    );
}

#[test]
fn test_hex_strings() {
    check(
        "rule test {
        strings: $a = { 64 01 00 00 60 01 }
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 64 0? 00 00 ?0 01 }
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 6? 01 00 00 60 0? }
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 64 01 [1-3] 60 01 }
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 64 01 [1-3] (60|61) 01 }
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 4D 5A [-] 6A 2A [-] 58 C3}
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 4D 5A [300-] 6A 2A [-] 58 C3}
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 2e 7? (65 | ?? ) 78 }
        condition: $a }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 4D 5A [0-300] 6A 2A }
        condition: $a }",
        PE32_FILE,
        false,
    );

    check(
        "rule test {
        strings: $a = { 4D 5A [0-128] 45 [0-128] 01 [0-128]  C3 }
        condition: $a }",
        PE32_FILE,
        false,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [-] 38 39 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = {\n 31 32 [-] 38 39 \n\r}
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 } private
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [1] 34 35 [2] 38 39 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
         strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 }
         condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-2] 35 [1-] 37 38 39 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-1] 33 }
        condition: !a == 3}",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-1] 34 }
        condition: !a == 4}",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-2] 34 }
        condition: !a == 4 }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [-] 38 39 }
        condition: all of them }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [-] 32 33 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        false,
    );

    check(
        "rule test {
        strings: $a = { 35 36 [-] 31 32 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        false,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [2-] 34 35 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        false,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-1] 33 34 [0-2] 36 37 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-1] 34 35 [0-2] 36 37 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-3] 37 38 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        false,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [1] 33 34 }
        condition: $a }",
        concatcp!(TEXT_1024_BYTES, "12\n34").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = {31 32 [3-6] 32}
        condition: !a == 6 }",
        concatcp!(TEXT_1024_BYTES, "12111222").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = {31 [0-3] (32|33)}
        condition: !a == 2 }",
        concatcp!("122222222", TEXT_1024_BYTES).as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 30 31 32 [0-5] 38 39 }
        condition: $a }",
        b"0123456789",
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-5] 38 39 30 }
        condition: $a }",
        b"1234567890",
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-2] 34 [0-2] 34 }
        condition: $a }",
        b"1244",
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-2] 34 [0-2] 34 }
        condition: $a }",
        b"12344",
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [0-2] 34 [0-2] 34 [2-3] 34 }
        condition: $a }",
        b"123440004",
        true,
    );

    // ERROR_INVALID_HEX_STRING
    check_err(
        "rule test {
        strings: $a = { 01 [0] 02 }
        condition: $a }",
        "mem:2:28: error: jump cannot have a length of 0",
    );

    // ERROR_INVALID_HEX_STRING
    check_err(
        "rule test {
        strings: $a = { [-] 01 02 } condition: $a }",
        "mem:2:25: error: a list of tokens cannot start or end with a jump",
    );

    // ERROR_INVALID_HEX_STRING
    check_err(
        "rule test {
        strings: $a = { 01 02 [-] }
        condition: $a }",
        "mem:2:25: error: a list of tokens cannot start or end with a jump",
    );

    // ERROR_INVALID_HEX_STRING
    check_err(
        "rule test {
        strings: $a = { 01 02 ([-] 03 | 04) }
        condition: $a }",
        "mem:2:32: error: unbounded jumps not allowed inside alternations (|)",
    );

    // ERROR_INVALID_HEX_STRING
    check_err(
        "rule test {
        strings: $a = { 01 02 (03 [-] | 04) }
        condition: $a }",
        "mem:2:35: error: unbounded jumps not allowed inside alternations (|)",
    );

    // ERROR_INVALID_HEX_STRING
    check_err(
        "rule test {
        strings: $a = { 01 02 (03 | 04 [-]) }
        condition: $a ",
        "mem:2:40: error: unbounded jumps not allowed inside alternations (|)",
    );
}

#[test]
fn test_count() {
    check(
        "rule test { strings: $a = \"ssi\" condition: #a == 2 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" private condition: #a == 2 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );
}

#[test]
fn test_at() {
    check(
        "rule test {
        strings: $a = \"ssi\"
        condition: $a at (1024+2) and $a at (1024+5) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = \"ssi\" private
        condition: $a at (1024+2) and $a at (1024+5) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = \"mis\"
        condition: $a at (1024+(~0xFF & 0xFF)) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 00 00 00 00 ?? 74 65 78 74 }
        condition: $a at 308}",
        PE32_FILE,
        true,
    );
}

// FIXME: implement entrypoint
#[ignore]
#[test]
fn test_in() {
    check(
        "rule test {
        strings: $a = { 6a 2a 58 c3 }
        condition: $a in (entrypoint .. entrypoint + 1) }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { 6a 2a 58 c3 } private
        condition: $a in (entrypoint .. entrypoint + 1) }",
        PE32_FILE,
        true,
    );
}

#[test]
fn test_offset() {
    check(
        "rule test { strings: $a = \"ssi\" condition: @a == (1024+2) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" private condition: @a == (1024+2) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" condition: @a == @a[1] }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" condition: @a[2] == (1024+5) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );
}

#[test]
fn test_length() {
    check(
        "rule test { strings: $a = /m.*?ssi/ condition: !a == 5 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /m.*?ssi/ private condition: !a == 5 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /m.*?ssi/ condition: !a[1] == 5 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /m.*ssi/ condition: !a == 8 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /m.*ssi/ condition: !a[1] == 8 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ssi.*ppi/ condition: !a[1] == 9 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ssi.*ppi/ condition: !a[2] == 6 }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = { 6D [1-3] 73 73 69 } condition: !a == 5}",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = { 6D [-] 73 73 69 } condition: !a == 5}",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = { 6D [-] 70 70 69 } condition: !a == 11}",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = { 6D 69 73 73 [-] 70 69 } condition: !a == 11}",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );
}

#[test]
fn test_of() {
    check(
        "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\"
      condition: any of them }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\"
      condition: none of them }",
        concatcp!(TEXT_1024_BYTES, "AXSERS").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" $b = \"mis\" private $c = \"oops\"
      condition: 1 of them }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = \"ssi\" $b = \"mis\" $c = \"oops\"
      condition: 2 of them }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    // FIXME: implement rule of
    // check(
    //     "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\"
    //   condition: any of ($a*, $b*) }",
    //     concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
    //     true,
    // );
    //
    // check(
    //     "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\"
    //   condition: none of ($a*, $b*) }",
    //     concatcp!(TEXT_1024_BYTES, "AXSERS").as_bytes(),
    //     true,
    // );

    check(
        "rule test {
         strings:
           $ = /abc/
           $ = /def/
           $ = /ghi/
         condition:
           for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )
       }",
        concatcp!(TEXT_1024_BYTES, "abc\0def\0ghi").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings:
          $a = \"ssi\"
          $b = \"mis\"
          $c = \"oops\"
        condition:
          all of them
      }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        false,
    );

    // FIXME: implement rule of
    // check_err("rule test { condition: all of ($a*) }", "z");

    check_err(
        "rule test { condition: all of them }",
        "mem:1:24: error: unknown variable $*",
    );

    // TODO: ideally, catch those in future simplifying step.
    if false {
        check_err(
            "rule test { strings: $a = \"AXS\" condition: 101% of them }",
            "z",
        );

        check_err(
            "rule test { strings: $a = \"ERS\" condition: 0% of them }",
            "z",
        );
    }

    check(
        "rule test {
        strings:
          $a1 = \"dummy\"
          $a2 = \"issi\"
        condition:
          50% of them
      }",
        b"mississippi",
        true,
    );

    // This is equivalent to "50% of them" because 1050%50 == 50
    check(
        "rule test {
        strings:
          $a1 = \"miss\"
          $a2 = \"issi\"
        condition:
          1050%100% of them
      }",
        b"mississippi",
        true,
    );

    check(
        "rule test {
        strings:
          $a1 = \"miss\"
          $a2 = \"issi\"
        condition:
          100% of them
      }",
        b"mississippi",
        true,
    );

    check(
        "import \"tests\"
       rule test {
         strings:
           $a1 = \"miss\"
           $a2 = \"issi\"
         condition:
           (25*tests.constants.two)% of them
       }",
        b"mississippi",
        true,
    );

    // tests.integer_array[5] is undefined, so the following rule must evaluate
    // to false.
    check(
        "import \"tests\"
       rule test {
         strings:
           $a1 = \"miss\"
           $a2 = \"issi\"
         condition:
           tests.integer_array[5]% of them
       }",
        b"mississippi",
        false,
    );
}

#[test]
fn test_for() {
    check(
        "rule test {
        strings:
          $a = \"ssi\"
        condition:
          for all i in (1..#a) : (@a[i] >= (1024+2) and @a[i] <= (1024+5))
      }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings:
          $a = \"ssi\"
          $b = \"mi\"
        condition:
          for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j]))
      }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings:
          $a = \"ssi\"
        condition:
          for all i in (1..#a) : (@a[i] == (1024+5))
      }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        false,
    );

    check(
        "rule test {
        condition:
          for any i in (1, 2, 3) : (i <= 1)
      }",
        b"",
        true,
    );

    check(
        "rule test {
        condition:
          for all i in (1, 2, 3) : (i >= 1)
      }",
        b"",
        true,
    );

    check(
        "rule test {
        condition:
          for all i in (1, 0) : (i != 1)
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for any item in tests.struct_array : (
            item.i == 1
          )
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for 0 item in tests.struct_array : (
            item.i == 100
          )
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for any item in tests.integer_array : (
            item == 2
          )
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for any item in tests.string_array : (
            item == \"bar\"
          )
      }",
        b"",
        true,
    );

    check(
        "rule test {
        condition:
          for all i in (3,5,4) : (
            i >= 3 and i <= 5
          )
      }",
        b"",
        true,
    );

    check(
        "rule test {
        condition:
          for all i in (3..5) : (
            i >= 3 and i <= 5
          )
      }",
        b"",
        true,
    );

    check(
        "rule test {
        condition:
          for 2 i in (5..10) : (
            i == 6 or i == 7
          )
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for any k,v in tests.empty_struct_dict : (
            true
          )
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for all i in (1..tests.undefined.i) : (
            true
          )
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for all i in (tests.undefined.i..10) : (
            true
          )
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for all i in (1..tests.undefined.i) : (
            false
          )
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for any k,v in tests.struct_dict : (
            k == \"foo\" and v.s == \"foo\" and v.i == 1
          )
      }",
        b"",
        true,
    );

    check_err(
        "import \"tests\"
      rule test {
        condition:
          for any k,v in tests.integer_array : ( false )
      }",
        "mem:4:19: error: expected 1 identifiers to bind, got 2",
    );

    check_err(
        "import \"tests\"
      rule test {
        condition:
          for any a,b,c in tests.struct_dict : ( false )
      }",
        "mem:4:19: error: expected 2 identifiers to bind, got 3",
    );

    check_err(
        "import \"tests\"
      rule test {
        condition:
          for any i in tests.struct_dict : ( false )
      }",
        "mem:4:19: error: expected 2 identifiers to bind, got 1",
    );

    check_err(
        "import \"tests\"
      rule test {
        condition:
          for any i in tests.integer_array : ( undefined_ident )
      }",
        "mem:4:48: error: unknown identifier \"undefined_ident\"",
    );

    check_err(
        "import \"tests\"
      rule test {
        condition:
          for any i in tests.integer_array : ( i == \"foo\" )
      }",
        "error: expressions have invalid types",
    );

    check(
        "rule test {
        condition:
          for any i in (0,1): (
            for any j in (0,1): (
              for any k in (0,1): (
                for any l in (0,1): (
                  false
                )
              )
            )
        )
      }",
        b"",
        false,
    );
}
