//! Tests imported from test_rules.c in YARA codebase.
//!
//! Those tests are directly copied from the yara codebase, and adapted to test them using boreal
//! as well. Do not modify those tests in any way. Custom tests should go in the other integration
//! tests, outside of the `libyara` directory.
use const_format::concatcp;

use super::util::{ISSUE_1006, PE32_FILE, TEXT_1024_BYTES};
use crate::utils::{check, check_count, check_err, check_file, Checker};

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
    // TODO: implement constants
    // check("rule test { condition: not var_false }", b"", true);
    // check("rule test { condition: var_true }", b"", true);
    // check("rule test { condition: var_false }", b"", false);
    // check("rule test { condition: not var_true }", b"", false);

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

    check(
        "import \"tests\"
    rule test {
        condition:
        not tests.string_dict[\"undefined\"] matches /foo/
    }",
        &[],
        false,
    );

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

    // TODO: implement constants
    // check("rule test { condition: var_one*3 == 3}", b"", true);
    // check("rule test { condition: var_zero*3 == 0}", b"", true);

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
        "mem:1:31: error: variable $a is declared more than once",
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

    check(
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

    // https://github.com/VirusTotal/yara/issues/1660
    check(
        "rule test {
         strings:
             $a = \"foo\"
             $b = \"bar\"
             $c = \"baz\"
         condition:
             all of them in (0..1)
       }",
        TEXT_1024_BYTES.as_bytes(),
        false,
    );

    check(
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

#[test]
#[cfg(feature = "object")]
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
fn test_rule_of() {
    check_count(
        "rule a { condition: true }
         rule b { condition: 1 of (a) }",
        b"",
        2,
    );

    check_count(
        "rule a1 { condition: true }
         rule a2 { condition: true }
         rule b { condition: 2 of (a*) }",
        b"",
        3,
    );

    check_count(
        "rule a1 { condition: true }
         rule a2 { condition: false }
         rule b { condition: 50% of (a*) }",
        b"",
        2,
    );

    check_err(
        "rule a { condition: all of (b*) }",
        "mem:1:21: error: unknown identifier \"b*\"",
    );

    check_err(
        "rule a0 { condition: true }
         rule b { condition: 1 of (a*) }
         rule a1 { condition: true } ",
        r#"error: rule "a1" matches a previous rule set "a*""#,
    );

    // Make sure repeating the rule set works
    check_count(
        "rule a { condition: true }
         rule b { condition: 1 of (a*) }
         rule c { condition: 1 of (a*) }",
        b"",
        3,
    );

    // This will compile but is false for the same reason that
    // "rule x { condition: x }" is compiles but is false.
    // TODO: handle this...
    // check("rule a { condition: 1 of (a*) }", b"", false);
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

    check(
        "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\"
      condition: any of ($a*, $b*) }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a1 = \"dummy1\" $b1 = \"dummy1\" $b2 = \"ssi\"
      condition: none of ($a*, $b*) }",
        concatcp!(TEXT_1024_BYTES, "AXSERS").as_bytes(),
        true,
    );

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

    check_err(
        "rule test { condition: all of ($a*) }",
        "mem:1:24: error: unknown variable $a*",
    );

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

#[test]
fn test_re() {
    fn build_regex_rule(regex: &str) -> String {
        // XXX: this is modified from the libyara version, to force boreal
        // to compute all matches of the string
        format!(
            "rule test {{ strings: $a = /{}/ condition: $a and #a > 0 }}",
            regex
        )
    }

    #[track_caller]
    fn check_regex_match(regex: &str, mem: &[u8], expected_match: &[u8]) {
        let checker = Checker::new(&build_regex_rule(regex));
        checker.check_str_has_match(mem, expected_match);
    }

    check(
        "rule test { strings: $a = /ssi/ condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ssi(s|p)/ condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ssim*/ condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ssa?/ condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /Miss/ nocase condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /(M|N)iss/ nocase condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /[M-N]iss/ nocase condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ppi\\tmi/ condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /ppi\\.mi/ condition: $a }",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /^mississippi/ fullword condition: $a }",
        concatcp!(
            "mississippi\tmississippi.mississippi\nmississippi",
            TEXT_1024_BYTES
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /mississippi.*mississippi$/s condition: $a}",
        concatcp!(
            TEXT_1024_BYTES,
            "mississippi\tmississippi.mississippi\nmississippi"
        )
        .as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /^ssi/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /ssi$/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /ssissi/ fullword condition: $a }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /^[isp]+/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "mississippi").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 6 }",
        concatcp!(TEXT_1024_BYTES, "a\0x\0b\0").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 8 }",
        concatcp!(TEXT_1024_BYTES, "a\0x\0x\0b\0").as_bytes(),
        true,
    );

    // TODO: handle boundaries and wide modifier
    // check(
    //     "rule test { strings: $a = /\\babc/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "a\0b\0c\0").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /\\babc/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "\0a\0b\0c\0").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /\\babc/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "\ta\0b\0c\0").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /\\babc/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "x\0a\0b\0c\0").as_bytes(),
    //     false,
    // );

    // check(
    //     "rule test { strings: $a = /\\babc/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "x\ta\0b\0c\0").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /abc\\b/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "a\0b\0c\0").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /abc\\b/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "a\0b\0c\0\0").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /abc\\b/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "a\0b\0c\0\t").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /abc\\b/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "a\0b\0c\0x\0").as_bytes(),
    //     false,
    // );

    // check(
    //     "rule test { strings: $a = /abc\\b/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "a\0b\0c\0b\t").as_bytes(),
    //     true,
    // );

    // check(
    //     "rule test { strings: $a = /\\b/ wide condition: $a }",
    //     concatcp!(TEXT_1024_BYTES, "abc").as_bytes(),
    //     false,
    // );

    check_err(
        &build_regex_rule(")"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_regex_match("abc", b"abc", b"abc");
    check(&build_regex_rule("abc"), b"xbc", false);
    check(&build_regex_rule("abc"), b"axc", false);
    check(&build_regex_rule("abc"), b"abx", false);
    check_regex_match("abc", b"xabcx", b"abc");
    check_regex_match("abc", b"ababc", b"abc");
    check_regex_match("a.c", b"abc", b"abc");
    check(&build_regex_rule("a.b"), b"a\nb", false);
    check(&build_regex_rule("a.*b"), b"acc\nccb", false);
    check(&build_regex_rule("a.{4,5}b"), b"acc\nccb", false);
    check_regex_match("a.b", b"a\rb", b"a\rb");
    check_regex_match("ab*c", b"abc", b"abc");
    check_regex_match("ab*c", b"ac", b"ac");
    check_regex_match("ab*bc", b"abc", b"abc");
    check_regex_match("ab*bc", b"abbc", b"abbc");
    check_regex_match("a.*bb", b"abbbb", b"abbbb");
    check_regex_match("a.*?bbb", b"abbbbbb", b"abbb");
    check_regex_match("a.*c", b"ac", b"ac");
    check_regex_match("a.*c", b"axyzc", b"axyzc");
    check_regex_match("ab+c", b"abbc", b"abbc");
    check(&build_regex_rule("ab+c"), b"ac", false);
    check_regex_match("ab+", b"abbbb", b"abbbb");
    check_regex_match("ab+?", b"abbbb", b"ab");
    check(&build_regex_rule("ab+bc"), b"abc", false);
    check(&build_regex_rule("ab+bc"), b"abq", false);
    check_regex_match("a+b+c", b"aabbabc", b"abc");
    check(&build_regex_rule("ab?bc"), b"abbbbc", false);
    check_regex_match("ab?c", b"abc", b"abc");
    check_regex_match("ab*?", b"abbb", b"a");
    check_regex_match("ab?c", b"ac", b"ac");
    check_regex_match("ab??", b"ab", b"a");
    check_regex_match("a(b|x)c", b"abc", b"abc");
    check_regex_match("a(b|x)c", b"axc", b"axc");
    check_regex_match("a(b|.)c", b"axc", b"axc");
    check_regex_match("a(b|x|y)c", b"ayc", b"ayc");
    check_regex_match("(a+|b)*", b"ab", b"ab");
    check_regex_match("a|b|c|d|e", b"e", b"e");
    check_regex_match("(a|b|c|d|e)f", b"ef", b"ef");
    check_regex_match("a|b", b"a", b"a");
    check_regex_match(".b{2}", b"abb", b"abb");
    check_regex_match(".b{2,3}", b"abbb", b"abbb");
    check_regex_match(".b{2,3}?", b"abbb", b"abb");
    check_regex_match("ab{2,3}c", b"abbbc", b"abbbc");
    check_regex_match("ab{2,3}?c", b"abbbc", b"abbbc");
    check_regex_match(".b{2,3}cccc", b"abbbcccc", b"abbbcccc");
    check_regex_match(".b{2,3}?cccc", b"abbbcccc", b"bbbcccc");
    check_regex_match("a.b{2,3}cccc", b"aabbbcccc", b"aabbbcccc");
    check_regex_match("ab{2,3}c", b"abbbc", b"abbbc");
    check_regex_match("ab{2,3}?c", b"abbbc", b"abbbc");
    check_regex_match("ab{0,1}?c", b"abc", b"abc");
    check_regex_match("a{0,1}?bc", b"abc", b"abc");
    check_regex_match("a{0,1}bc", b"bbc", b"bc");
    check_regex_match("a{0,1}?bc", b"abc", b"bc");
    check_regex_match("aa{0,1}?bc", b"abc", b"abc");
    check_regex_match("aa{0,1}?bc", b"abc", b"abc");
    check_regex_match("aa{0,1}bc", b"abc", b"abc");
    check_regex_match("ab{1}c", b"abc", b"abc");
    check_regex_match("ab{1,2}c", b"abbc", b"abbc");
    check(&build_regex_rule("ab{1,2}c"), b"abbbc", false);
    check_regex_match("ab{1,}c", b"abbbc", b"abbbc");
    check(&build_regex_rule("ab{1,}b"), b"ab", false);
    check(&build_regex_rule("ab{1}c"), b"abbc", false);
    check(&build_regex_rule("ab{1}c"), b"ac", false);
    check_regex_match("ab{0,}c", b"ac", b"ac");
    check_regex_match("ab{1,1}c", b"abc", b"abc");
    check_regex_match("ab{0,}c", b"abbbc", b"abbbc");

    // TODO: handle this syntax
    // check_regex_match("ab{,3}c", b"abbbc", b"abbbc");
    // check(&build_regex_rule("ab{,2}c"), b"abbbc", false);

    check(&build_regex_rule("ab{4,5}bc"), b"abbbbc", false);
    check(&build_regex_rule("ab{3}c"), b"abbbbc", false); // Issue #817
    check(&build_regex_rule("ab{4}c"), b"abbbbbc", false);
    check(&build_regex_rule("ab{5}c"), b"abbbbbbc", false);
    check_regex_match("ab{0,1}", b"abbbbb", b"ab");
    check_regex_match("ab{0,2}", b"abbbbb", b"abb");
    check_regex_match("ab{0,3}", b"abbbbb", b"abbb");
    check_regex_match("ab{0,4}", b"abbbbb", b"abbbb");
    check_regex_match("ab{1,1}", b"abbbbb", b"ab");
    check_regex_match("ab{1,2}", b"abbbbb", b"abb");
    check_regex_match("ab{1,3}", b"abbbbb", b"abbb");
    check_regex_match("ab{2,2}", b"abbbbb", b"abb");
    check_regex_match("ab{2,3}", b"abbbbb", b"abbb");
    check_regex_match("ab{2,4}", b"abbbbc", b"abbbb");
    check_regex_match("ab{3,4}", b"abbb", b"abbb");
    check_regex_match("ab{3,5}", b"abbbbb", b"abbbbb");
    check(&build_regex_rule("ab{3,4}c"), b"abbbbbc", false);
    check(&build_regex_rule("ab{3,4}c"), b"abbc", false);
    check(&build_regex_rule("ab{3,5}c"), b"abbbbbbc", false);
    check_regex_match("ab{1,3}?", b"abbbbb", b"ab");
    check_regex_match("ab{0,1}?", b"abbbbb", b"a");
    check_regex_match("ab{0,2}?", b"abbbbb", b"a");
    check_regex_match("ab{0,3}?", b"abbbbb", b"a");
    check_regex_match("ab{0,4}?", b"abbbbb", b"a");
    check_regex_match("ab{1,1}?", b"abbbbb", b"ab");
    check_regex_match("ab{1,2}?", b"abbbbb", b"ab");
    check_regex_match("ab{1,3}?", b"abbbbb", b"ab");
    check_regex_match("ab{2,2}?", b"abbbbb", b"abb");
    check_regex_match("ab{2,3}?", b"abbbbb", b"abb");
    check_regex_match("(a{2,3}b){2,3}", b"aabaaabaab", b"aabaaabaab");
    check_regex_match("(a{2,3}?b){2,3}?", b"aabaaabaab", b"aabaaab");
    check(
        &build_regex_rule("(a{4,5}b){4,5}"),
        b"aaaabaaaabaaaaab",
        false,
    );
    check_regex_match(
        "(a{4,5}b){4,5}",
        b"aaaabaaaabaaaaabaaaaab",
        b"aaaabaaaabaaaaabaaaaab",
    );
    check_regex_match(".(abc){0,1}", b"xabcabcabcabc", b"xabc");
    check_regex_match(".(abc){0,2}", b"xabcabcabcabc", b"xabcabc");
    check_regex_match("x{1,2}abcd", b"xxxxabcd", b"xxabcd");
    check_regex_match("x{1,2}abcd", b"xxxxabcd", b"xxabcd");

    // TODO: this is not supported by the regex crate
    // check_regex_match("ab{.*}", b"ab{c}", b"ab{c}");

    check_regex_match(".(aa){1,2}", b"aaaaaaaaaa", b"aaaaa");
    check_regex_match("a.(bc.){2}", b"aabcabca", b"aabcabca");
    check_regex_match("(ab{1,2}c){1,3}", b"abbcabc", b"abbcabc");
    check_regex_match("ab(c|cc){1,3}d", b"abccccccd", b"abccccccd");
    check_regex_match("a[bx]c", b"abc", b"abc");
    check_regex_match("a[bx]c", b"axc", b"axc");
    check_regex_match("a[0-9]*b", b"ab", b"ab");
    check_regex_match("a[0-9]*b", b"a0123456789b", b"a0123456789b");
    check_regex_match("[0-9a-f]+", b"0123456789abcdef", b"0123456789abcdef");
    check_regex_match("[0-9a-f]+", b"xyz0123456789xyz", b"0123456789");
    check_regex_match("a[\\s\\S]b", b"a b", b"a b");
    check_regex_match("a[\\d\\D]b", b"a1b", b"a1b");
    check(&build_regex_rule("[x-z]+"), b"abc", false);
    check_regex_match("a[-]?c", b"ac", b"ac");
    check_regex_match("a[-b]", b"a-", b"a-");
    check_regex_match("a[-b]", b"ab", b"ab");
    check_regex_match("a[b-]", b"a-", b"a-");
    check_regex_match("a[b-]", b"ab", b"ab");
    check_regex_match("[a-c-e]", b"b", b"b");
    check_regex_match("[a-c-e]", b"-", b"-");
    check(&build_regex_rule("[a-c-e]"), b"d", false);

    check_err(
        &build_regex_rule("[b-a]"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_err(
        &build_regex_rule("(abc"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_err(
        &build_regex_rule("abc)"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_err(
        &build_regex_rule("a[]b"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_regex_match("a[\\-b]", b"a-", b"a-");
    check_regex_match("a[\\-b]", b"ab", b"ab");
    check_regex_match("a]", b"a]", b"a]");
    check_regex_match("a[]]b", b"a]b", b"a]b");
    check_regex_match("a[\\]]b", b"a]b", b"a]b");
    check_regex_match("a[^bc]d", b"aed", b"aed");
    check(&build_regex_rule("a[^bc]d"), b"abd", false);
    check_regex_match("a[^-b]c", b"adc", b"adc");
    check(&build_regex_rule("a[^-b]c"), b"a-c", false);
    check(&build_regex_rule("a[^]b]c"), b"a]c", false);
    check_regex_match("a[^]b]c", b"adc", b"adc");
    check_regex_match("[^ab]*", b"cde", b"cde");
    check_err(
        &build_regex_rule(")("),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_regex_match("a\\sb", b"a b", b"a b");
    check_regex_match("a\\sb", b"a\tb", b"a\tb");
    check_regex_match("a\\sb", b"a\rb", b"a\rb");
    check_regex_match("a\\sb", b"a\nb", b"a\nb");
    check_regex_match("a\\sb", b"a\x0Bb", b"a\x0Bb");
    check_regex_match("a\\sb", b"a\x0Cb", b"a\x0Cb");
    check_regex_match("a[\\s]*b", b"a \t\r\n\x0B\x0Cb", b"a \t\r\n\x0B\x0Cb");
    check_regex_match("a[^\\S]*b", b"a \t\r\n\x0B\x0Cb", b"a \t\r\n\x0B\x0Cb");
    check(&build_regex_rule("a\\Sb"), b"a b", false);
    check(&build_regex_rule("a\\Sb"), b"a\tb", false);
    check(&build_regex_rule("a\\Sb"), b"a\rb", false);
    check(&build_regex_rule("a\\Sb"), b"a\nb", false);
    check(&build_regex_rule("a\\Sb"), b"a\x0Bb", false);
    check(&build_regex_rule("a\\Sb"), b"a\x0Cb", false);
    check_regex_match("foo([^\\s]*)", b"foobar\n", b"foobar");
    check_regex_match("foo([^\\s]*)", b"foobar\r\n", b"foobar");
    check_regex_match("\\n\\r\\t\\x0C\\x07", b"\n\r\t\x0C\x07", b"\n\r\t\x0C\x07");
    check_regex_match(
        "[\\n][\\r][\\t][\\x0C][\\x07]",
        b"\n\r\t\x0C\x07",
        b"\n\r\t\x0C\x07",
    );
    check_regex_match("\\x01\\x02\\x03", b"\x01\x02\x03", b"\x01\x02\x03");
    check_regex_match("[\\x01-\\x03]+", b"\x01\x02\x03", b"\x01\x02\x03");
    check(&build_regex_rule("[\\x00-\\x02]+"), b"\x03\x04\x05", false);
    check_regex_match("[\\x5D]", b"]", b"]");

    // TODO: not sure how this is supposed to work.
    // check_regex_match("[\\0x5A-\\x5D]", b"\x5B", b"\x5B");

    check_regex_match("[\\x5D-\\x5F]", b"\x5E", b"\x5E");
    check_regex_match("[\\x5C-\\x5F]", b"\x5E", b"\x5E");
    check_regex_match("[\\x5D-\\x5F]", b"\x5E", b"\x5E");
    check_regex_match("a\\wc", b"abc", b"abc");
    check_regex_match("a\\wc", b"a_c", b"a_c");
    check_regex_match("a\\wc", b"a0c", b"a0c");
    check(&build_regex_rule("a\\wc"), b"a*c", false);
    check_regex_match("\\w+", b"--ab_cd0123--", b"ab_cd0123");
    check_regex_match("[\\w]+", b"--ab_cd0123--", b"ab_cd0123");
    check_regex_match("\\D+", b"1234abc5678", b"abc");
    check_regex_match("[\\d]+", b"0123456789", b"0123456789");
    check_regex_match("[\\D]+", b"1234abc5678", b"abc");
    check_regex_match("[\\da-fA-F]+", b"123abc", b"123abc");
    check(&build_regex_rule("^(ab|cd)e"), b"abcde", false);
    check_regex_match("(abc|)ef", b"abcdef", b"ef");
    check_regex_match("(abc|)ef", b"abcef", b"abcef");
    check_regex_match("\\babc", b"abc", b"abc");
    check_regex_match("abc\\b", b"abc", b"abc");
    check(&build_regex_rule("\\babc"), b"1abc", false);
    check(&build_regex_rule("abc\\b"), b"abc1", false);
    check_regex_match("abc\\s\\b", b"abc x", b"abc ");
    check(&build_regex_rule("abc\\s\\b"), b"abc  ", false);
    check_regex_match("\\babc\\b", b" abc ", b"abc");
    check_regex_match("\\b\\w\\w\\w\\b", b" abc ", b"abc");
    check_regex_match("\\w\\w\\w\\b", b"abcd", b"bcd");
    check_regex_match("\\b\\w\\w\\w", b"abcd", b"abc");
    check(&build_regex_rule("\\b\\w\\w\\w\\b"), b"abcd", false);
    check(&build_regex_rule("\\Babc"), b"abc", false);
    check(&build_regex_rule("abc\\B"), b"abc", false);
    check_regex_match("\\Babc", b"1abc", b"abc");
    check_regex_match("abc\\B", b"abc1", b"abc");
    check(&build_regex_rule("abc\\s\\B"), b"abc x", false);
    check_regex_match("abc\\s\\B", b"abc  ", b"abc ");
    check_regex_match("\\w\\w\\w\\B", b"abcd", b"abc");
    check_regex_match("\\B\\w\\w\\w", b"abcd", b"bcd");
    check(&build_regex_rule("\\B\\w\\w\\w\\B"), b"abcd", false);

    // XXX: not allowed by libyara, allowed for us, this is fine
    // check_err(&build_regex_rule("(|abc)ef"), "z");

    check_regex_match("((a)(b)c)(d)", b"abcd", b"abcd");
    check_regex_match("(a|b)c*d", b"abcd", b"bcd");
    check_regex_match("(ab|ab*)bc", b"abc", b"abc");
    check_regex_match("a([bc]*)c*", b"abc", b"abc");
    check_regex_match("a([bc]*)c*", b"ac", b"ac");
    check_regex_match("a([bc]*)c*", b"a", b"a");
    check_regex_match("a([bc]*)(c*d)", b"abcd", b"abcd");
    check_regex_match("a([bc]+)(c*d)", b"abcd", b"abcd");
    check_regex_match("a([bc]*)(c+d)", b"abcd", b"abcd");
    check_regex_match("a[bcd]*dcdcde", b"adcdcde", b"adcdcde");
    check(&build_regex_rule("a[bcd]+dcdcde"), b"adcdcde", false);
    check_regex_match("\\((.*), (.*)\\)", b"(a, b)", b"(a, b)");
    check_regex_match("abc|123$", b"abcx", b"abc");
    check(&build_regex_rule("abc|123$"), b"123x", false);
    check_regex_match("abc|^123", b"123", b"123");
    check(&build_regex_rule("abc|^123"), b"x123", false);
    check_regex_match("^abc$", b"abc", b"abc");
    check(&build_regex_rule("^abc$"), b"abcc", false);
    check_regex_match("^abc", b"abcc", b"abc");
    check(&build_regex_rule("^abc$"), b"aabc", false);
    check(&build_regex_rule("abc^"), b"abc", false);
    check(&build_regex_rule("ab^c"), b"abc", false);
    check(&build_regex_rule("a^bcdef"), b"abcdef", false);
    check_regex_match("abc$", b"aabc", b"abc");
    check(&build_regex_rule("$abc"), b"abc", false);
    check_regex_match("(a|a$)bcd", b"abcd", b"abcd");
    check(&build_regex_rule("(a$|a$)bcd"), b"abcd", false);
    check(&build_regex_rule("(abc$|ab$)"), b"abcd", false);
    check_regex_match("^a(bc+|b[eh])g|.h$", b"abhg", b"abhg");
    check_regex_match("(bc+d$|ef*g.|h?i(j|k))", b"effgz", b"effgz");
    check_regex_match("(bc+d$|ef*g.|h?i(j|k))", b"ij", b"ij");
    check(&build_regex_rule("(bc+d$|ef*g.|h?i(j|k))"), b"effg", false);
    check(&build_regex_rule("(bc+d$|ef*g.|h?i(j|k))"), b"bcdd", false);
    check_regex_match("(bc+d$|ef*g.|h?i(j|k))", b"reffgz", b"effgz");

    // Test case for issue #324
    check_regex_match("whatever|   x.   x", b"   xy   x", b"   xy   x");

    // Test case for issue #503, \x without two following hex-digits
    check_err(
        &build_regex_rule("\\x0"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );
    check_err(
        &build_regex_rule("\\x"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );

    // XXX: not allowed by libyara, ok for us, this is fine
    // check_err(&build_regex_rule("x{0,0}"), "z");
    // check_err(&build_regex_rule("x{0}"), "z");

    check_err(
        &build_regex_rule("\\xxy"),
        "mem:1:22: error: variable $a cannot be compiled: regex parse error",
    );

    // Test case for issue #682
    check_regex_match("(a|\\b)[a]{1,}", b"aaaa", b"aaaa");

    // Test cases for issue #1018
    check_regex_match(
        "(ba{4}){4,10}",
        b"baaaabaaaabaaaabaaaabaaaa",
        b"baaaabaaaabaaaabaaaabaaaa",
    );

    check_regex_match(
        "(ba{2}a{2}){5,10}",
        b"baaaabaaaabaaaabaaaabaaaa",
        b"baaaabaaaabaaaabaaaabaaaa",
    );

    check_regex_match(
        "(ba{3}){4,10}",
        b"baaabaaabaaabaaabaaa",
        b"baaabaaabaaabaaabaaa",
    );

    check_regex_match(
        "(ba{4}){5,10}",
        b"baaaabaaaabaaaabaaaabaaaa",
        b"baaaabaaaabaaaabaaaabaaaa",
    );

    check(
        &build_regex_rule("(ba{4}){4,10}"),
        b"baaaabaaaabaaaa",
        false,
    );

    // Test for integer overflow in repeat interval
    check_err(
        &build_regex_rule("a{2977952116}"),
        "mem:1:22: error: variable $a cannot be compiled: Compiled regex exceeds size limit",
    );

    check_err(
        "rule test { strings: $a = /a\\/ condition: $a }",
        "mem:1:47: error: syntax error",
    );

    check_err(
        "rule test { strings: $a = /[a\\/ condition: $a }",
        "mem:1:48: error: syntax error",
    );

    // Test case for issue #996
    check_err(
        "rule test {strings:$=/.{,}? /",
        "mem:1:30: error: syntax error",
    );

    check(
        "rule test {
        strings: $a = /MZ.{300,}t/
        condition: !a == 317 }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = /MZ.{300,}?t/
        condition: !a == 314 }",
        PE32_FILE,
        true,
    );

    check(
        "rule test { strings: $a = /abc[^d]/ nocase condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /abc[^d]/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /abc[^D]/ nocase condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        false,
    );

    check(
        "rule test { strings: $a = /abc[^D]/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /abc[^f]/ nocase condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /abc[^f]/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /abc[^F]/ nocase condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        true,
    );

    check(
        "rule test { strings: $a = /abc[^F]/ condition: $a }",
        concatcp!(TEXT_1024_BYTES, "abcd").as_bytes(),
        true,
    );

    // Test case for issue #1006
    check(
        "rule test { strings: $a = \" cmd.exe \" nocase wide condition: $a }",
        ISSUE_1006,
        false,
    );

    // Test case for issue #1117
    let mut data = TEXT_1024_BYTES.as_bytes().to_vec();
    data.extend(b"abc\xE0\x22");
    check(
        "rule test { strings: $a =/abc([^\"\\\\])*\"/ nocase condition: $a }",
        &data,
        true,
    );
}

#[test]
#[cfg(feature = "object")]
fn test_entrypoint() {
    use super::util::{ELF32_FILE, ELF64_FILE};

    check(
        "rule test {
        strings: $a = { 6a 2a 58 c3 }
        condition: $a at entrypoint }",
        PE32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { b8 01 00 00 00 bb 2a }
        condition: $a at entrypoint }",
        ELF32_FILE,
        true,
    );

    check(
        "rule test {
        strings: $a = { b8 01 00 00 00 bb 2a }
        condition: $a at entrypoint }",
        ELF64_FILE,
        true,
    );

    check("rule test { condition: entrypoint >= 0 }", b"", false);
}

#[test]
fn test_filesize() {
    check(
        &format!("rule test {{ condition: filesize == {} }}", PE32_FILE.len()),
        PE32_FILE,
        true,
    );
}

#[test]
fn test_comments() {
    check(
        "rule test {
         condition:
             //  this is a comment
             /*** this is a comment ***/
             /* /* /*
                 this is a comment
             */
             true
      }",
        b"",
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 [-] // Inline comment
\r 38 39 }
        condition: !a == 9 }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 }
        condition: !a == 9 }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 }
                 $b = { 31 32 /* Inline comment */ [-] 35 36 }
        condition: (!a == 9) and (!b == 6) }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 /* Inline comment with *asterisks* */ [-] 38 39 }
        condition: !a == 9}",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { 31 32 /* Inline multi-line
\r     comment */ [-] 38 39 }
        condition: !a == 9 }",
        concatcp!(TEXT_1024_BYTES, "1234567890").as_bytes(),
        true,
    );

    check(
        "rule test {
        strings: $a = { /*Some*/ 31 /*interleaved*/ [-] /*comments*/ 38 39 }
        condition: !a == 9 }",
        concatcp!("1234567890", TEXT_1024_BYTES).as_bytes(),
        true,
    );
}

#[test]
fn test_matches_operator() {
    check("rule test { condition: \"foo\" matches /foo/ }", b"", true);

    check("rule test { condition: \"foo\" matches /bar/ }", b"", false);

    check("rule test { condition: \"FoO\" matches /fOo/i }", b"", true);

    check(
        "rule test { condition: \"xxFoOxx\" matches /fOo/i }",
        b"",
        true,
    );

    check(
        "rule test { condition: \"xxFoOxx\" matches /^fOo/i }",
        b"",
        false,
    );

    check(
        "rule test { condition: \"xxFoOxx\" matches /fOo$/i }",
        b"",
        false,
    );

    check(
        "rule test { condition: \"foo\" matches /^foo$/i }",
        b"",
        true,
    );

    check(
        "rule test { condition: \"foo\\nbar\" matches /foo.*bar/s }",
        b"",
        true,
    );

    check(
        "rule test { condition: \"foo\\nbar\" matches /foo.*bar/ }",
        b"",
        false,
    );
}

#[test]
fn test_global_rules() {
    check(
        "global private rule global_rule {
        condition:
          true
      }
      rule test {
        condition: true
      }",
        b"",
        true,
    );

    check(
        "global private rule global_rule {
        condition:
          false
      }
      rule test {
        condition: true
      }",
        b"",
        false,
    );
}

#[test]
fn test_modules() {
    check(
        "import \"tests\"
       rule test {
        condition: tests.constants.one + 1 == tests.constants.two
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.constants.foo == \"foo\"
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.constants.empty == \"\" 
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.empty() == \"\" 
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.struct_array[1].i == 1 
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.struct_array[0].i == 1 or true
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.integer_array[0] == 0
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.integer_array[1] == 1
      }",
        b"",
        true,
    );

    // XXX: boreal does not allow non consecutive indexes in
    // arrays. This is not really a feature actually used in yara either,
    // so ignore this test.
    // check(
    //     "import \"tests\"
    //    rule test {
    //     condition: tests.integer_array[256] == 256
    //   }",
    //     b"",
    //     true,
    // );

    check(
        "import \"tests\"
       rule test {
        condition: tests.string_array[0] == \"foo\"
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.string_array[2] == \"baz\"
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.string_dict[\"foo\"] == \"foo\"
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.string_dict[\"bar\"] == \"bar\"
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.isum(1,2) == 3
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.isum(1,2,3) == 6
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.fsum(1.0,2.0) == 3.0
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.fsum(1.0,2.0,3.0) == 6.0
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.foobar(1) == tests.foobar(1)
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.foobar(1) != tests.foobar(2)
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
       rule test {
        condition: tests.length(\"dummy\") == 5
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.struct_array[0].i == 1 
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.isum(1,1) == 3
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.fsum(1.0,1.0) == 3.0
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.match(/foo/,\"foo\") == 3
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.match(/foo/,\"bar\") == -1
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.match(/foo.bar/i,\"FOO\\nBAR\") == -1
      }",
        b"",
        true,
    );

    check(
        "import \"tests\"
      rule test { condition: tests.match(/foo.bar/is,\"FOO\\nBAR\") == 7
      }",
        b"",
        true,
    );

    check(
        "import \"tests\" rule test {
        condition:
          for any k,v in tests.empty_struct_array[0].struct_dict: (
            v.unused == \"foo\"
          )
      }",
        b"",
        false,
    );

    check(
        "import \"tests\"
      rule test {
        condition:
          for any item in tests.empty_struct_array[0].struct_array: (
            item.unused == \"foo\"
          )
      }",
        b"",
        false,
    );

    check_err("import \"\\x00\"", "error: unknown import");

    check_err("import \"\"", "mem:1:1: error: syntax error");
}

#[test]
fn test_time_module() {
    check(
        "import \"time\"
        rule test { condition: time.now() > 0 }",
        b"",
        true,
    );
}

#[test]
#[cfg(feature = "hash")]
fn test_module_hash() {
    let blob = &[0x61, 0x62, 0x63, 0x64, 0x65]; // abcde without trailing zero

    check(
        "import \"hash\"
       rule test {
        condition:
          hash.md5(0, filesize) ==
            \"ab56b4d92b40713acc5af89985d4b786\"
            and
          hash.md5(1, filesize) ==
            \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\"
            and
          hash.sha1(0, filesize) ==
            \"03de6c570bfe24bfc328ccd7ca46b76eadaf4334\"
            and
          hash.sha1(1, filesize) ==
            \"a302d65ae4d9e768a1538d53605f203fd8e2d6e2\"
            and
          hash.sha256(0, filesize) ==
            \"36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c\"
            and
          hash.sha256(1, filesize) ==
            \"aaaaf2863e043b9df604158ad5c16ff1adaf3fd7e9fcea5dcb322b6762b3b59a\"
            and
          hash.crc32(0, filesize) == 0x8587d865
            and
          hash.checksum32(0, filesize) == 0x1ef
      }",
        blob,
        true,
    );

    check(
        "import \"hash\"
       rule test {
        condition:
          hash.md5(\"TEST STRING\") ==
            \"2d7d687432758a8eeeca7b7e5d518e7f\"
            and
          hash.sha1(\"TEST STRING\") ==
            \"d39d009c05797a93a79720952e99c7054a24e7c4\"
            and
          hash.sha256(\"TEST STRING\") ==
            \"fb6ca29024bd42f1894620ffa45fd976217e72d988b04ee02bb4793ab9d0c862\"
            and
          hash.crc32(\"TEST STRING\") == 0x51f9be31
            and
          hash.checksum32(\"TEST STRING\") == 0x337
      }",
        b"",
        true,
    );

    // Test hash caching mechanism

    check(
        "import \"hash\"
       rule test {
        condition:
          hash.md5(0, filesize) ==
            \"ab56b4d92b40713acc5af89985d4b786\"
            and
          hash.md5(1, filesize) ==
            \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\"
            and
          hash.md5(0, filesize) ==
            \"ab56b4d92b40713acc5af89985d4b786\"
            and
          hash.md5(1, filesize) ==
            \"e02cfbe5502b64aa5ae9f2d0d69eaa8d\"
      }",
        blob,
        true,
    );

    let multi_block_blob = concatcp!(TEXT_1024_BYTES, TEXT_1024_BYTES, "\0").as_bytes();

    check(
        "import \"hash\"
       rule test {
        condition:
          hash.md5(768, 8) ==
            \"9edc35bab4510f115d0974fc3597d444\" /*    exact 1st block boundary - overlap */
            and
          hash.md5(1024, 8) ==
            \"2b607f2bcdf01d2cc5484230c89f5e18\" /*    exact 1st block boundary */
            and
          hash.md5(764, 8) ==
            \"0cdfa992f3a982b27c364ab7d4ae9aa2\" /* straddle 1st block boundary - overlap */
            and
          hash.md5(764, 8) ==
            \"0cdfa992f3a982b27c364ab7d4ae9aa2\" /* straddle 1st block boundary - overlap; cache */
            and
          hash.md5(1020, 8) ==
            \"478adcaee8dec0bf8d9425d6894e8672\" /* straddle 1st block boundary */
            and
          hash.md5(1020, 8) ==
            \"478adcaee8dec0bf8d9425d6894e8672\" /* straddle 1st block boundary; cache */
            and
          hash.md5(0, filesize) ==
            \"578848bccbd8294394864707e7f581e3\"
            and
          hash.md5(1, filesize) ==
            \"633e48db55a5b477f9eeafad0ebbe108\"
            and
          hash.sha1(0, filesize) ==
            \"0170d3bfb54b5ba2fc12df571ffb000fcb2a379d\"
            and
          hash.sha1(1, filesize) ==
            \"89d614c846abe670f998ef02c4f5277ab76c0b4d\"
            and
          hash.sha256(0, filesize) ==
            \"ebc7a22f28028552576eeef3c17182a7d635ddaefbc94fc6d85f099289fdf8a5\"
            and
          hash.sha256(1, filesize) ==
            \"9c19006ade01c93f42949723f4ec8b1158e07fa43fd946f03e84a1ce25baa2c1\"
            and
          hash.crc32(0, filesize) == 0x2b11af72
            and
          hash.crc32(\"TEST STRING\") == 0x51f9be31
      }",
        multi_block_blob,
        true,
    );
}

#[test]
fn test_integer_functions() {
    let mut input = TEXT_1024_BYTES.as_bytes().to_vec();
    input.extend(b"\xaa\xbb\xcc\xdd");

    check("rule test { condition: uint8(1024) == 0xAA}", &input, true);

    check(
        "rule test { condition: uint16(1024) == 0xBBAA}",
        &input,
        true,
    );

    check(
        "rule test { condition: uint32(1024) == 0xDDCCBBAA}",
        &input,
        true,
    );

    check(
        "rule test { condition: uint8be(1024) == 0xAA}",
        &input,
        true,
    );

    check(
        "rule test { condition: uint16be(1024) == 0xAABB}",
        &input,
        true,
    );

    check(
        "rule test { condition: uint32be(1024) == 0xAABBCCDD}",
        &input,
        true,
    );
}

// FIXME: add test_include

#[test]
fn test_tags() {
    check("rule test : tag1 { condition: true}", b"", true);

    check("rule test : tag1 tag2 { condition: true}", b"", true);

    check_err(
        "rule test : tag1 tag1 { condition: true}",
        "error: tag `tag1` specified multiple times",
    );
}

// FIXME add test_process_scan

// FIXME add test_performance_warnings ?

#[test]
fn test_meta() {
    // Make sure that multiple metadata with the same identifier are allowed.
    // This was not intentionally designed like that, but users are alreay
    // relying on this.
    check(
        "rule test { \
         meta: \
           foo = \"foo\" \
           foo = 1 \
           foo = false \
         condition:\
           true \
      }",
        b"",
        true,
    );
}

#[test]
#[cfg(feature = "object")]
fn test_defined() {
    check("rule t { condition: defined 1 }", b"", true);

    check(
        "import \"pe\"
      rule t {
        condition:
          defined pe.number_of_resources
      }",
        b"",
        false,
    );

    check(
        "import \"pe\"
      rule t {
        condition:
          not defined pe.number_of_resources
      }",
        b"",
        true,
    );

    check(
        "import \"pe\"
      rule t {
        condition:
          defined not pe.number_of_resources
      }",
        b"",
        false,
    );

    check(
        "import \"pe\"
      rule t {
        condition:
          defined pe.number_of_resources and pe.number_of_resources == 0
      }",
        b"",
        false,
    );

    check(
        "import \"pe\"
      rule t {
        condition:
          defined (pe.number_of_resources and pe.number_of_resources == 0)
      }",
        b"",
        true,
    );

    check(
        "import \"pe\"
      rule t {
        condition:
          defined \"foo\" contains \"f\"
      }",
        b"",
        true,
    );
}
