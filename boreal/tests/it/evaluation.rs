use crate::utils::{build_rule, check, check_boreal, check_err, Checker};

fn build_empty_rule(condition: &str) -> String {
    format!(
        r#"
rule a {{
    condition:
        {condition}
}}"#
    )
}

#[test]
fn test_eval_cast_to_bool() {
    check("rule test { condition: 0.0 }", &[], false);
    check("rule test { condition: 1.3 }", &[], true);
    check("rule test { condition: \"\" }", &[], false);
    check("rule test { condition: \"a\" }", &[], true);
    check("rule test { condition: 0 }", &[], false);
    check("rule test { condition: 1 }", &[], true);
    check("rule test { condition: /a/ }", &[], true);
}

#[test]
fn test_eval_add() {
    check(&build_empty_rule("2 + 6 == 8"), &[], true);
    check(&build_empty_rule("3 + 4.2 == 7.2"), &[], true);
    check(&build_empty_rule("2.62 + 3 == 5.62"), &[], true);
    check(&build_empty_rule("1.3 + 1.5 == 2.8"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("#c0 + 0x7FFFFFFFFFFFFFFF + 1 > 0"), &[], false);
    check(
        &build_rule("#c0 + -2 + -0x7FFFFFFFFFFFFFFF < 0"),
        &[],
        false,
    );
}

#[test]
fn test_eval_sub() {
    check(&build_empty_rule("2 - 6 == -4"), &[], true);
    check(&build_empty_rule("3 - 4.5 == -1.5"), &[], true);
    check(&build_empty_rule("2.62 - 3 == -0.38"), &[], true);
    check(&build_empty_rule("1.3 - 1.5 == -0.2"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("#c0 + -0x7FFFFFFFFFFFFFFF - 2 < 0"), &[], false);
    check(&build_rule("#c0 + 0x7FFFFFFFFFFFFFFF - -1 > 0"), &[], false);
}

#[test]
fn test_eval_mul() {
    check(&build_empty_rule("2 * 6 == 12"), &[], true);
    check(&build_empty_rule("3 * 0.1 == 0.3"), &[], true);
    check(&build_empty_rule("2.62 * 3 == 7.86"), &[], true);
    check(&build_empty_rule("1.3 * 0.5 == 0.65"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(
        &build_rule("(#c0 + -0x0FFFFFFFFFFFFFFF) * 10 < 0"),
        &[],
        false,
    );
    check(
        &build_rule("(#c0 + 0x1FFFFFFFFFFFFFFF) * 5 > 0"),
        &[],
        false,
    );
}

#[test]
fn test_eval_div() {
    check(&build_empty_rule("7 \\ 4 == 1"), &[], true);
    check(&build_empty_rule("-7 \\ 4 == -1"), &[], true);
    check(&build_empty_rule("7 \\ 4.0 == 1.75"), &[], true);
    check(&build_empty_rule("7.0 \\ 4 == 1.75"), &[], true);
    check(&build_empty_rule("2.3 \\ 4.6 == 0.5"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("1 \\ (#c0 + 0) == 1"), &[], false);
    check(&build_rule("-2 \\ (-0 + #c0) > 0"), &[], false);

    check(
        &build_rule("(#c0 + -0x7FFFFFFFFFFFFFFF - 1) \\ -1 > 0"),
        &[],
        false,
    );
}

#[test]
fn test_eval_mod() {
    check(&build_empty_rule("7 % 4 == 3"), &[], true);
    check(&build_empty_rule("-7 % 4 == -3"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("1 % (#c0 + 0) == 1"), &[], false);
    check(&build_rule("-2 % (-0 + #c0) > 0"), &[], false);

    check(
        &build_rule("(#c0 + -0x7FFFFFFFFFFFFFFF - 1) % -1 > 0"),
        &[],
        false,
    );
}

#[test]
fn test_eval_shl() {
    check(&build_empty_rule("15 << 2 == 60"), &[], true);
    check(
        &build_empty_rule("0xDEADCAFE << 16 == 0xDEADCAFE0000"),
        &[],
        true,
    );
    check(&build_empty_rule("-8 << 1 == -16"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(
        &build_rule("#c0 + 0x7FFFFFFFFFFFFFFF << 4 == -16"),
        &[],
        true,
    );
    check(
        &build_rule("#c0 + 0x7FFFFFFFFFFFFFFF << 1000 == 0"),
        &[],
        true,
    );
    check(
        &build_rule("#c0 + -0x7FFFFFFFFFFFFFFF << 1000 == 0"),
        &[],
        true,
    );
    check(&build_rule("12 << (#c0 + -2) == 0"), &[], false);
}

#[test]
fn test_eval_shr() {
    check(&build_empty_rule("15 >> 2 == 3"), &[], true);
    check(&build_empty_rule("0xDEADCAFE >> 16 == 0xDEAD"), &[], true);
    check(&build_empty_rule("-8 >> 1 == -4"), &[], true);

    check(
        &build_rule("#c0 + 0x7FFFFFFFFFFFFFFF >> 62 == 0x1"),
        &[],
        true,
    );
    check(
        &build_rule("#c0 + 0x7FFFFFFFFFFFFFFF >> 1000 == 0"),
        &[],
        true,
    );
    check(
        &build_rule("#c0 + -0x7FFFFFFFFFFFFFFF >> 1000 == 0"),
        &[],
        true,
    );
    check(&build_rule("12 >> (#c0 + -2) == 0"), &[], false);
}

#[test]
fn test_eval_var_count_string() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abc"
    condition:
        #a == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abcabc", false);
    checker.check(b"abcabcaabcb", true);
    checker.check(b"abcabcaabcb abc", false);

    check(
        r#"
rule a {
    strings:
        $a = "abc"
    condition:
        #a == 0
}"#,
        b"",
        true,
    );

    // Matches can overlap
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "aa"
    condition:
        #a == 3
}"#,
    );
    checker.check(b"aa", false);
    checker.check(b"aaa", false);
    checker.check(b"aaaa", true);
}

#[test]
fn test_eval_var_length_string() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abc"
    condition:
        !a == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abc", true);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abc"
    condition:
        !a[2] == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abc", false);
    checker.check(b"abc abcc", true);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abc"
    condition:
        !a != 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abc", false);
    checker.check(b"abcabc", false);

    // invalid occurence number is undefined
    check_boreal(&build_rule("defined !a1[0]"), b"", false);
    check_boreal(&build_rule("defined !a1[0]"), b"a1", false);
    check_boreal(&build_rule("defined !a1[-1]"), b"", false);
    check_boreal(&build_rule("defined !a1[-1]"), b"a1", false);
}

#[test]
fn test_eval_var_offset_string() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "ab"
    condition:
        @a == 2
}"#,
    );
    checker.check(b"", false);
    checker.check(b"ab", false);
    checker.check(b" ab", false);
    checker.check(b"  ab", true);
    checker.check(b"   ab", false);
    checker.check(b"abab", false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abc"
        $y = "y"
        $z = "z"
    condition:
        @a[#y + 1] == #z
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abc", true);
    checker.check(b"abc z", false);
    checker.check(b"abc abc y zzz", false);
    checker.check(b"abc abc y zzzz", true);
    checker.check(b"abc abc yy zzzz", false);
    checker.check(b"abcabcabc yy zzzzzz", true);
    checker.check(b"abcabcabc yy zzzzzzz", false);

    // invalid occurence number is undefined
    check_boreal(&build_rule("defined @a1[0]"), b"", false);
    check_boreal(&build_rule("defined @a1[0]"), b"a1", false);
    check_boreal(&build_rule("defined @a1[-1]"), b"", false);
    check_boreal(&build_rule("defined @a1[-1]"), b"a1", false);
}

#[test]
fn test_eval_var_count_regex() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a.*b/
    condition:
        #a == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"aaab", true);
    checker.check(b"abab", false);
    checker.check(b"ab aaabb acb", false);
    checker.check(b"ab abb acb", true);
    checker.check(b"aaabbb", true);
    checker.check(b"aaaabbb", false);

    check(
        r#"
rule a {
    strings:
        $a = /a/
    condition:
        #a == 0
}"#,
        b"",
        true,
    );
}

#[test]
fn test_eval_var_length_regex() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a.*b/
    condition:
        !a == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"ab", false);
    checker.check(b"azb", true);
    // Regexes are greedy
    checker.check(b"aabb", false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "a.*b+"
    condition:
        $a
}"#,
    );

    checker.check(b"aaabb", false);
    checker.check(b"aa.*b+", true);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a.*b+/
        $y = "y"
        $z = "z"
    condition:
        !a[#y + 1] == #z
}"#,
    );
    checker.check(b"aaabb", false);
    checker.check(b"aaabbcb z zzz zzz", true);
    checker.check(b"aaabb y zzzz", true);
    checker.check(b"aaabb yy zzz", true);
}

#[test]
fn test_eval_var_offset_regex() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a+b/
    condition:
        @a == 2
}"#,
    );
    checker.check(b"", false);
    checker.check(b"ab", false);
    checker.check(b" ab", false);
    checker.check(b"  ab", true);
    checker.check(b"  aab", true);
    checker.check(b"   ab", false);
    checker.check(b"abab", false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a.*c/
        $y = "y"
        $z = "z"
    condition:
        @a[#y + 1] == #z
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abc", true);
    checker.check(b"abc z", false);
    checker.check(b"abc abc y zzz", false);
    checker.check(b"abc abc y zzzz", true);
    checker.check(b"abc abc yy zzzz", false);
    checker.check(b"abcabcabc yy zzzzzz", true);
    checker.check(b"abcabcabc yy zzzzzzz", false);
}

#[test]
fn test_eval_var_count_hex_string() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { AB [1-3] CD }
    condition:
        #a == 2
}"#,
    );
    checker.check(b"\xab\xcd \xab_\xcd", false);
    checker.check(b"\xabpad\xcd \xab_\xcd", true);
    checker.check(b"\xab\xab_\xcd", true);
    checker.check(b"\xab\xab\xab_\xcd", false);
    checker.check(b"\xabpa\xcd\xcd", false);

    check(
        r#"
rule a {
    strings:
        $a = { AB [1-3] CD }
    condition:
        #a == 0
}"#,
        b"",
        true,
    );
}

#[test]
fn test_eval_var_length_hex_string() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { AB [1-3] CD }
    condition:
        !a == 3
}"#,
    );
    checker.check(b"\xab_\xcd", true);
    // hex strings are NOT greedy
    checker.check(b"\xab_\xcd\xcd", true);
    checker.check(b"\xab_\xcd\xcd\xcd", true);
    checker.check(b"\xabpad\xcd", false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { 61 [1-] 62 }
        $y = "y"
        $z = "z"
    condition:
        !a[#y + 1] == #z
}"#,
    );
    checker.check(b"a_b", false);
    checker.check(b"a_b zzz", true);
    checker.check(b"a1234b zzz zzz", true);

    checker.check(b"a_b aa999b y zzz zzz", true);
    checker.check(b"a_b aa999b yy zz zzz", true);

    // The alternatives are resolved in order, first one to match succeeds.
    #[track_caller]
    fn test_lengths(input: &[u8], a_len: usize, b_len: usize) {
        check(
            &format!(
                r#"
        rule a {{
            strings:
                $a = {{ AB ( FF | ?F [1-3] CD ) }}
                $b = {{ AB ( ?F [1-3] CD | FF ) }}
            condition:
                !a == {a_len} and !b == {b_len}
        }}"#,
            ),
            input,
            true,
        );
    }

    test_lengths(b"\xab\xff", 2, 2);
    test_lengths(b"zz \xab\xff_\xcd", 2, 4);
    test_lengths(b"zz \xab\xffpad\xcd", 2, 6);
    test_lengths(b"zz \xab\x5fpa\xcd\xcd", 5, 5);
}

#[test]
fn test_eval_var_offset_hex_string() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { 61 [1-3] 62 }
        $y = "y"
        $z = "z"
    condition:
        @a[#y + 1] == #z
}"#,
    );
    checker.check(b"a_b zz", false);
    checker.check(b" a__b zz", false);
    checker.check(b"  a___b zz", true);
    checker.check(b" aa_b zz", false);
    checker.check(b" aa_b y zz", true);
    checker.check(b"a_b aa__b y zzzz", true);
    checker.check(b"a_b aa__b yy zzzzz", true);
}

#[test]
fn test_eval_defined() {
    check(&build_empty_rule("defined 0"), &[], true);
    check(&build_empty_rule("defined 0.0"), &[], true);
    check(&build_empty_rule("defined \"a\""), &[], true);
    check(&build_empty_rule("defined /a/"), &[], true);
    check(&build_empty_rule("defined true"), &[], true);
    check(&build_empty_rule("defined false"), &[], true);

    check(&build_rule("defined ((1 \\ #c0) or false)"), &[], true);
    check(&build_rule("defined ((1 \\ #c0) or true)"), &[], true);
    check(&build_rule("defined ((1 \\ #c0) and false)"), &[], true);
    check(&build_rule("defined ((1 \\ #c0) and true)"), &[], true);
    check(&build_rule("defined (false or (1 \\ #c0))"), &[], true);
    check(&build_rule("defined (true or (1 \\ #c0))"), &[], true);
    check(&build_rule("defined (false and (1 \\ #c0))"), &[], true);
    check(&build_rule("defined (true and (1 \\ #c0))"), &[], true);

    check(&build_rule("defined (1 \\ #c0)"), &[], false);

    check_boreal(
        &build_rule("defined (tests.lazy().fake_int == 3)"),
        &[],
        false,
    );
    check_boreal(
        &build_rule("defined (tests.lazy().fake_int < 3)"),
        &[],
        false,
    );
    check_boreal(
        &build_rule("defined (tests.lazy().fake_int <= 3)"),
        &[],
        false,
    );
    check_boreal(
        &build_rule("defined (3 > tests.lazy().fake_int)"),
        &[],
        false,
    );
    check_boreal(
        &build_rule("defined (3 >= tests.lazy().fake_int)"),
        &[],
        false,
    );
    check_boreal(&build_rule("defined (-tests.lazy().fake_int)"), &[], false);

    check(
        &build_rule("defined (tests.string_array[5] matches /a.+z/s)"),
        &[],
        false,
    );
}

#[test]
fn test_eval_not() {
    check(&build_empty_rule("not 0"), &[], true);
    check(&build_empty_rule("not 1"), &[], false);
    check(&build_empty_rule("not 0.0"), &[], true);
    check(&build_empty_rule("not 0.1"), &[], false);
    check(&build_empty_rule("not \"\""), &[], true);
    check(&build_empty_rule("not \"a\""), &[], false);
    check(&build_empty_rule("not /a/"), &[], false);
    check(&build_empty_rule("not false"), &[], true);

    check(
        &build_rule("defined not tests.integer_array[5]"),
        &[],
        false,
    );
}

#[test]
fn test_eval_eq() {
    check(&build_empty_rule("var_true == var_true"), &[], true);
    check(&build_empty_rule("var_true == var_false"), &[], false);

    check(&build_empty_rule("1 == 2"), &[], false);
    check(&build_empty_rule("-1 == -1"), &[], true);

    check(&build_empty_rule("0.5 == 0.5"), &[], true);
    check(&build_empty_rule("1.23 == -1.0"), &[], false);

    check(&build_empty_rule("1.5 == 1"), &[], false);
    check(&build_empty_rule("1.0 == 1"), &[], true);
    check(&build_empty_rule("1 == 1.0"), &[], true);

    check(&build_empty_rule("\"\" == \"\""), &[], true);
    check(&build_empty_rule("\"anc\" == \"anc\""), &[], true);
    check(&build_empty_rule("\"anc\" == \"anC\""), &[], false);

    check_err(
        &build_empty_rule("1 == \"a\""),
        "error: expressions have invalid types",
    );
    check_err(
        &build_empty_rule("/a/ == /a/"),
        "error: expressions have invalid types",
    );
}

#[test]
fn test_eval_neq() {
    check(&build_empty_rule("var_true != var_true"), &[], false);
    check(&build_empty_rule("var_true != var_false"), &[], true);

    check(&build_empty_rule("1 != 2"), &[], true);
    check(&build_empty_rule("-1 != -1"), &[], false);

    check(&build_empty_rule("0.5 != 0.5"), &[], false);
    check(&build_empty_rule("1.23 != -1.0"), &[], true);

    check(&build_empty_rule("1.5 != 1"), &[], true);
    check(&build_empty_rule("1.0 != 1"), &[], false);
    check(&build_empty_rule("1 != 1.0"), &[], false);

    check(&build_empty_rule("\"\" != \"\""), &[], false);
    check(&build_empty_rule("\"anc\" != \"anc\""), &[], false);
    check(&build_empty_rule("\"anc\" != \"anC\""), &[], true);

    check_err(
        &build_empty_rule("1 != \"a\""),
        "error: expressions have invalid types",
    );
    check_err(
        &build_empty_rule("/a/ != /a/"),
        "error: expressions have invalid types",
    );
}

#[test]
fn test_eval_matches() {
    check(&build_rule("\"az\" matches /a.+z/"), &[], false);
    check(&build_rule("\"a<>z\" matches /a.+z/"), &[], true);
    check(&build_rule("\"a<>Z\" matches /a.+z/"), &[], false);
    check(&build_rule("\"a<>Z\" matches /a.+z/i"), &[], true);
    check(&build_rule("\"a<>Z\" matches /a.+z/i"), &[], true);
    check(&build_rule("\"a<\\n>Z\" matches /a.+z/i"), &[], false);
    check(&build_rule("\"A<\\n>Z\" matches /a.+z/is"), &[], true);
    check(&build_rule("\"A<\\n>Z\" matches /a.+z/s"), &[], false);
    check(&build_rule("\"a<\\n>z\" matches /a.+z/s"), &[], true);

    check(&build_rule("\"a<\\xFF>z\" matches /a.+z/"), &[], true);
}

#[test]
fn test_eval_var_count_in_range() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "abc"
    condition:
        #a in (0..8) == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"abcabc", false);
    checker.check(b"abcabcabc", true);
    checker.check(b"abcabcabc", true);
    checker.check(b" abcabcabc", true);
    checker.check(b"  abcabcabc", true);
    checker.check(b"   abcabcabc", false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a.*b/
    condition:
        #a in (2..5) == 3
}"#,
    );
    checker.check(b"", false);
    checker.check(b"  abaabb", true);
    checker.check(b"  ababab", false);
    checker.check(b"  abab", false);
    checker.check(b"  aaaab", false);
    checker.check(b" aaabb", false);
    checker.check(b"  aaabb", true);
    checker.check(b"   aaabb", true);
    checker.check(b"    aaabb", false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { AB [1-3] CD }
    condition:
        #a in (3..6) == 2
}"#,
    );
    checker.check(b"<<<\xab\xcd \xab_\xcd", false);
    checker.check(b"<<\xab\xcd \xab_\xcd", false);
    checker.check(b"<<<\xabpad\xcd \xab_\xcd", false);
    checker.check(b"<<<\xab\xab_\xcd", true);
    checker.check(b"<<<\xab\xab\xab_\xcd", false);
    checker.check(b"<<<|\xab\xab\xab_\xcd", false);
    checker.check(b"<<<||\xab\xab\xab_\xcd", true);
    checker.check(b"<<<|||\xab\xab\xab_\xcd", false);

    // Invalid range returns undefined
    check_boreal(&build_rule("defined (#a0 in (5..#c0))"), b"", false);

    // undefined is propagated
    check(
        &build_rule("defined (#a0 in (0..tests.integer_array[5]))"),
        b"",
        false,
    );
    check(
        &build_rule("defined (#a0 in (tests.integer_array[5]..5))"),
        b"",
        false,
    );
}

#[test]
fn test_eval_read_integer_8() {
    check(&build_rule("uint8(0) == 0"), b"\0", true);
    check(&build_rule("uint8(2) == 99"), b"abcd", true);
    check(&build_rule("uint8(2) == 99"), b"\0\0\0\0", false);
    check(&build_rule("uint8(2) == 255"), b"\0\0\xFF\0", true);

    check(&build_rule("int8(0) == 0"), b"\0", true);
    check(&build_rule("int8(2) == 99"), b"abcd", true);
    check(&build_rule("int8(2) == 127"), b"\0\0\x7F\0", true);
    check(&build_rule("int8(0) == -128"), b"\xFF", false);
    check(&build_rule("int8(0) == -1"), b"\xFF\0", true);
    check(&build_rule("int8(0) == -128"), b"\x80\0", true);

    check(&build_rule("defined uint8(-1)"), b"", false);
    check(&build_rule("defined uint8(1)"), b"", false);
    check(
        &build_rule("defined uint8(tests.integer_array[5])"),
        b"",
        false,
    );
    check(&build_rule("defined int8(-1)"), b"", false);
    check(&build_rule("defined int8(1)"), b"", false);
    check(
        &build_rule("defined int8(tests.integer_array[5])"),
        b"",
        false,
    );
}

#[test]
fn test_eval_read_integer_16() {
    check(&build_rule("uint16(0) == 0"), b"\0\0", true);
    check(&build_rule("uint16(2) == 25699"), b"abcd", true);
    check(&build_rule("uint16(0) == 255"), b"\0\xFF\0", false);
    check(&build_rule("uint16(0) == 65280"), b"\0\xFF\0", true);
    check(&build_rule("uint16(0) == 65535"), b"\xFF\xFF\0", true);

    check(&build_rule("uint16be(0) == 0"), b"\0\0", true);
    check(&build_rule("uint16be(2) == 25444"), b"abcd", true);
    check(&build_rule("uint16be(0) == 255"), b"\0\xFF\0", true);
    check(&build_rule("uint16be(0) == 65280"), b"\0\xFF\0", false);
    check(&build_rule("uint16be(0) == 65535"), b"\xFF\xFF\0", true);

    check(&build_rule("int16(0) == 0"), b"\0\0", true);
    check(&build_rule("int16(2) == 25699"), b"abcd", true);
    check(&build_rule("int16(0) == 255"), b"\0\xFF\0", false);
    check(&build_rule("int16(0) == -256"), b"\0\xFF\0", true);
    check(&build_rule("int16(0) == 32767"), b"\x7F\xFF\0", false);
    check(&build_rule("int16(0) == 32767"), b"\xFF\x7F\0", true);
    check(&build_rule("int16(0) == -1"), b"\xFF\xFF\0", true);
    check(&build_rule("int16(0) == -32768"), b"\x00\x80\0", true);

    check(&build_rule("int16be(0) == 0"), b"\0\0", true);
    check(&build_rule("int16be(2) == 25444"), b"abcd", true);
    check(&build_rule("int16be(0) == 255"), b"\0\xFF\0", true);
    check(&build_rule("int16be(0) == -256"), b"\0\xFF\0", false);
    check(&build_rule("int16be(0) == -256"), b"\xFF\0\0", true);
    check(&build_rule("int16be(0) == 32767"), b"\x7F\xFF\0", true);
    check(&build_rule("int16be(0) == 32767"), b"\xFF\x7F\0", false);
    check(&build_rule("int16be(0) == -1"), b"\xFF\xFF\0", true);
    check(&build_rule("int16be(0) == -32768"), b"\x80\0\0", true);

    // undefined with out of bounds index
    check(&build_rule("defined uint16(-1)"), b"", false);
    check(&build_rule("defined int16(-1)"), b"", false);
    check(&build_rule("defined uint16be(-1)"), b"", false);
    check(&build_rule("defined int16be(-1)"), b"", false);
    check(&build_rule("defined uint16(5)"), b"", false);
    check(&build_rule("defined int16(5)"), b"", false);
    check(&build_rule("defined uint16be(5)"), b"", false);
    check(&build_rule("defined int16be(5)"), b"", false);

    // undefined with in bounds, but missing some bytes
    check(&build_rule("defined uint16(2)"), b"abc", false);
    check(&build_rule("defined int16(2)"), b"abc", false);
    check(&build_rule("defined uint16be(2)"), b"abc", false);
    check(&build_rule("defined int16be(2)"), b"abc", false);

    // undefined with undefined index
    check(
        &build_rule("defined uint16(tests.integer_array[5])"),
        b"",
        false,
    );
    check(
        &build_rule("defined int16(tests.integer_array[5])"),
        b"",
        false,
    );
    check(
        &build_rule("defined uint16be(tests.integer_array[5])"),
        b"",
        false,
    );
    check(
        &build_rule("defined int16be(tests.integer_array[5])"),
        b"",
        false,
    );
}

#[test]
fn test_eval_read_integer_32() {
    check(&build_rule("uint32(0) == 0"), b"\0\0\0\0", true);
    check(&build_rule("uint32(2) == 1717920867"), b"abcdefg", true);
    check(&build_rule("uint32(0) == 255"), b"\0\0\0\xFF", false);
    check(&build_rule("uint32(0) == 4278190080"), b"\0\0\0\xFF", true);
    check(
        &build_rule("uint32(0) == 4294967295"),
        b"\xFF\xFF\xFF\xFF",
        true,
    );

    check(&build_rule("uint32be(0) == 0"), b"\0\0\0\0", true);
    check(&build_rule("uint32be(2) == 1667523942"), b"abcdefg", true);
    check(&build_rule("uint32be(0) == 255"), b"\0\0\0\xFF", true);
    check(
        &build_rule("uint32be(0) == 4278190080"),
        b"\0\0\0\xFF",
        false,
    );
    check(
        &build_rule("uint32be(0) == 4294967295"),
        b"\xFF\xFF\xFF\xFF",
        true,
    );

    check(&build_rule("int32(0) == 0"), b"\0\0\0\0", true);
    check(&build_rule("int32(2) == 1717920867"), b"abcdefg", true);
    check(&build_rule("int32(0) == 255"), b"\0\0\0\xFF", false);
    check(&build_rule("int32(0) == -16777216"), b"\0\0\0\xFF", true);
    check(&build_rule("int32(0) == 255"), b"\xFF\0\0\0", true);
    check(
        &build_rule("int32(0) == 2147483647"),
        b"\xFF\xFF\x7F\xFF\0",
        false,
    );
    check(
        &build_rule("int32(0) == 2147483647"),
        b"\xFF\xFF\xFF\x7F\0",
        true,
    );
    check(&build_rule("int32(0) == -1"), b"\xFF\xFF\0\0", false);
    check(&build_rule("int32(0) == -1"), b"\xFF\xFF\xFF\xFF\0", true);
    check(&build_rule("int32(0) == -2147483648"), b"\0\0\0\x80", true);

    check(&build_rule("int32be(0) == 0"), b"\0\0\0\0", true);
    check(&build_rule("int32be(2) == 1667523942"), b"abcdefg", true);
    check(&build_rule("int32be(0) == 255"), b"\0\0\0\xFF", true);
    check(&build_rule("int32be(0) == -16777216"), b"\0\0\0\xFF", false);
    check(&build_rule("int32be(0) == -16777216"), b"\xFF\0\0\0", true);
    check(
        &build_rule("int32be(0) == 2147483647"),
        b"\xFF\xFF\x7F\xFF\0",
        false,
    );
    check(
        &build_rule("int32be(0) == 2147483647"),
        b"\x7F\xFF\xFF\xFF\0",
        true,
    );
    check(&build_rule("int32be(0) == -1"), b"\xFF\xFF\0\0", false);
    check(&build_rule("int32be(0) == -1"), b"\xFF\xFF\xFF\xFF\0", true);
    check(
        &build_rule("int32be(0) == -2147483648"),
        b"\x80\0\0\0",
        true,
    );

    // undefined with out of bounds index
    check(&build_rule("defined uint32(-1)"), b"", false);
    check(&build_rule("defined int32(-1)"), b"", false);
    check(&build_rule("defined uint32be(-1)"), b"", false);
    check(&build_rule("defined int32be(-1)"), b"", false);
    check(&build_rule("defined uint32(5)"), b"", false);
    check(&build_rule("defined int32(5)"), b"", false);
    check(&build_rule("defined uint32be(5)"), b"", false);
    check(&build_rule("defined int32be(5)"), b"", false);

    // undefined with in bounds, but missing some bytes
    check(&build_rule("defined uint32(4)"), b"abcdefg", false);
    check(&build_rule("defined int32(4)"), b"abcdefg", false);
    check(&build_rule("defined uint32be(4)"), b"abcdefg", false);
    check(&build_rule("defined int32be(4)"), b"abcdefg", false);

    // undefined with undefined index
    check(
        &build_rule("defined uint32(tests.integer_array[5])"),
        b"",
        false,
    );
    check(
        &build_rule("defined int32(tests.integer_array[5])"),
        b"",
        false,
    );
    check(
        &build_rule("defined uint32be(tests.integer_array[5])"),
        b"",
        false,
    );
    check(
        &build_rule("defined int32be(tests.integer_array[5])"),
        b"",
        false,
    );
}

#[test]
fn test_eval_filesize() {
    check(&build_empty_rule("filesize == 0"), b"", true);
    check(&build_empty_rule("filesize == 0"), b"a", false);
    check(
        &build_empty_rule("filesize == 4096"),
        format!("{:<4096}", " ").as_bytes(),
        true,
    );
}

// Test the specific behavior of the entrypoing expression compared to the modules entrypoint
// values (which is tested in the tests for each module).
#[test]
#[cfg(feature = "object")]
fn test_eval_entrypoint() {
    use crate::libyara_compat::util::{ELF32_FILE, ELF64_FILE};
    use crate::utils::check_file;

    fn build_rule(module_name: &str, v1: u32, v2: u32) -> String {
        format!(
            r#"
            import "{module_name}"
            rule a {{
                condition:
                    {module_name}.entry_point == {v1} and entrypoint == {v2}
            }}
        "#
        )
    }

    // Not a PE or ELF
    check(&build_empty_rule("not defined entrypoint"), b"", true);
    check_file(
        &build_empty_rule("not defined entrypoint"),
        "tests/assets/libyara/data/tiny-macho",
        true,
    );

    // pe 32
    check_file(
        &build_rule("pe", 2976, 2976),
        "tests/assets/libyara/data/pe_imports",
        true,
    );
    // pe 64
    check_file(
        &build_rule("pe", 2800, 2800),
        "tests/assets/libyara/data/pe_mingw",
        true,
    );
    // elf 32
    check(&build_rule("elf", 96, 96), ELF32_FILE, true);
    // elf 64
    check(&build_rule("elf", 128, 128), ELF64_FILE, true);

    // For this file, the section raw data containing the entry point has been modified to test
    // the "realign" from the section alignment. The values are different between the module value
    // and the deprecated entrypoint one, as this one did not get the bugfixes.
    check_file(
        r#"
import "pe"
rule b {
    condition:
        pe.entry_point == 3086 and entrypoint == 3597
}"#,
        "tests/assets/pe/ord_and_delay.exe",
        true,
    );
}

#[test]
fn test_private_rule() {
    let checker = Checker::new(
        r#"
private rule a { strings: $a0 = "a0" condition: $a0 }
rule b { condition: a }
rule c { strings: $a1 = "a1" condition: $a1 }
private rule d { condition: c }
private rule e { condition: true }
private rule f { condition: false }
"#,
    );

    // e matches, but is private
    checker.check_rule_matches(b"", &[]);
    // a and b matches, a is private
    checker.check_rule_matches(b"a0", &["default:b"]);
    // c and d matches, d is private
    checker.check_rule_matches(b"a1", &["default:c"]);
    // a, b, c, d matches
    checker.check_rule_matches(b"a1a0", &["default:b", "default:c"]);
}

#[test]
fn test_private_strings() {
    let checker = Checker::new(
        r#"
// rule with only private strings
rule a {
    strings:
        $a0 = "a0" private
        $a1 = /a1/ private
        $a2 = { 61 32 } private // this is "a2"
    // This is used to force computation of all matches
    condition: for all of them: (# > 0) or any of them
}
// Mixed private & public
rule b {
    strings:
        $b0 = "b0"
        $b1 = "b1" private
        $b2 = "b2"
    condition: for all of them: (# > 0) or any of them
}
// Only public
rule c {
    strings:
        $c0 = "c0"
        $c1 = "c1"
    condition: for all of them: (# > 0) or any of them
}
"#,
    );

    // Nothing matches
    checker.check_full_matches(b"", vec![]);
    // Match on a0, b0 and c0: private strings are not reported,
    // independently on number of matches
    checker.check_full_matches(
        b"c0a0b0c0   c0",
        vec![
            ("default:a".to_owned(), vec![]),
            ("default:b".to_owned(), vec![("b0", vec![(b"b0", 4, 2)])]),
            (
                "default:c".to_owned(),
                vec![("c0", vec![(b"c0", 0, 2), (b"c0", 6, 2), (b"c0", 11, 2)])],
            ),
        ],
    );
    // Match on b1 only
    checker.check_full_matches(b"b1", vec![("default:b".to_owned(), vec![])]);
    // Match on a0 a1 and a2
    checker.check_full_matches(b"a0a2a1", vec![("default:a".to_owned(), vec![])]);

    // match on all of them
    checker.check_full_matches(
        b"a0a1a2c2c1c0b2b0b1",
        vec![
            ("default:a".to_owned(), vec![]),
            (
                "default:b".to_owned(),
                vec![("b0", vec![(b"b0", 14, 2)]), ("b2", vec![(b"b2", 12, 2)])],
            ),
            (
                "default:c".to_owned(),
                vec![("c0", vec![(b"c0", 10, 2)]), ("c1", vec![(b"c1", 8, 2)])],
            ),
        ],
    );
}

#[test]
fn test_global_rules() {
    let checker = Checker::new(
        r#"
global rule g1 {
    strings:
        $ = "g1"
    condition: all of them
}

private global rule g2 {
    strings:
        $ = "g2"
    condition: all of them
}

rule foo {
    strings:
        $ = "foo"
    condition: all of them
}

rule bar {
    condition: g1 or g2
}
"#,
    );

    // Nothing matches
    checker.check_rule_matches(b"", &[]);

    // Matching foo does not work without matching globals
    checker.check_rule_matches(b"foo", &[]);

    // Matching only one of the global rules does not work
    checker.check_rule_matches(b"g1 foo", &[]);
    checker.check_rule_matches(b"g2 foo", &[]);

    // Matching both globals work
    checker.check_rule_matches(b"g1 foo g2", &["default:g1", "default:foo", "default:bar"]);
    checker.check_rule_matches(b"g1 g2", &["default:g1", "default:bar"]);
}

#[test]
fn test_global_rules_in_rulesets() {
    let checker = Checker::new(
        r#"
global private rule g1 {
    strings:
        $ = "g1"
    condition: all of them
}

private global rule g2 {
    strings:
        $ = "g2"
    condition: all of them
}

rule g3 {
    strings:
        $ = "g3"
    condition: all of them
}

rule g4 {
    strings:
        $ = "g4"
    condition: all of them
}

rule a {
    condition: any of (g1, g2, g3)
}

rule b {
    condition: all of (g1, g2, g3, g4)
}

rule c {
    condition: 60% of (g*)
}

rule d {
    condition: 20% of (g*)
}

rule e {
    condition: 3 of (g*)
}


rule f {
    condition: none of (g*)
}
"#,
    );

    checker.check_rule_matches(b"", &[]);
    // Should make rule a and d match
    checker.check_rule_matches(b"g1 g2", &["default:a", "default:d"]);

    // Should make rule c and e match
    checker.check_rule_matches(
        b"g1 g2 g3",
        &[
            "default:g3",
            "default:a",
            "default:c",
            "default:d",
            "default:e",
        ],
    );
    checker.check_rule_matches(
        b"g1 g2 g4",
        &[
            "default:g4",
            "default:a",
            "default:c",
            "default:d",
            "default:e",
        ],
    );
    checker.check_rule_matches(b"g1 g3 g4", &[]);
    checker.check_rule_matches(b"g2 g3 g4", &[]);

    // Should match rule b as well
    checker.check_rule_matches(
        b"g1 g2 g3 g4",
        &[
            "default:g3",
            "default:g4",
            "default:a",
            "default:b",
            "default:c",
            "default:d",
            "default:e",
        ],
    );
}

// Check that if we can find matching rules without scanning, "compute_full_matches" is still
// properly handled.
#[test]
fn test_compute_full_matches_without_ac_scan() {
    let checker = Checker::new(
        r#"
global rule a {
    strings:
        $a = "a"
    condition:
        true or $a
}

rule b {
    strings:
        $b = "b"
    condition:
        false and $b
}

rule c {
    strings:
        $c = "c"
    condition:
        true or $c
}"#,
    );

    checker.check_rule_matches(b"", &["default:a", "default:c"]);
    checker.check_full_matches(
        b"",
        vec![
            ("default:a".to_owned(), vec![]),
            ("default:c".to_owned(), vec![]),
        ],
    );
    checker.check_full_matches(
        b"abaccad",
        vec![
            (
                "default:a".to_owned(),
                vec![("a", vec![(b"a", 0, 1), (b"a", 2, 1), (b"a", 5, 1)])],
            ),
            (
                "default:c".to_owned(),
                vec![("c", vec![(b"c", 3, 1), (b"c", 4, 1)])],
            ),
        ],
    );
}

// TODO: test count, offset, length with selected for variable
