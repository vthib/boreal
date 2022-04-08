use crate::utils::{check, check_boreal, check_err, Checker};

fn build_empty_rule(condition: &str) -> String {
    format!(
        r#"
rule a {{
    condition:
        {}
}}"#,
        condition
    )
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
        and for all of ($*) : (# >= 0) // this part is just to remove "unused strings" errors
}}"#,
        condition
    )
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

#[test]
fn test_variable_regex_modifiers() {
    // \x76 is 'v'
    //
    // FIXME: {,2} is OK for yara, not for us...
    let rule = r#"
rule a {
    strings:
        $a = /f[aF]T[d-g]\x76/ nocase
        $b = /foo/ fullword
        $c = /bar.{0,3}/ fullword nocase
        $d = /.{0,2}quu/ nocase fullword
    condition:
        any of them
}"#;

    // Nocase: work on literals, ranges, and explicit hexa char
    check(rule, b"faTgv", true);
    check(rule, b"faTgx", false);
    check(rule, b"FATGV", true);
    check(rule, b"fftDV", true);
    check(rule, b"fftEV", true);
    check(rule, b"fftE", false);
    check(rule, b"ftEV", false);

    // Fullword
    check(rule, b"foo", true);
    check(rule, b" foo ", true);
    check(rule, b"-foo_", true);
    check(rule, b"-fooa", false);
    check(rule, b"-fooA", false);
    check(rule, b"-foo0", false);
    check(rule, b"afoo:", false);
    check(rule, b"Zfoo:", false);
    check(rule, b"0foo:", false);

    check(rule, b"bar-", true);
    check(rule, b"bara-", true);
    check(rule, b"baraa-", true);
    check(rule, b"baraaa-", true);
    check(rule, b"baraaaa-", false);
    check(rule, b"abaraaa-", false);
    check(rule, b"|baraaa-", true);
    check(rule, b"|bar", true);

    check(rule, b"quu", true);
    check(rule, b"QUU", true);
    check(rule, b"quux", false);
    check(rule, b"aQuu", true);
    check(rule, b"aqUU", true);
    check(rule, b"aaqUu", true);
    check(rule, b"aAaQUu", false);

    let rule = r#"
rule a {
    strings:
        $a = /.{0,2}yay.{0,2}/ fullword
    condition:
        $a
}"#;

    check(rule, b"yay", true);
    // This is an example of something that would match with a smart regex, but does not with the
    // yara implem: find a match, check fullword, find next match, etc.
    check(rule, b"| yay |a", false);
    // But this works. Why? because we advance by one byte after every match.
    // First match: `| yay |` => not fullword
    // second match: ` yay |` => fullword, match
    check(rule, b"a| yay |", true);

    let rule = r#"
rule a {
    strings:
        $a = /.{0,2}yay.{0,2}/
    condition:
        #a == 3
}"#;
    // Confirmation, we have three matches here, for the 3 possibles captures on the left. However,
    // the right capture is always greedy.
    check(rule, b"a| yay |a", true);
}

#[test]
fn test_variable_string_modifiers() {
    // \x76 is 'v'
    let rule = r#"
rule a {
    strings:
        $a = "c\to\x76" nocase
        $b = "foo" fullword
        $c = "bar" fullword nocase
    condition:
        any of them
}"#;

    // Nocase
    check(rule, b"c\tov", true);
    check(rule, b"C\tOV", true);
    check(rule, b"C\tOx", false);
    check(rule, b"C\tov", true);

    // Fullword
    check(rule, b"foo", true);
    check(rule, b" foo ", true);
    check(rule, b"-foo_", true);
    check(rule, b"-fooa", false);
    check(rule, b"-fooA", false);
    check(rule, b"-foo0", false);
    check(rule, b"afoo:", false);
    check(rule, b"Zfoo:", false);
    check(rule, b"0foo:", false);

    check(rule, b"bar", true);
    check(rule, b" BAR ", true);
    check(rule, b"-baR_", true);
    check(rule, b"-baRa", false);
    check(rule, b"-barA", false);
    check(rule, b"-bAr0", false);
    check(rule, b"aBAr:", false);
    check(rule, b"Zbar:", false);
    check(rule, b"0bAR:", false);

    let rule = r#"
rule a {
    strings:
        $a = "margit" wide
        $b = "morgott" ascii wide
        $c = "mohg" ascii
    condition:
        any of them
}"#;

    // Wide
    check(rule, b"amargita", false);
    check(rule, b"a\0m\0a\0r\0g\0i\0t\0a\0", true);
    check(rule, b"\0m\0a\0r\0g\0i\0t\0a\0", true);
    check(rule, b"m\0a\0r\0g\0i\0t\0a\0", true);
    check(rule, b"m\0a\0r\0g\0i\0ta\0", false);

    // Wide + ascii
    check(rule, b"morgott", true);
    check(rule, b"amorgotta", true);
    check(rule, b"a\0m\0o\0r\0g\0o\0t\0t\0a\0", true);
    check(rule, b"\0m\0o\0r\0g\0o\0t\0t\0a\0", true);
    check(rule, b"m\0o\0r\0g\0o\0t\0t\0a\0", true);
    check(rule, b"m\0o\0r\0g\0o\0t\0ta\0", false);

    // Ascii
    check(rule, b"amohgus", true);
    check(rule, b"a\0m\0o\0g\0h\0u\0s\0", false);

    let rule = r#"
rule a {
    strings:
        $a = "rykard" xor
        $b = "rennala" xor(20-30)
        $c = "radagon" wide xor(10)
        $d = "radahn" wide ascii xor
    condition:
        any of them
}"#;
    let checker = Checker::new(rule);

    let check_xor = |mem: &[u8], xor_byte: u8, expected_res: bool| {
        let mut out = Vec::new();
        out.extend(b"abc");
        out.extend(mem.iter().map(|c| c ^ xor_byte));
        out.extend(b"xyz");

        checker.check(&out, expected_res);
        checker.check(&out[1..], expected_res);
    };

    // Xor
    let rykard = b"rykard";
    let rybard = b"rybard";
    for x in 0..=255 {
        check_xor(rykard, x, true);
        check_xor(rybard, x, false);
    }

    // Xor range specified
    let rennala = b"rennala";
    let wide_rennala = b"r\0e\0n\0n\0a\0l\0a\0";
    for x in 0..=255 {
        check_xor(rennala, x, x >= 20 && x <= 30);
        check_xor(wide_rennala, x, false);
    }

    // Xor single value + wide
    let radagon = b"radagon";
    let wide_radagon = b"r\0a\0d\0a\0g\0o\0n\0";
    for x in 0..=255 {
        check_xor(radagon, x, false);
        check_xor(wide_radagon, x, x == 10);
    }

    // Xor + wide + ascii
    let radahn = b"radahn";
    let wide_radahn = b"r\0a\0d\0a\0h\0n\0";
    for x in 0..=255 {
        check_xor(radahn, x, true);
        check_xor(wide_radahn, x, true);
    }
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
// TODO: test with libyara when yara-rust is update to 4.2.0
fn test_for_expression_none() {
    check_boreal(&build_rule("none of them"), b"", true);
    check_boreal(&build_rule("none of them"), b"a0", false);
    check_boreal(&build_rule("none of them"), b"a1", false);
    check_boreal(&build_rule("none of them"), b"a2", false);
    check_boreal(&build_rule("none of them"), b"b0", false);
    check_boreal(&build_rule("none of them"), b"b1", false);
    check_boreal(&build_rule("none of them"), b"c", false);
    check_boreal(&build_rule("none of them"), b"a0b1c", false);
    check_boreal(&build_rule("none of them"), b"a0a1a2b0b1", false);
    check_boreal(&build_rule("none of them"), b"a0a1a2b0b1c", false);

    check_boreal(&build_rule("none of ($b*)"), b"", true);
    check_boreal(&build_rule("none of ($b*)"), b"a0", true);
    check_boreal(&build_rule("none of ($b*)"), b"a1", true);
    check_boreal(&build_rule("none of ($b*)"), b"a2", true);
    check_boreal(&build_rule("none of ($b*)"), b"b0", false);
    check_boreal(&build_rule("none of ($b*)"), b"b1", false);
    check_boreal(&build_rule("none of ($b*)"), b"c", true);
    check_boreal(&build_rule("none of ($b*)"), b"a0b1c", false);
    check_boreal(&build_rule("none of ($b*)"), b"a0a1a2b0b1", false);
    check_boreal(&build_rule("none of ($b*)"), b"a0a1a2b0b1c", false);
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
// TODO: test with libyara when yara-rust is update to 4.2.0
fn test_for_expression_percent() {
    check_boreal(&build_rule("-1% of them"), b"", true);
    check_boreal(&build_rule("-1% of them"), b"a0", true);
    check_boreal(&build_rule("-1% of them"), b"a1", true);
    check_boreal(&build_rule("-1% of them"), b"a2", true);
    check_boreal(&build_rule("-1% of them"), b"b0", true);
    check_boreal(&build_rule("-1% of them"), b"b1", true);
    check_boreal(&build_rule("-1% of them"), b"c", true);
    check_boreal(&build_rule("-1% of them"), b"a0b1", true);
    check_boreal(&build_rule("-1% of them"), b"a0b1c", true);
    check_boreal(&build_rule("-1% of them"), b"a0a1a2b0b1", true);
    check_boreal(&build_rule("-1% of them"), b"a0a1a2b0b1c", true);

    check_boreal(&build_rule("0% of them"), b"", true);
    check_boreal(&build_rule("0% of them"), b"a0", true);
    check_boreal(&build_rule("0% of them"), b"a1", true);
    check_boreal(&build_rule("0% of them"), b"a2", true);
    check_boreal(&build_rule("0% of them"), b"b0", true);
    check_boreal(&build_rule("0% of them"), b"b1", true);
    check_boreal(&build_rule("0% of them"), b"c", true);
    check_boreal(&build_rule("0% of them"), b"a0b1", true);
    check_boreal(&build_rule("0% of them"), b"a0b1c", true);
    check_boreal(&build_rule("0% of them"), b"a0a1a2b0b1", true);
    check_boreal(&build_rule("0% of them"), b"a0a1a2b0b1c", true);

    check_boreal(&build_rule("50% of them"), b"", false);
    check_boreal(&build_rule("50% of them"), b"a0", false);
    check_boreal(&build_rule("50% of them"), b"a1", false);
    check_boreal(&build_rule("50% of them"), b"a2", false);
    check_boreal(&build_rule("50% of them"), b"b0", false);
    check_boreal(&build_rule("50% of them"), b"b1", false);
    check_boreal(&build_rule("50% of them"), b"c", false);
    check_boreal(&build_rule("50% of them"), b"a0b1", false);
    check_boreal(&build_rule("50% of them"), b"a0b1c", true);
    check_boreal(&build_rule("50% of them"), b"a0a1a2b0b1", true);
    check_boreal(&build_rule("50% of them"), b"a0a1a2b0b1c", true);

    // Gets rounded up to 4 of them
    check_boreal(&build_rule("51% of them"), b"", false);
    check_boreal(&build_rule("51% of them"), b"a0", false);
    check_boreal(&build_rule("51% of them"), b"a1", false);
    check_boreal(&build_rule("51% of them"), b"a2", false);
    check_boreal(&build_rule("51% of them"), b"b0", false);
    check_boreal(&build_rule("51% of them"), b"b1", false);
    check_boreal(&build_rule("51% of them"), b"c", false);
    check_boreal(&build_rule("51% of them"), b"a0b1", false);
    check_boreal(&build_rule("51% of them"), b"a0b1c", false);
    check_boreal(&build_rule("51% of them"), b"a0b0b1c", true);
    check_boreal(&build_rule("51% of them"), b"a0a1a2b0b1", true);
    check_boreal(&build_rule("51% of them"), b"a0a1a2b0b1c", true);

    check_boreal(&build_rule("100% of them"), b"", false);
    check_boreal(&build_rule("100% of them"), b"a0", false);
    check_boreal(&build_rule("100% of them"), b"a1", false);
    check_boreal(&build_rule("100% of them"), b"a2", false);
    check_boreal(&build_rule("100% of them"), b"b0", false);
    check_boreal(&build_rule("100% of them"), b"b1", false);
    check_boreal(&build_rule("100% of them"), b"c", false);
    check_boreal(&build_rule("100% of them"), b"a0b1", false);
    check_boreal(&build_rule("100% of them"), b"a0b1c", false);
    check_boreal(&build_rule("100% of them"), b"a0a1a2b0b1", false);
    check_boreal(&build_rule("100% of them"), b"a0a1a2b0b1c", true);

    check_boreal(&build_rule("101% of them"), b"", false);
    check_boreal(&build_rule("101% of them"), b"a0", false);
    check_boreal(&build_rule("101% of them"), b"a1", false);
    check_boreal(&build_rule("101% of them"), b"a2", false);
    check_boreal(&build_rule("101% of them"), b"b0", false);
    check_boreal(&build_rule("101% of them"), b"b1", false);
    check_boreal(&build_rule("101% of them"), b"c", false);
    check_boreal(&build_rule("101% of them"), b"a0b1", false);
    check_boreal(&build_rule("101% of them"), b"a0b1c", false);
    check_boreal(&build_rule("101% of them"), b"a0a1a2b0b1", false);
    check_boreal(&build_rule("101% of them"), b"a0a1a2b0b1c", false);
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

#[test]
fn test_eval_add() {
    check(&build_empty_rule("2 + 6 == 8"), &[], true);
    check(&build_empty_rule("3 + 4.2 == 7.2"), &[], true);
    check(&build_empty_rule("2.62 + 3 == 5.62"), &[], true);
    check(&build_empty_rule("1.3 + 1.5 == 2.8"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("#c + 0x7FFFFFFFFFFFFFFF + 1 > 0"), &[], false);
    check(&build_rule("#c + -2 + -0x7FFFFFFFFFFFFFFF < 0"), &[], false);
}

#[test]
fn test_eval_sub() {
    check(&build_empty_rule("2 - 6 == -4"), &[], true);
    check(&build_empty_rule("3 - 4.5 == -1.5"), &[], true);
    check(&build_empty_rule("2.62 - 3 == -0.38"), &[], true);
    check(&build_empty_rule("1.3 - 1.5 == -0.2"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("#c + -0x7FFFFFFFFFFFFFFF - 2 < 0"), &[], false);
    check(&build_rule("#c + 0x7FFFFFFFFFFFFFFF - -1 > 0"), &[], false);
}

#[test]
fn test_eval_mul() {
    check(&build_empty_rule("2 * 6 == 12"), &[], true);
    check(&build_empty_rule("3 * 0.1 == 0.3"), &[], true);
    check(&build_empty_rule("2.62 * 3 == 7.86"), &[], true);
    check(&build_empty_rule("1.3 * 0.5 == 0.65"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(
        &build_rule("(#c + -0x0FFFFFFFFFFFFFFF) * 10 < 0"),
        &[],
        false,
    );
    check(&build_rule("(#c + 0x1FFFFFFFFFFFFFFF) * 5 > 0"), &[], false);
}

#[test]
fn test_eval_div() {
    check(&build_empty_rule("7 \\ 4 == 1"), &[], true);
    check(&build_empty_rule("-7 \\ 4 == -1"), &[], true);
    check(&build_empty_rule("7 \\ 4.0 == 1.75"), &[], true);
    check(&build_empty_rule("7.0 \\ 4 == 1.75"), &[], true);
    check(&build_empty_rule("2.3 \\ 4.6 == 0.5"), &[], true);

    // Use some tricks to avoid overflow rejection in libyara on parsing
    check(&build_rule("1 \\ (#c + 0) == 1"), &[], false);
    check(&build_rule("-2 \\ (-0 + #c) > 0"), &[], false);

    // TODO: Dont actually test this on libyara, it triggers a SIGFPE. Report it upstream
    check_boreal(
        &build_rule("(#c + -0x7FFFFFFFFFFFFFFF - 1) \\ -1 > 0"),
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
        &build_rule("#c + 0x7FFFFFFFFFFFFFFF << 4 == -16"),
        &[],
        true,
    );
    check(
        &build_rule("#c + 0x7FFFFFFFFFFFFFFF << 1000 == 0"),
        &[],
        true,
    );
    check(
        &build_rule("#c + -0x7FFFFFFFFFFFFFFF << 1000 == 0"),
        &[],
        true,
    );
    check(&build_rule("12 << (#c + -2) == 0"), &[], false);
}

#[test]
fn test_eval_shr() {
    check(&build_empty_rule("15 >> 2 == 3"), &[], true);
    check(&build_empty_rule("0xDEADCAFE >> 16 == 0xDEAD"), &[], true);
    check(&build_empty_rule("-8 >> 1 == -4"), &[], true);

    check(
        &build_rule("#c + 0x7FFFFFFFFFFFFFFF >> 62 == 0x1"),
        &[],
        true,
    );
    check(
        &build_rule("#c + 0x7FFFFFFFFFFFFFFF >> 1000 == 0"),
        &[],
        true,
    );
    check(
        &build_rule("#c + -0x7FFFFFFFFFFFFFFF >> 1000 == 0"),
        &[],
        true,
    );
    check(&build_rule("12 >> (#c + -2) == 0"), &[], false);
}

#[test]
fn test_eval_var_count_string() {
    let rule = r#"
rule a {
    strings:
        $a = "abc"
    condition:
        #a == 3
}"#;
    check(rule, b"", false);
    check(rule, b"abcabc", false);
    check(rule, b"abcabcaabcb", true);
    check(rule, b"abcabcaabcb abc", false);

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
    let rule = r#"
rule a {
    strings:
        $a = "aa"
    condition:
        #a == 3
}"#;
    check(rule, b"aa", false);
    check(rule, b"aaa", false);
    check(rule, b"aaaa", true);
}

#[test]
fn test_eval_var_length_string() {
    let rule = r#"
rule a {
    strings:
        $a = "abc"
    condition:
        !a == 3
}"#;
    check(rule, b"", false);
    check(rule, b"abc", true);

    let rule = r#"
rule a {
    strings:
        $a = "abc"
    condition:
        !a[2] == 3
}"#;
    check(rule, b"", false);
    check(rule, b"abc", false);
    check(rule, b"abc abcc", true);

    let rule = r#"
rule a {
    strings:
        $a = "abc"
    condition:
        !a != 3
}"#;
    check(rule, b"", false);
    check(rule, b"abc", false);
    check(rule, b"abcabc", false);
}

#[test]
fn test_eval_var_offset_string() {
    let rule = r#"
rule a {
    strings:
        $a = "ab"
    condition:
        @a == 2
}"#;
    check(rule, b"", false);
    check(rule, b"ab", false);
    check(rule, b" ab", false);
    check(rule, b"  ab", true);
    check(rule, b"   ab", false);
    check(rule, b"abab", false);

    let rule = r#"
rule a {
    strings:
        $a = "abc"
        $y = "y"
        $z = "z"
    condition:
        @a[#y + 1] == #z
}"#;
    check(rule, b"", false);
    check(rule, b"abc", true);
    check(rule, b"abc z", false);
    check(rule, b"abc abc y zzz", false);
    check(rule, b"abc abc y zzzz", true);
    check(rule, b"abc abc yy zzzz", false);
    check(rule, b"abcabcabc yy zzzzzz", true);
    check(rule, b"abcabcabc yy zzzzzzz", false);
}

#[test]
fn test_eval_var_count_regex() {
    let rule = r#"
rule a {
    strings:
        $a = /a.*b/
    condition:
        #a == 3
}"#;
    check(rule, b"", false);
    check(rule, b"aaab", true);
    check(rule, b"abab", false);
    check(rule, b"ab aaabb acb", false);
    check(rule, b"ab abb acb", true);
    check(rule, b"aaabbb", true);
    check(rule, b"aaaabbb", false);

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
    let rule = r#"
rule a {
    strings:
        $a = /a.*b/
    condition:
        !a == 3
}"#;
    check(rule, b"", false);
    check(rule, b"ab", false);
    check(rule, b"azb", true);
    // Regexes are greedy
    check(rule, b"aabb", false);

    let rule = r#"
rule a {
    strings:
        $a = "a.*b+"
    condition:
        $a
}"#;

    check(rule, b"aaabb", false);
    check(rule, b"aa.*b+", true);

    let rule = r#"
rule a {
    strings:
        $a = /a.*b+/
        $y = "y"
        $z = "z"
    condition:
        !a[#y + 1] == #z
}"#;
    check(rule, b"aaabb", false);
    check(rule, b"aaabbcb z zzz zzz", true);
    check(rule, b"aaabb y zzzz", true);
    check(rule, b"aaabb yy zzz", true);
}

#[test]
fn test_eval_var_offset_regex() {
    let rule = r#"
rule a {
    strings:
        $a = /a+b/
    condition:
        @a == 2
}"#;
    check(rule, b"", false);
    check(rule, b"ab", false);
    check(rule, b" ab", false);
    check(rule, b"  ab", true);
    check(rule, b"  aab", true);
    check(rule, b"   ab", false);
    check(rule, b"abab", false);

    let rule = r#"
rule a {
    strings:
        $a = /a.*c/
        $y = "y"
        $z = "z"
    condition:
        @a[#y + 1] == #z
}"#;
    check(rule, b"", false);
    check(rule, b"abc", true);
    check(rule, b"abc z", false);
    check(rule, b"abc abc y zzz", false);
    check(rule, b"abc abc y zzzz", true);
    check(rule, b"abc abc yy zzzz", false);
    check(rule, b"abcabcabc yy zzzzzz", true);
    check(rule, b"abcabcabc yy zzzzzzz", false);
}

#[test]
fn test_eval_var_count_hex_string() {
    let rule = r#"
rule a {
    strings:
        $a = { AB [1-3] CD }
    condition:
        #a == 2
}"#;
    check(rule, b"\xab\xcd \xab_\xcd", false);
    check(rule, b"\xabpad\xcd \xab_\xcd", true);
    check(rule, b"\xab\xab_\xcd", true);
    check(rule, b"\xab\xab\xab_\xcd", false);
    check(rule, b"\xabpa\xcd\xcd", false);

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
    let rule = r#"
rule a {
    strings:
        $a = { AB [1-3] CD }
    condition:
        !a == 3
}"#;
    check(rule, b"\xab_\xcd", true);
    // hex strings are NOT greedy
    check(rule, b"\xab_\xcd\xcd", true);
    check(rule, b"\xab_\xcd\xcd\xcd", true);
    check(rule, b"\xabpad\xcd", false);

    let rule = r#"
rule a {
    strings:
        $a = { 61 [1-] 62 }
        $y = "y"
        $z = "z"
    condition:
        !a[#y + 1] == #z
}"#;
    check(rule, b"a_b", false);
    check(rule, b"a_b zzz", true);
    check(rule, b"a1234b zzz zzz", true);

    check(rule, b"a_b aa999b y zzz zzz", true);
    check(rule, b"a_b aa999b yy zz zzz", true);

    // This alternation will always resolve to the shortest one.
    // FIXME: fix this, test more complex alternations / masked bytes
    if false {
        let rule = r#"
    rule a {
        strings:
            $a = { AB ( ?F | FF [1-3] CD ) }
            $b = { AB ( FF [1-3] CD | ?F ) }
        condition:
            !a == 2 and !b == 2
    }"#;
        check(rule, b"\xab\xff", true);
        check(rule, b"zz \xab\xff_\xcd", true);
        check(rule, b"zz \xab\xffpad\xcd", true);
    }
}

#[test]
fn test_eval_var_offset_hex_string() {
    let rule = r#"
rule a {
    strings:
        $a = { 61 [1-3] 62 }
        $y = "y"
        $z = "z"
    condition:
        @a[#y + 1] == #z
}"#;
    check(rule, b"a_b zz", false);
    check(rule, b" a__b zz", false);
    check(rule, b"  a___b zz", true);
    check(rule, b" aa_b zz", false);
    check(rule, b" aa_b y zz", true);
    check(rule, b"a_b aa__b y zzzz", true);
    check(rule, b"a_b aa__b yy zzzzz", true);
}

// TODO: test count, offset, length with selected for variable
