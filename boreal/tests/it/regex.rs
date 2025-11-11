use crate::utils::{check, check_err, Checker};

fn build_rule(var: &str) -> String {
    format!(
        r#"
rule a {{
    strings:
        $ = {var}
    condition:
        all of them
}}"#
    )
}

#[test]
fn test_regex_unicode_handling() {
    // The '+' will apply on the last byte of the 'é' utf-8 char, not on the char itself,
    // so this is: `<\xC3\xA9+>`.
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /<é+>/
    condition:
        $a
}"#,
    );
    checker.check(b"", false);
    checker.check("é".as_bytes(), false);
    checker.check("<é>".as_bytes(), true);
    checker.check(b"<\xC3\xA9>", true);
    checker.check(b"<\xC3\xA9\xC3\xA9>", false);
    checker.check("<éé>".as_bytes(), false);
    checker.check(b"<\xC3\xA9\xA9>", true);
    checker.check(b"<\xC3\xA9\xA9\xA9\xA9>", true);
    checker.check(b"<\xC3\xA9\xA9\xA9\xA9", false);
    checker.check(b"\xC3\xA9\xA9\xA9\xA9>", false);

    // unicode chars in a class is not accepted.
    check_err(
        "rule a { strings: $a = /[é]/ condition: $a }",
        "mem:1:26: error: regex should only contain ascii bytes",
    );

    // escaped unicode char is accepted.
    let mut checker = Checker::new(r"rule a { strings: $a = /\µ/ condition: $a }");
    checker.check("µ".as_bytes(), true);
}

#[test]
fn test_regex_flags() {
    let mut checker = Checker::new(&build_rule(r"/a.b/"));
    checker.check(b"ab", false);
    checker.check(b"aab", true);
    checker.check(b"AaB", false);
    checker.check(b"Aab", false);
    checker.check(b"aaB", false);
    checker.check(b"a\tb", true);
    checker.check(b"a\nb", false);
    checker.check(b"A\nB", false);

    let mut checker = Checker::new(&build_rule(r"/a.b/s"));
    checker.check(b"ab", false);
    checker.check(b"aab", true);
    checker.check(b"AaB", false);
    checker.check(b"Aab", false);
    checker.check(b"aaB", false);
    checker.check(b"a\tb", true);
    checker.check(b"a\nb", true);
    checker.check(b"A\nB", false);

    let mut checker = Checker::new(&build_rule(r"/a.b/i"));
    checker.check(b"ab", false);
    checker.check(b"aab", true);
    checker.check(b"AaB", true);
    checker.check(b"Aab", true);
    checker.check(b"aaB", true);
    checker.check(b"a\tb", true);
    checker.check(b"a\nb", false);
    checker.check(b"A\nB", false);

    let mut checker = Checker::new(&build_rule(r"/a.b/is"));
    checker.check(b"ab", false);
    checker.check(b"aab", true);
    checker.check(b"AaB", true);
    checker.check(b"Aab", true);
    checker.check(b"aaB", true);
    checker.check(b"a\tb", true);
    checker.check(b"a\nb", true);
    checker.check(b"A\nB", true);
}

#[test]
fn test_regex_anchors() {
    let mut checker = Checker::new(&build_rule(r"/^a/"));
    checker.check(b"a", true);
    checker.check(b"ab", true);
    checker.check(b"ba", false);
    checker.check(b"b\ta", false);
    checker.check(b"b\na", false);
    let mut checker = Checker::new(&build_rule(r"/a$/"));
    checker.check(b"a", true);
    checker.check(b"ab", false);
    checker.check(b"ba", true);
    checker.check(b"a\tb", false);
    checker.check(b"a\nb", false);

    // s flag does not modify this behavior
    let mut checker = Checker::new(&build_rule(r"/^a/s"));
    checker.check(b"a", true);
    checker.check(b"ab", true);
    checker.check(b"ba", false);
    checker.check(b"b\ta", false);
    checker.check(b"b\na", false);
    let mut checker = Checker::new(&build_rule(r"/a$/s"));
    checker.check(b"a", true);
    checker.check(b"ab", false);
    checker.check(b"ba", true);
    checker.check(b"a\tb", false);
    checker.check(b"a\nb", false);
}

#[test]
fn test_regex_unneeded_escapes() {
    // Escaping for specific bytes
    check(
        &build_rule(r"/<\a\f\r\t\n\xE9>/"),
        b"<\x07\x0C\r\t\n\xE9>",
        true,
    );

    // Escaping for specific regex behavior
    let mut checker = Checker::new(&build_rule(r"/<\w\W>/"));
    checker.check(b"<ab>", false);
    checker.check(b"<a/>", true);
    checker.check(b"<_]>", true);
    checker.check(b"<8]>", true);
    checker.check(b"<88>", false);
    checker.check(b"<[]>", false);
    let mut checker = Checker::new(&build_rule(r"/<\d\D>/"));
    checker.check(b"<ab>", false);
    checker.check(b"<7b>", true);
    checker.check(b"<77>", false);
    let mut checker = Checker::new(&build_rule(r"/<\s\S>/"));
    checker.check(b"<ab>", false);
    checker.check(b"< b>", true);
    checker.check(b"<\tb>", true);
    checker.check(b"<\t >", false);
    let mut checker = Checker::new(&build_rule(r"/\bab\B/"));
    checker.check(b"ab", false);
    checker.check(b"<ab>", false);
    checker.check(b"abc", true);
    checker.check(b"<abc", true);
    checker.check(b"zabc", false);
    checker.check(b"zab", false);

    // Escaping for special regex characters
    check(&build_rule(r"/<\.\[\]\+\*\?>/"), b"<.[]+*?>", true);
    check(&build_rule(r"/\\/"), b"\\", true);

    // Escaping the '/' character is handled during parsing.
    check(&build_rule(r"/<\/>/"), b"</>", true);

    // Escaping on other stuff will discard the escape
    check(&build_rule(r#"/\<\z\/\!\ \"\'\>/"#), br#"<z/! "'>"#, true);

    // Test from libyara: makes no sense, but works because of useless escapes being removed
    // This accepts 0, x, 5, then A-Z [ \\ and ]
    // This is *not* \x5A to \x5D
    let mut checker = Checker::new(&build_rule(r"/[\0x5A-\x5D]/"));
    checker.check(b"0", true);
    checker.check(b"1", false);
    checker.check(b"x", true);
    checker.check(b"5", true);
    checker.check(b"A", true);
    checker.check(b"Z", true);
    checker.check(b"[", true);
    checker.check(b"\\", true);
    checker.check(b"]", true);
    checker.check(b"^", false);
}

#[test]
fn test_regex_at_most_repetitions() {
    let mut checker = Checker::new(&build_rule(r"/<a{,2}>/"));
    checker.check(b"<>", true);
    checker.check(b"<a>", true);
    checker.check(b"<aa>", true);
    checker.check(b"<aaa>", false);

    // Empty means {0,}, so same as *
    let mut checker = Checker::new(&build_rule(r"/<a{,}>/"));
    checker.check(b"<>", true);
    checker.check(b"<a>", true);
    checker.check(b"<aaaaaaaaaaaaaaaaaa>", true);
    checker.check(b"<", false);
    checker.check(b">", false);

    let mut checker = Checker::new(&build_rule(r"/<a\{,2}>/"));
    checker.check(b"<>", false);
    checker.check(b"<a>", false);
    checker.check(b"<a{,2}>", true);

    let mut checker = Checker::new(&build_rule(r"/<\\{,2}>/"));
    checker.check(br"<>", true);
    checker.check(br"<\>", true);
    checker.check(br"<\\>", true);
    checker.check(br"<\\\>", false);

    let mut checker = Checker::new(&build_rule(r"/<a{\,2}>/"));
    checker.check(br"<>", false);
    checker.check(br"<a>", false);
    checker.check(br"<aa>", false);
    checker.check(br"<aaa>", false);
    checker.check(br"<a{,2}>", true);

    let mut checker = Checker::new(&build_rule(r"/<a{{,2}>/"));
    checker.check(br"<a>", true);
    checker.check(br"<a{>", true);
    checker.check(br"<a{{>", true);
    checker.check(br"<a{{{>", false);
    checker.check(br"<a{{,2}>", false);

    let mut checker = Checker::new(&build_rule(r"/<\{{,2}>/"));
    checker.check(br"<>", true);
    checker.check(br"<{>", true);
    checker.check(br"<{{>", true);
    checker.check(br"<{{{>", false);
}

// Check the regex size is checked regardless of the matcher picked.
#[test]
fn test_regex_size() {
    let check =
        |regex| {
            check_err(&format!("rule test {{ strings: $a = {regex} condition: $a }}"),
        "mem:1:22: error: variable $a cannot be compiled: Compiled regex exceeds size limit");
        };

    // Raw matcher
    check("/^a{2977952116}/");
    check(r"/^a{2977952116}\b/ wide");

    // Right validator
    check("/abcd a{0,2977952116}?/");

    // Left validator
    check("/a{0,2977952116}? abcd/");

    // Left greedy validator
    check("/a{0,2977952116} abcd/");
    // Full greedy validator
    check("/a+ abcd a{0,2977952116}/");
}

#[test]
fn test_regex_same_alternative() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a(bcd|bcd)e/
    condition:
        #a == 1
}"#,
    );
    checker.check(b"0abcdef", true);

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /(\x00abcd|abcd\x00)/
    condition:
        #a == 1
}"#,
    );
    checker.check(b"<\x00abcd>", true);
    checker.check(b"<abcd\x00>", true);
    checker.check(b"<\x00abcd\x00>", false);
}
