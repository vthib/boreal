use crate::utils::{check, check_err, Checker};

fn build_rule(var: &str) -> String {
    format!(
        r#"
rule a {{
    strings:
        $ = {}
    condition:
        all of them
}}"#,
        var
    )
}

#[test]
fn test_regex_unicode_handling() {
    // Unicode characters are rejected inside a regex.
    // TODO: this is broken in libyara: see https://github.com/VirusTotal/yara/pull/1770
    // To re-enable once updated to 4.3
    // check_err(
    //     "rule a { strings: $a = /<é+>/ condition: $a }",
    //     "mem:1:26: error: regex should only contain ascii bytes",
    // );
    check_err(
        "rule a { strings: $a = /[é]/ condition: $a }",
        "mem:1:26: error: regex should only contain ascii bytes",
    );
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
    let checker = Checker::new(&build_rule(r"/<\w\W>/"));
    checker.check(b"<ab>", false);
    checker.check(b"<a/>", true);
    checker.check(b"<_]>", true);
    checker.check(b"<8]>", true);
    checker.check(b"<88>", false);
    checker.check(b"<[]>", false);
    let checker = Checker::new(&build_rule(r"/<\d\D>/"));
    checker.check(b"<ab>", false);
    checker.check(b"<7b>", true);
    checker.check(b"<77>", false);
    let checker = Checker::new(&build_rule(r"/<\s\S>/"));
    checker.check(b"<ab>", false);
    checker.check(b"< b>", true);
    checker.check(b"<\tb>", true);
    checker.check(b"<\t >", false);
    let checker = Checker::new(&build_rule(r"/\bab\B/"));
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
    let checker = Checker::new(&build_rule(r"/[\0x5A-\x5D]/"));
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
    let checker = Checker::new(&build_rule(r"/<a{,2}>/"));
    checker.check(b"<>", true);
    checker.check(b"<a>", true);
    checker.check(b"<aa>", true);
    checker.check(b"<aaa>", false);

    // Empty means {0,}, so same as *
    let checker = Checker::new(&build_rule(r"/<a{,}>/"));
    checker.check(b"<>", true);
    checker.check(b"<a>", true);
    checker.check(b"<aaaaaaaaaaaaaaaaaa>", true);
    checker.check(b"<", false);
    checker.check(b">", false);

    let checker = Checker::new(&build_rule(r"/<a\{,2}>/"));
    checker.check(b"<>", false);
    checker.check(b"<a>", false);
    checker.check(b"<a{,2}>", true);

    let checker = Checker::new(&build_rule(r"/<\\{,2}>/"));
    checker.check(br"<>", true);
    checker.check(br"<\>", true);
    checker.check(br"<\\>", true);
    checker.check(br"<\\\>", false);

    let checker = Checker::new(&build_rule(r"/<a{\,2}>/"));
    checker.check(br"<>", false);
    checker.check(br"<a>", false);
    checker.check(br"<aa>", false);
    checker.check(br"<aaa>", false);
    checker.check(br"<a{,2}>", true);

    let checker = Checker::new(&build_rule(r"/<a{{,2}>/"));
    checker.check(br"<a>", true);
    checker.check(br"<a{>", true);
    checker.check(br"<a{{>", true);
    checker.check(br"<a{{{>", false);
    checker.check(br"<a{{,2}>", false);

    let checker = Checker::new(&build_rule(r"/<\{{,2}>/"));
    checker.check(br"<>", true);
    checker.check(br"<{>", true);
    checker.check(br"<{{>", true);
    checker.check(br"<{{{>", false);
}