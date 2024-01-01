use crate::utils::{build_rule, check, check_err, Checker};

#[test]
fn test_variable() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "X"
        $b = "foo"
        $c = /re+xv?/
        $d = /^bav/
        $e = { FF ( ?A | B? [1-3] ?? ) FF }
    condition:
        any of them
}"#,
    );
    checker.check(b"nothing", false);
    checker.check(b"i Xm", true);
    checker.check(b"barfool", true);
    checker.check(b"greeex", true);
    checker.check(b"bZv", false);
    checker.check(b"bavaoze", true);
    checker.check(b"abavaoze", false);
    checker.check(b"a\xFF\xDC\xFFp", false);
    checker.check(b"dbaz\xFF\xDA\xFFeaz", true);
    checker.check(b"dbaz\xFF\xBFer\xFFeaz", true);
    checker.check(b"dbaz\xFF\xBFerdf\xFFeaz", true);
}

#[test]
fn test_variable_err() {
    check_err(
        "rule a {
    condition:
        $a
}",
        "mem:3:9: error: unknown variable $a",
    );

    check_err(
        "rule a {
    strings:
        $a = /aaa/
    condition:
        true
}",
        "mem:3:9: error: variable $a is unused",
    );
}

#[test]
fn test_variable_regex_modifiers() {
    // \x76 is 'v'
    let mut checker = Checker::new(
        r"
rule a {
    strings:
        $a = /f[aF]T[d-g]\x76/ nocase
        $b = /foo/ fullword
        $c = /bar.{0,3}/ fullword nocase
        $d = /.{,2}quu/ nocase fullword
    condition:
        any of them
}",
    );

    // Nocase: work on literals, ranges, and explicit hexa char
    checker.check(b"faTgv", true);
    checker.check(b"faTgx", false);
    checker.check(b"FATGV", true);
    checker.check(b"fftDV", true);
    checker.check(b"fftEV", true);
    checker.check(b"fftE", false);
    checker.check(b"ftEV", false);

    // Fullword
    checker.check(b"foo", true);
    checker.check(b" foo ", true);
    checker.check(b"-foo_", true);
    checker.check(b"-fooa", false);
    checker.check(b"-fooA", false);
    checker.check(b"-foo0", false);
    checker.check(b"afoo:", false);
    checker.check(b"Zfoo:", false);
    checker.check(b"0foo:", false);

    checker.check(b"bar-", true);
    checker.check(b"bara-", true);
    checker.check(b"baraa-", true);
    checker.check(b"baraaa-", true);
    checker.check(b"baraaaa-", false);
    checker.check(b"abaraaa-", false);
    checker.check(b"|baraaa-", true);
    checker.check(b"|bar", true);

    checker.check(b"quu", true);
    checker.check(b"QUU", true);
    checker.check(b"quux", false);
    checker.check(b"aQuu", true);
    checker.check(b"aqUU", true);
    checker.check(b"aaqUu", true);
    checker.check(b"aAaQUu", false);

    // Test fullword with raw matcher
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a$/ fullword
    condition:
        $a
}"#,
    );
    checker.check(b"", false);
    checker.check(b"a", true);
    checker.check(b"ba", false);
    checker.check(b"<a", true);
    checker.check(b"ab", false);
    checker.check(b"b", false);

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /.{0,2}yay.{0,2}/ fullword
    condition:
        $a
}"#,
    );

    checker.check(b"yay", true);
    // This is an example of something that would match with a smart regex, but does not with the
    // yara implem: find a match, check fullword, find next match, etc.
    checker.check(b"| yay |a", false);
    // But this works. Why? because we advance by one byte after every match.
    // First match: `| yay |` => not fullword
    // second match: ` yay |` => fullword, match
    checker.check(b"a| yay |", true);

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /.{0,2}yay.{0,2}/
    condition:
        #a == 3
}"#,
    );
    // Confirmation, we have three matches here, for the 3 possibles captures on the left. However,
    // the right capture is always greedy.
    checker.check(b"a| yay |a", true);
}

fn build_checker(regex: &str, modifiers: &str) -> Checker {
    Checker::new(&format!(
        r#"
rule a {{
    strings:
        $a = /{regex}/ {modifiers}
    condition:
        $a
}}"#
    ))
}

fn to_wide(e: &[u8]) -> Vec<u8> {
    let mut ret = Vec::new();

    for c in e {
        ret.push(*c);
        ret.push(b'\0');
    }

    ret
}

#[test]
fn test_variable_regex_wide() {
    // Without yara, it does not allow empty regex nodes
    let mut checker = Checker::new_without_yara(
        r#"
        rule a {
            strings:
                $a = /()/ wide
            condition:
                $a
        }"#,
    );
    checker.check(b"", false);
    checker.check(b"\0", true);

    let mut checker = build_checker(".", "wide");
    checker.check(b"", false);
    checker.check(b"\0", false);
    checker.check(b"a", false);
    checker.check(b"a\0", true);
    checker.check(b"ab", false);

    let mut checker = build_checker("abc", "wide");
    checker.check(b"abc", false);
    checker.check(b"a\0b\0c\0", true);
    checker.check(b"a\0b\0c", false);
    checker.check(b"ab\0c\0", false);
    checker.check(b"\0a\0b\0c\0", true);
    checker.check(b"\0a\0b\0c", false);

    let mut checker = build_checker("a+b|cd{2,}", "wide");
    checker.check(b"ab", false);
    checker.check(b"aaab", false);
    checker.check(b"abcd", false);
    checker.check(b"cdd", false);
    checker.check(b"a\0b\0", true);
    checker.check(b"aa\0b\0", true);
    checker.check(b"a\0a\0b\0", true);
    checker.check(b"a\0a\0a\0a\0b\0", true);
    checker.check(b"c\0d\0", false);
    checker.check(b"c\0d\0d", false);
    checker.check(b"c\0d\0d\0", true);
    checker.check(b"c\0d\0d\0d\0d\0", true);

    let mut checker = build_checker("<[a-z][0-9]*>", "wide");
    checker.check(b"<a>", false);
    checker.check(b"<\x00a\x00>\x00", true);
    checker.check(b"<\x00a>\x00", false);
    checker.check(b"<\x00\x00\x00>\x00", false);
    checker.check(b"<\x00\x00>\x00", false);
    checker.check(b"<b22>", false);
    checker.check(b"<\x00b\x0022\x00>\x00", false);
    checker.check(b"<\x00b\x002\x002\x00>\x00", true);
    checker.check(b"<\x00a\x009\x003\x00>\x00", true);
    checker.check(b"<\x00a\x009\x00d\x00>\x00", false);
    checker.check(b"a\x009\x00", false);

    let mut checker = build_checker(r"\d[^abc]d$", "wide");
    checker.check(b"13d", false);
    checker.check(b"1\x003\x00d\x00", true);
    checker.check(b"1\x003\x00d", false);
    checker.check(b"1\x003\x00\x00", false);
    checker.check(b"a\x00d\x00d\x00", false);
    checker.check(b"1\x00a\x00d\x00", false);
    checker.check(b"1\x00d\x00e\x00", false);
    checker.check(b"1\x00d\x00d\x00", true);

    let mut checker = build_checker(r"a(b|c+)[def][^g]", "wide ascii");
    checker.check(b"abdf", true);
    checker.check(b"a\0b\0d\0f\0", true);
    checker.check(b"a\0b\0d\0f", false);
    checker.check(b"abeg", false);
    checker.check(b"a\0b\0e\0g\0", false);
    checker.check(b"acccf\0", true);
    checker.check(b"a\0c\0c\0c\0f\0\0\0", true);
    checker.check(b"a\0c\0c\0c\0f\0\0", false);

    let mut checker = build_checker(r"d\b", "wide ascii");
    checker.check(b"d", true);
    checker.check(b"d\0", true);
    checker.check(b"d.", true);
    checker.check(b"d\0b", true);
    checker.check(b"d\0b\0", true);
    checker.check(b"d\0.\0", true);
    checker.check(b"da", false);
    checker.check(b"da\0", false);

    let mut checker = build_checker(r"ad\b", "wide ascii");
    checker.check(b"ad", true);
    checker.check(b"ad\0", true);
    checker.check(b"ad.", true);
    checker.check(b"ad\0b", true);
    checker.check(b"ad\0b\0", true);
    checker.check(b"ad\0.\0", true);
    checker.check(b"ada", false);
    checker.check(b"ada\0", false);
    checker.check(b"a\0d\0", true);
    checker.check(b"a\0d\0b", true);
    checker.check(b"a\0d\0b\0", false);
    checker.check(b"a\0d\0.\0", true);
    checker.check(b"a\0da", false);
    checker.check(b"a\0da\0", false);
}

fn join(expr: &[u8], prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(prefix);
    out.extend(expr);
    out.extend(suffix);
    out
}

fn test_regex_wide_fullword(regex: &str, mem_ascii: &[u8]) {
    let mem_wide = &to_wide(mem_ascii);

    // Ascii fullword
    let mut checker = build_checker(regex, "ascii fullword");
    checker.check(&join(mem_ascii, b"", b""), true);
    checker.check(&join(mem_ascii, b"a", b""), false);
    checker.check(&join(mem_ascii, b"", b"a"), false);
    checker.check(&join(mem_ascii, b"<", b"a"), false);
    checker.check(&join(mem_ascii, b"a", b">"), false);
    checker.check(&join(mem_ascii, b"<", b">"), true);

    // Wide fullword
    let mut checker = build_checker(regex, "wide fullword");
    checker.check(&join(mem_wide, b"", b""), true);
    checker.check(&join(mem_wide, b"a", b""), true);
    checker.check(&join(mem_wide, b"", b"a"), true);
    checker.check(&join(mem_wide, b"<", b"a"), true);
    checker.check(&join(mem_wide, b"a", b">"), true);
    checker.check(&join(mem_wide, b"<", b">"), true);

    checker.check(&join(mem_wide, b"<\0", b">\0"), true);
    checker.check(&join(mem_wide, b"<\0", b"b\0"), false);
    checker.check(&join(mem_wide, b"a\0", b">\0"), false);
    checker.check(&join(mem_wide, b"<\0a\0", b"b\0>\0"), false);
    checker.check(&join(mem_wide, b"a\0<\0", b">\0a\0"), true);

    // Ascii wide fullword
    let mut checker = build_checker(regex, "ascii wide fullword");
    checker.check(&join(mem_ascii, b"", b""), true);
    checker.check(&join(mem_ascii, b"a", b""), false);
    checker.check(&join(mem_ascii, b"", b"a"), false);
    checker.check(&join(mem_ascii, b"a", b"a"), false);
    checker.check(&join(mem_ascii, b"<", b">"), true);

    checker.check(&join(mem_ascii, b"<\0", b">\0"), true);
    checker.check(&join(mem_ascii, b"<\0", b"b\0"), false);
    checker.check(&join(mem_ascii, b"a\0", b">\0"), true);
    checker.check(&join(mem_ascii, b"<\0a\0", b"b\0>\0"), false);
    checker.check(&join(mem_ascii, b"a\0<\0", b">\0a\0"), true);

    // TODO: This is caused by <https://github.com/VirusTotal/yara/issues/1933>
    checker.check_boreal(&join(mem_wide, b"", b""), true);
    checker.check_boreal(&join(mem_wide, b"a", b""), true);
    checker.check_boreal(&join(mem_wide, b"", b"a"), true);
    checker.check_boreal(&join(mem_wide, b"a", b"a"), true);
    checker.check_boreal(&join(mem_wide, b"<", b">"), true);

    checker.check_boreal(&join(mem_wide, b"<\0", b">\0"), true);
    checker.check_boreal(&join(mem_wide, b"<\0", b"b\0"), false);
    checker.check_boreal(&join(mem_wide, b"a\0", b">\0"), false);
    checker.check_boreal(&join(mem_wide, b"<\0a\0", b"b\0>\0"), false);
    checker.check_boreal(&join(mem_wide, b"a\0<\0", b">\0a\0"), true);
}

#[test]
fn test_variable_regex_wide_fullword() {
    // Dot is here to avoid the literals extraction handling
    test_regex_wide_fullword("b.{1,5}?123", b"bb123");
    test_regex_wide_fullword("b.{1,5}123", b"bb123");

    // Test the raw regex matcher, no literals possible to extract)
    test_regex_wide_fullword(r"(a.{5}1|z+)", b"abcdef1");

    // Same thing, but with a tricky regex: the literal looks "wide", but is considered ascii
    test_regex_wide_fullword(r"b\x00.{1,5}?i\x00j\x00k\x00", &to_wide(b"bbijk"));
    test_regex_wide_fullword(r"b\x00.{1,5}i\x00j\x00k\x00", &to_wide(b"bbijk"));
}

#[test]
fn test_variable_regex_wide_fullword_raw() {
    // Test the wide fullword behavior with the "raw" matcher.
    // To ensure we get the raw matcher, we use a anchor.
    let mut checker = build_checker("^ab", "ascii wide fullword");
    let mem_ascii = b"ab";
    let mem_wide = b"a\0b\0";
    checker.check(&join(mem_ascii, b"", b""), true);
    checker.check(&join(mem_ascii, b"", b"a"), false);
    checker.check(&join(mem_ascii, b"", b">"), true);
    checker.check(&join(mem_ascii, b"", b">\0"), true);
    checker.check(&join(mem_ascii, b"", b"a\0"), false);

    checker.check(&join(mem_wide, b"", b""), true);
    checker.check(&join(mem_wide, b"", b"a"), true);
    checker.check(&join(mem_wide, b"", b">"), true);
    checker.check(&join(mem_wide, b"", b">\0"), true);
    checker.check(&join(mem_wide, b"", b"a\0"), false);

    let mut checker = build_checker("ab$", "ascii wide fullword");
    checker.check(&join(mem_ascii, b"", b""), true);
    checker.check(&join(mem_ascii, b"a", b""), false);
    checker.check(&join(mem_ascii, b"<", b""), true);
    checker.check(&join(mem_ascii, b"<\0", b""), true);
    checker.check(&join(mem_ascii, b"a\0", b""), true);

    checker.check(&join(mem_wide, b"", b""), true);
    checker.check(&join(mem_wide, b"a", b""), true);
    checker.check(&join(mem_wide, b"<", b""), true);
    checker.check(&join(mem_wide, b"<\0", b""), true);
    checker.check(&join(mem_wide, b"a\0", b""), false);

    // Do the same with word boundaries instead of fullword modifier
    let mut checker = build_checker(r"\bab$", "ascii wide");
    checker.check(&join(mem_ascii, b"", b""), true);
    checker.check(&join(mem_ascii, b"a", b""), false);
    checker.check(&join(mem_ascii, b"<", b""), true);
    checker.check(&join(mem_ascii, b"<\0", b""), true);
    checker.check(&join(mem_ascii, b"a\0", b""), true);

    checker.check(&join(mem_wide, b"", b""), true);
    checker.check(&join(mem_wide, b"a", b""), true);
    checker.check(&join(mem_wide, b"<", b""), true);
    checker.check(&join(mem_wide, b"<\0", b""), true);
    checker.check(&join(mem_wide, b"a\0", b""), false);

    let mut checker = build_checker(r"^a\x00b\x00", "ascii wide fullword");
    let mem_ascii = b"a\0b\0";
    let mem_wide = &to_wide(mem_ascii);
    checker.check(&join(mem_ascii, b"", b""), true);
    checker.check(&join(mem_ascii, b"", b"a"), false);
    checker.check(&join(mem_ascii, b"", b">"), true);
    checker.check(&join(mem_ascii, b"", b">\0"), true);
    checker.check(&join(mem_ascii, b"", b"a\0"), false);

    checker.check(&join(mem_wide, b"", b""), true);
    checker.check(&join(mem_wide, b"", b"a"), true);
    checker.check(&join(mem_wide, b"", b">"), true);
    checker.check(&join(mem_ascii, b"", b">\0"), true);
    checker.check(&join(mem_ascii, b"", b"a\0"), false);
}

// Test wide regex with word boundaries
#[test]
fn test_variable_regex_wide_word_boundaries() {
    // Test regex consisting of a single word boundary. No-one will ever use this regex, but
    // it helps comparing with libyara
    let mut checker = build_checker(r"\b", "wide");
    checker.check(b"", false);
    checker.check(b"\0", false);
    // This one has different behavior from libyara. Does it matter? no, no-one will every use
    // this regex.
    checker.check_boreal(b"a\0", true);
    checker.check_libyara(b"a\0", false);
    checker.check(b"\0a", false);

    let mut checker = build_checker(r"\B", "wide");
    checker.check(b"", false);
    // These ones have different behavior from libyara. Does it matter? no, no-one will every use
    // this regex.
    checker.check_boreal(b"\0", true);
    checker.check_libyara(b"\0", false);
    checker.check_boreal(b"a\0", true);
    checker.check_libyara(b"a\0", false);
    checker.check_boreal(b"\0a", true);
    checker.check_libyara(b"\0a", false);

    // Check word boundary at start
    let mut checker = build_checker(r"\ba+", "wide");
    checker.check(b"", false);
    checker.check(b"a", false);
    checker.check(b"a\0", true);
    checker.check(b"a\0b", true);
    checker.check(b"a\0b\0", true);
    checker.check(b"a\0>\0", true);
    checker.check(b"ba\0", true);
    checker.check(b"\0a\0", true);
    checker.check(b"b\0a\0", false);
    checker.check(b"[\0a\0", true);
    checker.check(b"b\ra\0", true);
    let mut checker = build_checker(r"\Ba", "wide");
    checker.check(b"", false);
    checker.check(b"a", false);
    checker.check(b"a\0", false);
    checker.check(b"a\0b", false);
    checker.check(b"a\0b\0", false);
    checker.check(b"a\0>\0", false);
    checker.check(b"ba\0", false);
    checker.check(b"\0a\0", false);
    checker.check(b"b\0a\0", true);
    checker.check(b"[\0a\0", false);
    checker.check(b"b\ra\0", false);

    // Check word boundary at end
    let mut checker = build_checker(r"a+\b", "wide");
    checker.check(b"", false);
    checker.check(b"a", false);
    checker.check(b"a\0", true);
    checker.check(b"a\0b", true);
    checker.check(b"a\0b\0", false);
    checker.check(b"a\0>\0", true);
    checker.check(b"ba\0", true);
    checker.check(b"\0a\0", true);
    checker.check(b"b\0a\0", true);
    checker.check(b"[\0a\0", true);
    checker.check(b"b\ra\0", true);
    let mut checker = build_checker(r"a\B", "wide");
    checker.check(b"", false);
    checker.check(b"a", false);
    checker.check(b"a\0", false);
    checker.check(b"a\0b", false);
    checker.check(b"a\0b\0", true);
    checker.check(b"a\0>\0", false);
    checker.check(b"ba\0", false);
    checker.check(b"\0a\0", false);
    checker.check(b"b\0a\0", false);
    checker.check(b"[\0a\0", false);
    checker.check(b"b\ra\0", false);

    // Check word boundary in the middle
    let mut checker = build_checker(r"<.+\bA\b.+>", "wide");
    checker.check(&to_wide(b""), false);
    checker.check(&to_wide(b"<>"), false);
    checker.check(&to_wide(b"<A>"), false);
    checker.check(&to_wide(b"<[A]>"), true);
    checker.check(&to_wide(b"<[aAa]>"), false);
    checker.check(&to_wide(b"<a[A]a>"), true);
    checker.check(&to_wide(b"<aaA]a>"), false);
    // Lets check more complex cases
    checker.check(&to_wide(b"<aAAAAa>"), false);
    checker.check(&to_wide(b"<a[AA]>"), false);
    checker.check(&to_wide(b"<a[AAA.A!AA]>"), true);
    checker.check(&to_wide(b"<a[A.AAA]>"), true);
    checker.check(&to_wide(b"<a[AA.AAA]>"), false);
    checker.check(&to_wide(b"<a[AA>A.>"), true);
    checker.check(&to_wide(b"<a[AA>AA.>"), false);
    let mut checker = build_checker(r"<.+\BA\B.+>", "wide");
    checker.check(&to_wide(b""), false);
    checker.check(&to_wide(b"<>"), false);
    checker.check(&to_wide(b"<A>"), false);
    checker.check(&to_wide(b"<[A]>"), false);
    checker.check(&to_wide(b"<[aAa]>"), true);
    checker.check(&to_wide(b"<a[A]a>"), false);
    checker.check(&to_wide(b"<a[Aa>"), false);
    // Lets check more complex cases
    checker.check(&to_wide(b"<aAAAAa>"), true);
    checker.check(&to_wide(b"<a[AA]>"), false);
    checker.check(&to_wide(b"<a[AAA.A!AA]>"), true);
    checker.check(&to_wide(b"<a[A.AAA]>"), true);
    checker.check(&to_wide(b"<a[AA.AAA]>"), true);
    checker.check(&to_wide(b"<a[AA>A.>"), false);
    checker.check(&to_wide(b"<a[AA>AA.>"), false);

    // Test word boundaries do not use unicode syntax
    let mut checker = build_checker(r"<\w+\b.a>", "wide");
    checker.check(&to_wide(b"<ave|a>"), true);
    checker.check(&to_wide(b"<aveva>"), false);
    checker.check(&to_wide("<avéva>".as_bytes()), false);
    checker.check(&to_wide("<avé|a>".as_bytes()), false);

    // Test word boundaries inside a repetition, regression test
    let mut checker = build_checker(r"<(c\b.a){2}>", "wide");
    checker.check(&to_wide(b"<c|ac.a>"), true);
    checker.check(&to_wide(b"<cbac.a>"), false);
    checker.check(&to_wide(b"<c|acba>"), false);
    checker.check(&to_wide(b"<cbacba>"), false);
}

#[test]
fn test_variable_regex_word_boundaries_edge_cases() {
    let build_checker = |regex: &str, modifiers: &str| {
        Checker::new(&format!(
            r#"
rule a {{
    strings:
        $a = /{regex}/ {modifiers}
        $z = "z"
    condition:
        (#z == 0 and #a == 0) or (!a == #z)
}}"#,
        ))
    };

    // The difference between a regex with a boundary, and one without it with post match checking,
    // is that the boundary does not factor in the resolution of repetitions.

    // This works, because we recheck after the initial match, and the repetition is greedy, hence
    // the post match will only reduce the match.
    let mut checker = build_checker(r"a.{0,4}\b", "");
    checker.check(b"z a", true);
    checker.check(b"zz a1", true);
    checker.check(b"zzz a12", true);
    checker.check(b"zzzzz a1234", true);
    checker.check(b"a12345", true);
    checker.check(b"zzzzz a1234>", true);
    checker.check(b"zzzz a12>34", true);
    checker.check(b"zzzz a>>>34", true);
    let mut checker = build_checker(r"a.{0,4}\b", "wide");
    checker.check(&to_wide(b"zz a"), true);
    checker.check(&to_wide(b"zzzz a1"), true);
    checker.check(&to_wide(b"zzzzzz a12"), true);
    checker.check(&to_wide(b"zzzzzzzzzz a1234"), true);
    checker.check(&to_wide(b"a12345"), true);
    checker.check(&to_wide(b"zzzzzzzzzz a1234>"), true);
    checker.check(&to_wide(b"zzzzzzzz a12>34"), true);
    checker.check(&to_wide(b"zzzzzzzz a>>>34"), true);

    // This works, because we include mmore than the initial match, so the post check can improve
    // the non greedy repetition until it finds a boundary.
    let mut checker = build_checker(r"a.{0,4}?\b", "");
    checker.check(b"z a", true);
    checker.check(b"zz a1", true);
    checker.check(b"zzz a12", true);
    checker.check(b"zzzzz a1234", true);
    checker.check(b"a12345", true);
    checker.check(b"zzzzz a1234>", true);
    checker.check(b"zzz a12>34", true);
    checker.check(b"z a>>>34", true);
    let mut checker = build_checker(r"a.{0,4}?\b", "wide");
    checker.check(&to_wide(b"zz a"), true);
    checker.check(&to_wide(b"zzzz a1"), true);
    checker.check(&to_wide(b"zzzzzz a12"), true);
    checker.check(&to_wide(b"zzzzzzzzzz a1234"), true);
    checker.check(&to_wide(b"a12345"), true);
    checker.check(&to_wide(b"zzzzzzzzzz a1234>"), true);
    checker.check(&to_wide(b"zzzzzz a12>34"), true);
    checker.check(&to_wide(b"zz a>>>34"), true);
}

#[test]
fn test_variable_boundary_ac_confirm() {
    // Make sure the boundary is taken into account when confirming an ac match.
    let mut checker = Checker::new(
        r"
rule a {
    strings:
        $a = /\Wabcd\W/
    condition:
        $a
}",
    );

    checker.check(b"aabcde", false);
    checker.check(b"<abcde", false);
    checker.check(b"aabcd>", false);
    checker.check(b"<abcd>", true);
}

#[test]
fn test_variable_string_wide_ascii() {
    // \x76 is 'v'
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "c\to\x76" nocase
        $b = "foo" fullword
        $c = "bar" fullword nocase
    condition:
        any of them
}"#,
    );

    // Nocase
    checker.check(b"c\tov", true);
    checker.check(b"C\tOV", true);
    checker.check(b"C\tOx", false);
    checker.check(b"C\tov", true);

    // Fullword
    checker.check(b"foo", true);
    checker.check(b" foo ", true);
    checker.check(b"-foo_", true);
    checker.check(b"-fooa", false);
    checker.check(b"-fooA", false);
    checker.check(b"-foo0", false);
    checker.check(b"afoo:", false);
    checker.check(b"Zfoo:", false);
    checker.check(b"0foo:", false);

    checker.check(b"bar", true);
    checker.check(b" BAR ", true);
    checker.check(b"-baR_", true);
    checker.check(b"-baRa", false);
    checker.check(b"-barA", false);
    checker.check(b"-bAr0", false);
    checker.check(b"aBAr:", false);
    checker.check(b"Zbar:", false);
    checker.check(b"0bAR:", false);

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "margit" wide
        $b = "morgott" ascii wide
        $c = "mohg" ascii
        $d = "maliketh" wide fullword
        $e = "malenia" wide ascii fullword
    condition:
        any of them
}"#,
    );

    // Wide
    checker.check(b"amargita", false);
    checker.check(b"a\0m\0a\0r\0g\0i\0t\0a\0", true);
    checker.check(b"\0m\0a\0r\0g\0i\0t\0a\0", true);
    checker.check(b"m\0a\0r\0g\0i\0t\0a\0", true);
    checker.check(b"m\0a\0r\0g\0i\0ta\0", false);

    // Wide + ascii
    checker.check(b"morgott", true);
    checker.check(b"amorgotta", true);
    checker.check(b"a\0m\0o\0r\0g\0o\0t\0t\0a\0", true);
    checker.check(b"\0m\0o\0r\0g\0o\0t\0t\0a\0", true);
    checker.check(b"m\0o\0r\0g\0o\0t\0t\0a\0", true);
    checker.check(b"m\0o\0r\0g\0o\0t\0ta\0", false);

    // Ascii
    checker.check(b"amohgus", true);
    checker.check(b"a\0m\0o\0g\0h\0u\0s\0", false);

    // Wide fullword
    checker.check(b"<<<maliketh>>>", false);
    checker.check(b"<\0<\0<\0m\0a\0l\0i\0k\0e\0t\0h\0>\0>\0>\0", true);
    checker.check(b"<\0<\0a\0m\0a\0l\0i\0k\0e\0t\0h\0>\0>\0>\0", false);
    checker.check(b"a\0m\0a\0l\0i\0k\0e\0t\0h\0b\0", false);
    checker.check(b"a\0m\0a\0l\0i\0k\0e\0t\0h\0>\0", false);
    checker.check(b"<\0m\0a\0l\0i\0k\0e\0t\0h\0b\0", false);
    checker.check(b"<\0m\0a\0l\0i\0k\0e\0t\0h\0>\0", true);
    checker.check(b"\0m\0a\0l\0i\0k\0e\0t\0h\0>\0", true);
    checker.check(b"<\0m\0a\0l\0i\0k\0e\0t\0h\0>", true);
    checker.check(b"<\0m\0a\0l\0i\0k\0e\0t\0h\0", true);
    checker.check(b"\0m\0a\0l\0i\0k\0e\0t\0h\0", true);
    checker.check(b"m\0a\0l\0i\0k\0e\0t\0h\0", true);
    checker.check(b"<\0maliketh\0>\0", false);

    // Wide ascii fullword
    checker.check(b"<malenia>", true);
    checker.check(b"<\0m\0a\0l\0e\0n\0i\0a\0>\0", true);
    checker.check(b"amalenia>", false);
    checker.check(b"<maleniab", false);
    checker.check(b"malenia", true);
    checker.check(b"a\0m\0a\0l\0e\0n\0i\0a\0>\0", false);
    checker.check(b"<\0m\0a\0l\0e\0n\0i\0a\0b\0", false);
    checker.check(b"am\0a\0l\0e\0n\0i\0a\0b\0", false);
    checker.check(b"m\0a\0l\0e\0n\0i\0a\0b\0", false);

    // For those, we need to know if the match is wide or ascii to do the proper fullword check.
    checker.check(b"am\0a\0l\0e\0n\0i\0a\0b", true);
    checker.check(b"a\0malenia<\0", true);
}

#[test]
fn test_variable_string_xor() {
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
    let mut checker = Checker::new(rule);

    let mut check_xor = |mem: &[u8], xor_byte: u8, expected_res: bool| {
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
        check_xor(rennala, x, (20..=30).contains(&x));
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
fn test_variable_string_xor_fullword() {
    // Test fullword with xor
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "rykard" xor fullword
        $c = "radagon" wide xor(0-10) fullword
        $d = "radahn" wide ascii xor fullword
    condition:
        any of them
}"#,
    );

    let mut check_xor =
        |mem: &[u8], prefix: &[u8], suffix: &[u8], xor_byte: u8, expected_res: bool| {
            let mut out = Vec::new();
            out.extend(prefix);
            out.extend(mem.iter().map(|c| c ^ xor_byte));
            out.extend(suffix);
            checker.check(&out, expected_res);
        };

    // ascii xor fullword
    let mem = b"rykard";
    for x in [0, 15, 100] {
        check_xor(mem, b"", b"", x, true);
        check_xor(mem, b"a", b"", x, false);
        check_xor(mem, b"", b"a", x, false);
        check_xor(mem, b"a", b"a", x, false);
        check_xor(mem, b"<", b">", x, true);
    }

    // wide xor fullword
    let mem = b"r\0a\0d\0a\0g\0o\0n\0";
    for x in [0, 3, 8] {
        check_xor(mem, b"", b"", x, true);
        check_xor(mem, b"a", b"", x, true);
        check_xor(mem, b"", b"a", x, true);
        check_xor(mem, b"a", b"a", x, true);
        check_xor(mem, b"<", b">", x, true);

        check_xor(mem, b"<\0", b">\0", x, true);
        check_xor(mem, b"<\0", b"b\0", x, false);
        check_xor(mem, b"a\0", b">\0", x, false);
        check_xor(mem, b"<\0a\0", b"b\0>\0", x, false);
        check_xor(mem, b"a\0<\0", b">\0a\0", x, true);
    }

    // wide ascii xor fullword
    let mem_ascii = b"radahn";
    let mem_wide = b"r\0a\0d\0a\0h\0n\0";
    for x in [0, 84, 123, 230] {
        check_xor(mem_ascii, b"", b"", x, true);
        check_xor(mem_ascii, b"a", b"", x, false);
        check_xor(mem_ascii, b"", b"a", x, false);
        check_xor(mem_ascii, b"a", b"a", x, false);
        check_xor(mem_ascii, b"<", b">", x, true);

        check_xor(mem_ascii, b"<\0", b">\0", x, true);
        check_xor(mem_ascii, b"<\0", b"b\0", x, false);
        check_xor(mem_ascii, b"a\0", b">\0", x, true);
        check_xor(mem_ascii, b"<\0a\0", b"b\0>\0", x, false);
        check_xor(mem_ascii, b"a\0<\0", b">\0a\0", x, true);

        check_xor(mem_wide, b"", b"", x, true);
        check_xor(mem_wide, b"a", b"", x, true);
        check_xor(mem_wide, b"", b"a", x, true);
        check_xor(mem_wide, b"a", b"a", x, true);
        check_xor(mem_wide, b"<", b">", x, true);

        check_xor(mem_wide, b"<\0", b">\0", x, true);
        check_xor(mem_wide, b"<\0", b"b\0", x, false);
        check_xor(mem_wide, b"a\0", b">\0", x, false);
        check_xor(mem_wide, b"<\0a\0", b"b\0>\0", x, false);
        check_xor(mem_wide, b"a\0<\0", b">\0a\0", x, true);
    }
}

fn base64_encode<T: AsRef<[u8]>>(s: T) -> Vec<u8> {
    use base64::engine::Engine;

    base64::engine::general_purpose::STANDARD
        .encode(s)
        .into_bytes()
}

#[test]
fn test_variable_base64_small() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "a" base64
    condition:
        $a
}"#,
    );

    // From yara doc:
    // For example, "a" with the base64 keyword matches "`", "b", "c", "!", "\xA1", or "\xE1"
    // after base64 encoding, and will not match where the base64 encoding matches the
    // [GWm2][EFGH] regular expression.
    checker.check(b"", false);
    checker.check(&base64_encode("`"), true);
    checker.check(&base64_encode("b"), true);
    checker.check(&base64_encode("c"), true);

    // TODO: this is not matching, contrary to yara doc. report this
    checker.check(&base64_encode("!"), false);
    checker.check(&base64_encode(b"\xA1"), false);
    checker.check(&base64_encode(b"\xE1"), false);

    checker.check(&base64_encode(b"\xA0"), false);
    checker.check(&base64_encode(b"ha"), false);
}

#[test]
fn test_variable_base64() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a0 = "Hello world" base64
        $a1 = "mangue" wide base64
        $a2 = "fraise" ascii wide base64
    condition:
        any of them
}"#,
    );

    // "Hello world" base64
    checker.check(b"aaaSGVsbG8gd29ybGbbb", true);
    checker.check(b"aaahlbGxvIHdvcmxkbbb", true);
    checker.check(b"aaaIZWxsbyB3b3JsZbbb", true);
    checker.check(b"SGVsbG8gd29yb", false);
    checker.check(b"hlbGxvIHdvcmx", false);
    checker.check(b"IZWxsbyB3b3Js", false);
    checker.check(b"GVsbG8gd29ybG", false);
    checker.check(b"lbGxvIHdvcmxk", false);
    checker.check(b"ZWxsbyB3b3JsZ", false);
    checker.check(b"aaaSGVsbG9gd29ybGbbb", false);
    checker.check(b"aaahlbGxvVHdvcmxkbbb", false);
    checker.check(b"aaaIZWxsbyB4b3JsZbbb", false);
    checker.check(b"aaahlbGxvIHdvcmxkbbb", true);
    checker.check(b"a\0h\0l\0b\0G\0x\0v\0I\0H\0d\0v\0c\0m\0x\0k\0b\0", false);

    // "mangue" wide, then base64

    checker.check(b"mangue", false);
    // not matching on ascii base64
    checker.check(&base64_encode("mangue"), false);
    checker.check(&base64_encode(" mangue"), false);
    checker.check(&base64_encode("  mangue"), false);
    // not matching on ascii base64wide
    checker.check(b"b\0W\0F\0u\0Z\x003\0V\0l\0", false);
    checker.check(b"1\0h\0b\0m\0d\x001\0Z\0", false);
    checker.check(b"t\0Y\0W\x005\0n\0d\0W\0", false);
    // matching on wide, then base64
    checker.check(&base64_encode("m\0a\0n\0g\0u\0e\0"), true);
    checker.check(&base64_encode(" m\0a\0n\0g\0u\0e\0"), true);
    checker.check(&base64_encode("  m\0a\0n\0g\0u\0e\0"), true);

    // "fraise" ascii and wide, then base64

    checker.check(b"fraise", false);
    // matching on ascii, then base64
    checker.check(&base64_encode("fraise"), true);
    checker.check(&base64_encode(" fraise"), true);
    checker.check(&base64_encode("  fraise"), true);
    // not matching on ascii base64wide
    checker.check(b"Z\0n\0J\0h\0a\0X\0N\0l\0", false);
    checker.check(b"Z\0y\0Y\0W\0l\0z\0Z\0", false);
    checker.check(b"m\0c\0m\0F\0p\0c\x002\0", false);
    // matching on wide, then base64
    checker.check(&base64_encode("f\0r\0a\0i\0s\0e\0"), true);
    checker.check(&base64_encode(" f\0r\0a\0i\0s\0e\0"), true);
    checker.check(&base64_encode("  f\0r\0a\0i\0s\0e\0"), true);
}

#[test]
fn test_variable_base64wide() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a0 = "framboise" base64wide
        $a1 = "mures" wide base64wide
        $a2 = "myrtille" wide ascii base64wide
    condition:
        any of them
}"#,
    );

    // "framboise" base64wide

    checker.check(b"framboise", false);
    // not matching on ascii, then base64
    checker.check(&base64_encode("framboise"), false);
    checker.check(&base64_encode(" framboise"), false);
    checker.check(&base64_encode("  framboise"), false);
    // matching on ascii base64wide
    checker.check(b"Z\0n\0J\0h\0b\0W\0J\0v\0a\0X\0N\0l\0", true);
    checker.check(b"Z\0y\0Y\0W\x001\0i\0b\x002\0l\0z\0Z\0", true);
    checker.check(b"m\0c\0m\0F\0t\0Y\0m\09\0p\0c\x002\0", true);
    // not matching on wide, then base64
    checker.check(&base64_encode("f\0r\0a\0m\0b\0o\0i\0s\0e\0"), false);
    checker.check(&base64_encode(" f\0r\0a\0m\0b\0o\0i\0s\0e\0"), false);
    checker.check(&base64_encode("  f\0r\0a\0m\0b\0o\0i\0s\0e\0"), false);

    // "mures" wide base64wide

    checker.check(b"mures", false);
    // not matching on ascii, then base64
    checker.check(&base64_encode("mures"), false);
    checker.check(&base64_encode(" mures"), false);
    checker.check(&base64_encode("  mures"), false);
    // not matching on ascii base64wide
    checker.check(&base64_encode("b\0X\0V\0y\0Z\0X\0"), false);
    checker.check(&base64_encode("1\x01\0c\0m\0V\0z\0"), false);
    checker.check(&base64_encode("t\0d\0X\0J\0l\0c\0"), false);

    // not matching on "mures" wide, then base64
    checker.check(&base64_encode("m\0u\0r\0e\0s\0"), false);
    checker.check(&base64_encode(" m\0u\0r\0e\0s\0"), false);
    checker.check(&base64_encode("  m\0u\0r\0e\0s\0"), false);

    // Matches on "mures" wide, then base64wide
    checker.check(b"b\0Q\0B\x001\0A\0H\0I\0A\0Z\0Q\0B\0z\0A\0", true);
    checker.check(b"0\0A\0d\0Q\0B\0y\0A\0G\0U\0A\0c\0w\0", true);
    checker.check(b"t\0A\0H\0U\0A\0c\0g\0B\0l\0A\0H\0M\0A\0", true);

    // "myrtille" wide base64wide

    checker.check(b"myrtille", false);
    // not matching on ascii, then base64
    checker.check(&base64_encode("myrtille"), false);
    checker.check(&base64_encode(" myrtille"), false);
    checker.check(&base64_encode("  myrtille"), false);
    // matching on ascii base64wide
    checker.check(b"b\0X\0l\0y\0d\0G\0l\0s\0b\0G\0", true);
    checker.check(b"1\x005\0c\0n\0R\0p\0b\0G\0x\0l\0", true);
    checker.check(b"t\0e\0X\0J\x000\0a\0W\0x\0s\0Z\0", true);

    // not matching on wide, then base64
    checker.check(&base64_encode("m\0y\0r\0t\0i\0l\0l\0e\0"), false);
    checker.check(&base64_encode(" m\0y\0r\0t\0i\0l\0l\0e\0"), false);
    checker.check(&base64_encode("  m\0y\0r\0t\0i\0l\0l\0e\0"), false);

    // Matches on "myrtille" wide, then base64wide
    checker.check(
        b"b\0Q\0B\x005\0A\0H\0I\0A\0d\0A\0B\0p\0A\0G\0w\0A\0b\0A\0B\0l\0A\0",
        true,
    );
    checker.check(
        b"0\0A\0e\0Q\0B\0y\0A\0H\0Q\0A\0a\0Q\0B\0s\0A\0G\0w\0A\0Z\0Q\0",
        true,
    );
    checker.check(
        b"t\0A\0H\0k\0A\0c\0g\0B\x000\0A\0G\0k\0A\0b\0A\0B\0s\0A\0G\0U\0A\0",
        true,
    );
}

#[test]
fn test_variable_base64_base64wide() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a0 = "boreal forest" ascii base64 base64wide
        $a1 = "noix de coco" wide base64 base64wide
        $a2 = "comcombre" ascii wide base64 base64wide
    condition:
        any of them
}"#,
    );

    // "boreal forest", ascii, base64 and base64wide

    checker.check(b"boreal forest", false);
    // matching on ascii base64
    checker.check(&base64_encode("boreal forest"), true);
    checker.check(&base64_encode(" boreal forest"), true);
    checker.check(&base64_encode("  boreal forest"), true);
    // matching on ascii base64wide
    checker.check(b"Y\0m\09\0y\0Z\0W\0F\0s\0I\0G\0Z\0v\0c\0m\0V\0z\0d\0", true);
    checker.check(
        b"J\0v\0c\0m\0V\0h\0b\0C\0B\0m\0b\x003\0J\0l\0c\x003\0",
        true,
    );
    checker.check(
        b"i\0b\x003\0J\0l\0Y\0W\0w\0g\0Z\0m\09\0y\0Z\0X\0N\x000\0",
        true,
    );
    // not matching on wide, then base64
    checker.check(
        &base64_encode("b\0o\0r\0e\0a\0l\0 \0f\0o\0r\0e\0s\0t\0"),
        false,
    );
    checker.check(
        &base64_encode(" b\0o\0r\0e\0a\0l\0 \0f\0o\0r\0e\0s\0t\0"),
        false,
    );
    checker.check(
        &base64_encode("  b\0o\0r\0e\0a\0l\0 \0f\0o\0r\0e\0s\0t\0"),
        false,
    );
    // not matching on wide, then base64wide
    checker.check(
        b"Y\0g\0B\0v\0A\0H\0I\0A\0Z\0Q\0B\0h\0A\0G\0w\0A\0I\0A\0B\0m\0A\0G\08\0A\0c\0g\0B\0l\0A\0H\0M\0A\0d\0A\0",
        false
    );
    checker.check(
        b"I\0A\0b\0w\0B\0y\0A\0G\0U\0A\0Y\0Q\0B\0s\0A\0C\0A\0A\0Z\0g\0B\0v\0A\0H\0I\0A\0Z\0Q\0B\0z\0A\0H\0Q\0A\0",
        false,
    );
    checker.check(
        b"i\0A\0G\08\0A\0c\0g\0B\0l\0A\0G\0E\0A\0b\0A\0A\0g\0A\0G\0Y\0A\0b\0w\0B\0y\0A\0G\0U\0A\0c\0w\0B\x000\0A\0",
        false,
    );

    // "noix de coco", wide, base64 and base64wide

    checker.check(b"noix de coco", false);
    // not matching on ascii base64
    checker.check(&base64_encode("noix de coco"), false);
    checker.check(&base64_encode(" noix de coco"), false);
    checker.check(&base64_encode("  noix de coco"), false);
    // not matching on ascii base64wide
    checker.check(b"b\0m\09\0p\0e\0C\0B\0k\0Z\0S\0B\0j\0b\x002\0N\0v\0", false);
    checker.check(b"5\0v\0a\0X\0g\0g\0Z\0G\0U\0g\0Y\x002\09\0j\0b\0", false);
    checker.check(
        b"u\0b\x002\0l\x004\0I\0G\0R\0l\0I\0G\0N\0v\0Y\x002\0",
        false,
    );
    // matching on wide, then base64
    checker.check(&base64_encode("n\0o\0i\0x\0 \0d\0e\0 \0c\0o\0c\0o\0"), true);
    checker.check(
        &base64_encode(" n\0o\0i\0x\0 \0d\0e\0 \0c\0o\0c\0o\0"),
        true,
    );
    checker.check(
        &base64_encode("  n\0o\0i\0x\0 \0d\0e\0 \0c\0o\0c\0o\0"),
        true,
    );
    // matching on wide, then base64wide
    checker.check(
        b"b\0g\0B\0v\0A\0G\0k\0A\0e\0A\0A\0g\0A\0G\0Q\0A\0Z\0Q\0A\0g\0A\0G\0M\0A\0b\0w\0B\0j\0A\0G\08\0A\0",
        true
    );
    checker.check(
        b"4\0A\0b\0w\0B\0p\0A\0H\0g\0A\0I\0A\0B\0k\0A\0G\0U\0A\0I\0A\0B\0j\0A\0G\08\0A\0Y\0w\0B\0v\0A\0",
        true,
    );
    checker.check(
        b"u\0A\0G\08\0A\0a\0Q\0B\x004\0A\0C\0A\0A\0Z\0A\0B\0l\0A\0C\0A\0A\0Y\0w\0B\0v\0A\0G\0M\0A\0b\0w\0",
        true,
    );

    // "comcombre", ascii and wide, base64 and base64wide

    checker.check(b"comcombre", false);
    // not matching on ascii base64
    checker.check(&base64_encode("comcombre"), true);
    checker.check(&base64_encode(" comcombre"), true);
    checker.check(&base64_encode("  comcombre"), true);
    // matching on ascii base64wide
    checker.check(b"Y\x002\09\0t\0Y\x002\09\0t\0Y\0n\0J\0l\0", true);
    checker.check(b"N\0v\0b\0W\0N\0v\0b\0W\0J\0y\0Z\0", true);
    checker.check(b"j\0b\x002\x001\0j\0b\x002\x001\0i\0c\0m\0", true);
    // matching on wide, then base64
    checker.check(&base64_encode("c\0o\0m\0c\0o\0m\0b\0r\0e\0"), true);
    checker.check(&base64_encode(" c\0o\0m\0c\0o\0m\0b\0r\0e\0"), true);
    checker.check(&base64_encode("  c\0o\0m\0c\0o\0m\0b\0r\0e\0"), true);
    // matching on wide, then base64wide
    checker.check(
        b"Y\0w\0B\0v\0A\0G\x000\0A\0Y\0w\0B\0v\0A\0G\x000\0A\0Y\0g\0B\0y\0A\0G\0U\0A\0",
        true,
    );
    checker.check(
        b"M\0A\0b\0w\0B\0t\0A\0G\0M\0A\0b\0w\0B\0t\0A\0G\0I\0A\0c\0g\0B\0l\0A\0",
        true,
    );
    checker.check(
        b"j\0A\0G\08\0A\0b\0Q\0B\0j\0A\0G\08\0A\0b\0Q\0B\0i\0A\0H\0I\0A\0Z\0Q\0",
        true,
    );
}

#[test]
fn test_variable_find() {
    let mut checker = Checker::new(
        r#"
        rule a {
            strings:
                $a = "45"
            condition:
                $a
        }"#,
    );
    checker.check(b"12345678", true);
    checker.check(b"45678", true);
    checker.check(b"45", true);
    checker.check(b"345", true);
    checker.check(b"1234678", false);
    checker.check(b"465", false);

    let mut checker = Checker::new(
        r#"
        rule a {
            strings:
                $a = /4.5+/
            condition:
                $a
        }"#,
    );
    checker.check(b"445", true);
    checker.check(b"34\x3D555", true);
    checker.check(b"123", false);
    checker.check(b"44", false);
    checker.check(b"4\n5", false);

    let mut checker = Checker::new(
        r#"
        rule a {
            strings:
                $a = /fo{2,}/i
            condition:
                $a
        }"#,
    );
    checker.check(b"foo", true);
    checker.check(b"FoOoOoO", true);
    checker.check(b"barFOOObaz", true);
    checker.check(b"fo", false);
    checker.check(b"FO", false);

    let mut checker = Checker::new(
        r#"
        rule a {
            strings:
                $a = /a.*b/s
            condition:
                $a
        }"#,
    );
    checker.check(b"ab", true);
    checker.check(b"ba\n\n  ba", true);
    checker.check(b"AB", false);
    checker.check(b"ec", false);
}

#[test]
fn test_variable_find_at() {
    #[track_caller]
    fn check_at(mem: &[u8], at: u64, res: bool) {
        let rule = format!(
            r#"
    rule a {{
        strings:
            $a = "34"
            $b = /[a-z]{{2}}/
            $c = /=%=$/
        condition:
            for any of them: ($ at {at})
    }}"#
        );
        check(&rule, mem, res);
    }

    check_at(b"01234567", 3, true);
    check_at(b"342342", 3, true);
    check_at(b"34", 0, true);
    check_at(b"234", 2, false);
    check_at(b"234", 0, false);
    check_at(b"01234", 15, false);

    check_at(b"abc", 0, true);
    check_at(b"abc", 1, true);
    check_at(b"abc", 2, false);
    check_at(b" abc", 0, false);
    check_at(b" abc", 1, true);
    check_at(b" abc", 2, true);

    check_at(b"=%=", 0, true);
    check_at(b"=%=", 1, false);
    check_at(b"=%=", 2, false);
    check_at(b" =%=", 0, false);
    check_at(b" =%=", 1, true);
}

#[test]
fn test_variable_find_in() {
    #[track_caller]
    fn check_in(mem: &[u8], from: u64, to: u64, res: bool) {
        let rule = format!(
            r#"
    rule a {{
        strings:
            $a = "345"
            // Force a raw matcher
            $b = /abc$/
        condition:
            $a in ({from}..{to}) or $b in ({from}..{to})
    }}"#
        );
        check(&rule, mem, res);
    }

    check_in(b"01234567", 0, 20, true);
    check_in(b"01234567", 2, 6, true);
    check_in(b"01234567", 3, 5, true);
    check_in(b"01234567", 3, 4, true);
    check_in(b"01234567", 3, 3, true);
    check_in(b"01234567", 2, 3, true);
    check_in(b"01234567", 1, 2, false);
    check_in(b"34353435", 1, 6, false);
    check_in(b"34501234567", 3, 23, true);
    check_in(b"34501234567", 5, 9, true);
    check_in(b"34501234567", 6, 8, true);
    check_in(b"34501234567", 6, 7, true);
    check_in(b"34501234567", 6, 6, true);
    check_in(b"34501234567", 5, 6, true);
    check_in(b"34501234567", 4, 5, false);

    check_in(b"abc", 0, 4, true);
    check_in(b"0123abc", 0, 4, true);
    check_in(b"0123abc", 0, 2, false);
    check_in(b"0123abc", 5, 8, false);
}

#[test]
fn test_variable_find_at_invalid() {
    // Negative index gives a defined result, but false
    check(&build_rule("defined ($a0 at (#a0-10))"), b"", true);
    check(&build_rule("$a0 at (#a0-10)"), b"", false);

    // Undefined value
    check(
        &build_rule("defined ($a0 at tests.integer_array[5])"),
        b"",
        false,
    );
    check(&build_rule("$a0 at tests.integer_array[5]"), b"", false);
}

#[test]
fn test_variable_find_in_invalid() {
    // Negative values give result false
    check(&build_rule("defined ($a0 in (0..(#a0-1)))"), b"", true);
    check(&build_rule("defined ($a0 in ((#a0-1)..0))"), b"", true);
    check(&build_rule("$a0 in (0..(#a0-1))"), b"", false);
    check(&build_rule("$a0 in ((#a0-1)..0)"), b"", false);

    // Undefined value is propagated
    check(
        &build_rule("defined ($a0 in (0..tests.integer_array[5]))"),
        b"",
        false,
    );
    check(
        &build_rule("defined ($a0 in ((tests.integer_array[5])..3))"),
        b"",
        false,
    );
}

#[test]
fn test_variable_hex_string_masks() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { ?C }
        $b = { C? }
    condition:
        any of them
}
"#,
    );

    checker.check_full_matches(
        &(0_u8..=255_u8).collect::<Vec<_>>(),
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"\x0c", 12, 1),
                        (b"\x1c", 28, 1),
                        (b"\x2c", 44, 1),
                        (b"\x3c", 60, 1),
                        (b"\x4c", 76, 1),
                        (b"\x5c", 92, 1),
                        (b"\x6c", 108, 1),
                        (b"\x7c", 124, 1),
                        (b"\x8c", 140, 1),
                        (b"\x9c", 156, 1),
                        (b"\xac", 172, 1),
                        (b"\xbc", 188, 1),
                        (b"\xcc", 204, 1),
                        (b"\xdc", 220, 1),
                        (b"\xec", 236, 1),
                        (b"\xfc", 252, 1),
                    ],
                ),
                (
                    "b",
                    vec![
                        (b"\xc0", 192, 1),
                        (b"\xc1", 193, 1),
                        (b"\xc2", 194, 1),
                        (b"\xc3", 195, 1),
                        (b"\xc4", 196, 1),
                        (b"\xc5", 197, 1),
                        (b"\xc6", 198, 1),
                        (b"\xc7", 199, 1),
                        (b"\xc8", 200, 1),
                        (b"\xc9", 201, 1),
                        (b"\xca", 202, 1),
                        (b"\xcb", 203, 1),
                        (b"\xcc", 204, 1),
                        (b"\xcd", 205, 1),
                        (b"\xce", 206, 1),
                        (b"\xcf", 207, 1),
                    ],
                ),
            ],
        )],
    );

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { AB ?C DE }
        $b = { AB C? DE }
        $c = { AB ?? }
        $d = { ?? DE }
    condition:
        any of them
}
"#,
    );

    checker.check_full_matches(b"", vec![]);
    checker.check_full_matches(
        b"\xab\xde \xab\xcc\xde \xab \xde \xde \xde\xde \xab\xab\xcf\xde\xde\xde\xab",
        vec![(
            "default:a".to_owned(),
            vec![
                ("a", vec![(b"\xab\xcc\xde", 3, 3)]),
                ("b", vec![(b"\xab\xcc\xde", 3, 3), (b"\xab\xcf\xde", 17, 3)]),
                (
                    "c",
                    vec![
                        (b"\xab\xde", 0, 2),
                        (b"\xab\xcc", 3, 2),
                        (b"\xab ", 7, 2),
                        (b"\xab\xab", 16, 2),
                        (b"\xab\xcf", 17, 2),
                    ],
                ),
                (
                    "d",
                    vec![
                        (b"\xab\xde", 0, 2),
                        (b"\xcc\xde", 4, 2),
                        (b" \xde", 8, 2),
                        (b" \xde", 10, 2),
                        (b" \xde", 12, 2),
                        (b"\xde\xde", 13, 2),
                        (b"\xcf\xde", 18, 2),
                        (b"\xde\xde", 19, 2),
                        (b"\xde\xde", 20, 2),
                    ],
                ),
            ],
        )],
    );
}

#[test]
fn test_variable_hex_string_jumps() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        // 61 is 'a', 62 is 'b'
        $a = { 61 [1-2] 62 }
        $b = { 61 [1-] 62 }
        $c = { 61 [0-1] 62 }
    condition:
        any of them
}
"#,
    );

    checker.check_full_matches(
        b"b ab aab abbb aaaab aaaaabb ababaabb abbaaabab",
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"aab", 5, 3),
                        (b"abb", 9, 3),
                        (b"aaab", 15, 4),
                        (b"aab", 16, 3),
                        (b"aaab", 22, 4),
                        (b"aab", 23, 3),
                        (b"abb", 24, 3),
                        (b"abab", 28, 4),
                        (b"aab", 32, 3),
                        (b"abb", 33, 3),
                        (b"abb", 37, 3),
                        (b"aaab", 40, 4),
                        (b"aab", 41, 3),
                        (b"abab", 42, 4),
                    ],
                ),
                (
                    "b",
                    vec![
                        (b"ab aab", 2, 6),
                        (b"aab", 5, 3),
                        (b"ab ab", 6, 5),
                        (b"abb", 9, 3),
                        (b"aaaab", 14, 5),
                        (b"aaab", 15, 4),
                        (b"aab", 16, 3),
                        (b"ab aaaaab", 17, 9),
                        (b"aaaaab", 20, 6),
                        (b"aaaab", 21, 5),
                        (b"aaab", 22, 4),
                        (b"aab", 23, 3),
                        (b"abb", 24, 3),
                        (b"abab", 28, 4),
                        (b"abaab", 30, 5),
                        (b"aab", 32, 3),
                        (b"abb", 33, 3),
                        (b"abb", 37, 3),
                        (b"aaab", 40, 4),
                        (b"aab", 41, 3),
                        (b"abab", 42, 4),
                    ],
                ),
                (
                    "c",
                    vec![
                        (b"ab", 2, 2),
                        (b"aab", 5, 3),
                        (b"ab", 6, 2),
                        (b"ab", 9, 2),
                        (b"aab", 16, 3),
                        (b"ab", 17, 2),
                        (b"aab", 23, 3),
                        (b"ab", 24, 2),
                        (b"ab", 28, 2),
                        (b"ab", 30, 2),
                        (b"aab", 32, 3),
                        (b"ab", 33, 2),
                        (b"ab", 37, 2),
                        (b"aab", 41, 3),
                        (b"ab", 42, 2),
                        (b"ab", 44, 2),
                    ],
                ),
            ],
        )],
    );
}

#[test]
fn test_variable_hex_string_alternations() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        // 61 is 'a', 67 is 'g'
        $a = { 61 (62 | 63 | 64 65 | 66 ) 67 }
        $b = { 61 (62 | ( 63 | 64 ) 65 ) }
        $c = { ( ( 61 | 62 ) | 63 64 ) }
    condition:
        any of them
}
"#,
    );

    checker.check_full_matches(
        b"ag abcdefg abg cde ace df acg adeg adfg afg egadadce",
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"abg", 11, 3),
                        (b"acg", 26, 3),
                        (b"adeg", 30, 4),
                        (b"afg", 40, 3),
                    ],
                ),
                (
                    "b",
                    vec![
                        (b"ab", 3, 2),
                        (b"ab", 11, 2),
                        (b"ace", 19, 3),
                        (b"ade", 30, 3),
                    ],
                ),
                (
                    "c",
                    vec![
                        (b"a", 0, 1),
                        (b"a", 3, 1),
                        (b"b", 4, 1),
                        (b"cd", 5, 2),
                        (b"a", 11, 1),
                        (b"b", 12, 1),
                        (b"cd", 15, 2),
                        (b"a", 19, 1),
                        (b"a", 26, 1),
                        (b"a", 30, 1),
                        (b"a", 35, 1),
                        (b"a", 40, 1),
                        (b"a", 46, 1),
                        (b"a", 48, 1),
                    ],
                ),
            ],
        )],
    );
}

#[test]
fn test_variable_hex_string_atoms() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        // whole atom on the left side
        $a = { 64 65 66 67 (?? | 68) ?9 }
        // whole atom on the right side
        $b = { 6? (62 | 63 ??) 64 65 66 67 }
        // whole atom in the middle
        $c = { (?2 | 61) 64 65 66 67 ?? 69 }
    condition:
        any of them
}
"#,
    );
    checker.check_full_matches(
        b"abcdefghi defgri defghh abdefg acadefg adefggi bdefg.i",
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"defghi", 3, 6),
                        (b"defgri", 10, 6),
                        (b"defggi", 40, 6),
                        (b"defg.i", 48, 6),
                    ],
                ),
                ("b", vec![(b"abdefg", 24, 6), (b"acadefg", 31, 7)]),
                ("c", vec![(b"adefggi", 39, 7), (b"bdefg.i", 47, 7)]),
            ],
        )],
    );

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        // atom from a whole alternation
        $a = { 61 ?? ( 62 63 | 64) 65 }
        // atom from a split alternation
        $b = { 61 ( ?? 62 63 | 64) 65 }
        $c = { 61 62 ( 63 ?? | 64) 65 }
        // atom from two split alternations
        $d = { 61 ( ?? 62 | 63 ) ( 64 | 65 ?? ) 66 }
    condition:
        any of them
}
"#,
    );
    checker.check_full_matches(
        b"aabce a.de ade ace abe abde abcce aabdf a.bdf aceef a.be.f",
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![(b"aabce", 0, 5), (b"a.de", 6, 4), (b"abde", 23, 4)],
                ),
                ("b", vec![(b"aabce", 0, 5), (b"ade", 11, 3)]),
                ("c", vec![(b"abde", 23, 4), (b"abcce", 28, 5)]),
                (
                    "d",
                    vec![
                        (b"aabdf", 34, 5),
                        (b"a.bdf", 40, 5),
                        (b"aceef", 46, 5),
                        (b"a.be.f", 52, 6),
                    ],
                ),
            ],
        )],
    );
}

#[test]
fn test_hex_string_atoms_multiple_matches() {
    // Define variables with the atom after some ungreedy repetitions.
    // This means that for one literal match, there might be multiple actual matches.
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        // 61 is 'a', 62 is 'b'
        $a = { 61 [1-2] 62 62 }
        $b = { 61 [1-] 62 62 }
        $c = { 61 [0-1] 62 62 }
    condition:
        any of them
}
"#,
    );

    checker.check_full_matches(
        b"b ab aab abbb aaaab aaaaabb ababaabb abbaaabab",
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"abbb", 9, 4),
                        (b"aaabb", 22, 5),
                        (b"aabb", 23, 4),
                        (b"aabb", 32, 4),
                    ],
                ),
                (
                    "b",
                    vec![
                        (b"ab aab abb", 2, 10),
                        (b"aab abb", 5, 7),
                        (b"ab abb", 6, 6),
                        (b"abbb", 9, 4),
                        (b"aaaab aaaaabb", 14, 13),
                        (b"aaab aaaaabb", 15, 12),
                        (b"aab aaaaabb", 16, 11),
                        (b"ab aaaaabb", 17, 10),
                        (b"aaaaabb", 20, 7),
                        (b"aaaabb", 21, 6),
                        (b"aaabb", 22, 5),
                        (b"aabb", 23, 4),
                        (b"abb ababaabb", 24, 12),
                        (b"ababaabb", 28, 8),
                        (b"abaabb", 30, 6),
                        (b"aabb", 32, 4),
                        (b"abb abb", 33, 7),
                    ],
                ),
                (
                    "c",
                    vec![
                        (b"abb", 9, 3),
                        (b"aabb", 23, 4),
                        (b"abb", 24, 3),
                        (b"aabb", 32, 4),
                        (b"abb", 33, 3),
                        (b"abb", 37, 3),
                    ],
                ),
            ],
        )],
    );

    // Do the same with greedy repetitions.
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a.{1,2}bb/
        $b = /a[^z]+bb/
        $c = /a.?bb/
        // Regression test, hide the greedy repetitions inside an expression not
        // visited by the atom visitor.
        $d = /a([^ ]+|z).aa/
    condition:
        any of them
}
"#,
    );

    checker.check_full_matches(
        b"b ab aab abbb aaaab aaaaabb ababaabb abbaaabab",
        vec![(
            "default:a".to_owned(),
            vec![
                (
                    "a",
                    vec![
                        (b"abbb", 9, 4),
                        (b"aaabb", 22, 5),
                        (b"aabb", 23, 4),
                        (b"aabb", 32, 4),
                    ],
                ),
                (
                    "b",
                    vec![
                        (b"ab aab abbb aaaab aaaaabb ababaabb abb", 2, 38),
                        (b"aab abbb aaaab aaaaabb ababaabb abb", 5, 35),
                        (b"ab abbb aaaab aaaaabb ababaabb abb", 6, 34),
                        (b"abbb aaaab aaaaabb ababaabb abb", 9, 31),
                        (b"aaaab aaaaabb ababaabb abb", 14, 26),
                        (b"aaab aaaaabb ababaabb abb", 15, 25),
                        (b"aab aaaaabb ababaabb abb", 16, 24),
                        (b"ab aaaaabb ababaabb abb", 17, 23),
                        (b"aaaaabb ababaabb abb", 20, 20),
                        (b"aaaabb ababaabb abb", 21, 19),
                        (b"aaabb ababaabb abb", 22, 18),
                        (b"aabb ababaabb abb", 23, 17),
                        (b"abb ababaabb abb", 24, 16),
                        (b"ababaabb abb", 28, 12),
                        (b"abaabb abb", 30, 10),
                        (b"aabb abb", 32, 8),
                        (b"abb abb", 33, 7),
                    ],
                ),
                (
                    "c",
                    vec![
                        (b"abbb", 9, 4),
                        (b"aabb", 23, 4),
                        (b"abb", 24, 3),
                        (b"aabb", 32, 4),
                        (b"abb", 33, 3),
                        (b"abb", 37, 3),
                    ],
                ),
                (
                    "d",
                    vec![
                        (b"ab aa", 2, 5),
                        (b"abbb aa", 9, 7),
                        (b"aaaab aa", 14, 8),
                        (b"aaab aa", 15, 7),
                        (b"aab aa", 16, 6),
                        (b"ab aa", 17, 5),
                        (b"aaaaa", 20, 5),
                        (b"ababaa", 28, 6),
                        (b"abbaaa", 37, 6),
                    ],
                ),
            ],
        )],
    );
}

#[test]
fn test_variable_hex_string_negation() {
    let input = (0_u8..=255_u8).collect::<Vec<_>>();

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { ~?C }
    condition:
        any of them
}
"#,
    );
    checker.check_full_matches(
        &input,
        vec![(
            "default:a".to_owned(),
            vec![(
                "a",
                (0..=255)
                    .filter(|v| v & 0x0F != 0x0C)
                    .map(|v| (&input[v..(v + 1)], v, 1))
                    .collect(),
            )],
        )],
    );

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $b = { ~C? }
    condition:
        any of them
}
"#,
    );
    checker.check_full_matches(
        &input,
        vec![(
            "default:a".to_owned(),
            vec![(
                "b",
                (0..=255)
                    .filter(|v| v & 0xF0 != 0xC0)
                    .map(|v| (&input[v..(v + 1)], v, 1))
                    .collect(),
            )],
        )],
    );

    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $c = { ~C3 }
    condition:
        any of them
}
"#,
    );
    checker.check_full_matches(
        &input,
        vec![(
            "default:a".to_owned(),
            vec![(
                "c",
                (0..=255)
                    .filter(|v| *v != 0xC3)
                    .map(|v| (&input[v..(v + 1)], v, 1))
                    .collect(),
            )],
        )],
    );
}

#[test]
fn test_variable_no_literals() {
    // Test a var with no literals extracted
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a+(b|)c+/
    condition:
        any of them
}"#,
    );
    checker.check(b"a", false);
    checker.check(b"b", false);
    checker.check(b"ab", false);
    checker.check(b"bc", false);
    checker.check(b"abc", true);
    checker.check(b"ac", true);
    checker.check(b"aac", true);
    checker.check(b"abccc", true);
    checker.check(b"aabbc", false);
}
