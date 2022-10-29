use crate::utils::{build_rule, check, check_err, Checker};

#[test]
fn test_variable() {
    let checker = Checker::new(
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
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /f[aF]T[d-g]\x76/ nocase
        $b = /foo/ fullword
        $c = /bar.{0,3}/ fullword nocase
        $d = /.{,2}quu/ nocase fullword
    condition:
        any of them
}"#,
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

    let checker = Checker::new(
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

    let checker = Checker::new(
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
        $a = /{}/ {}
    condition:
        $a
}}"#,
        regex, modifiers
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
    let checker = build_checker("abc", "wide");
    checker.check(b"abc", false);
    checker.check(b"a\0b\0c\0", true);
    checker.check(b"a\0b\0c", false);
    checker.check(b"ab\0c\0", false);
    checker.check(b"\0a\0b\0c\0", true);
    checker.check(b"\0a\0b\0c", false);

    let checker = build_checker("a+b|cd{2,}", "wide");
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

    let checker = build_checker("<[a-z][0-9]*>", "wide");
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

    let checker = build_checker(r#"\d[^abc]d$"#, "wide");
    checker.check(b"13d", false);
    checker.check(b"1\x003\x00d\x00", true);
    checker.check(b"1\x003\x00d", false);
    checker.check(b"1\x003\x00\x00", false);
    checker.check(b"a\x00d\x00d\x00", false);
    checker.check(b"1\x00a\x00d\x00", false);
    checker.check(b"1\x00d\x00e\x00", false);
    checker.check(b"1\x00d\x00d\x00", true);

    let checker = build_checker(r"a(b|c+)[def][^g]", "wide ascii");
    checker.check(b"abdf", true);
    checker.check(b"a\0b\0d\0f\0", true);
    checker.check(b"a\0b\0d\0f", false);
    checker.check(b"abeg", false);
    checker.check(b"a\0b\0e\0g\0", false);
    checker.check(b"acccf\0", true);
    checker.check(b"a\0c\0c\0c\0f\0\0\0", true);
    checker.check(b"a\0c\0c\0c\0f\0\0", false);
}

// Test wide regex with word boundaries
#[test]
fn test_variable_regex_wide_word_boundaries() {
    // Test regex consisting of a single word boundary. No-one will ever use this regex, but
    // it helps comparing with libyara
    let checker = build_checker(r"\b", "wide");
    checker.check(b"", false);
    checker.check(b"\0", false);
    // This one has different behavior from libyara. Does it matter? no, no-one will every use
    // this regex.
    checker.check_boreal(b"a\0", true);
    checker.check_libyara(b"a\0", false);
    checker.check(b"\0a", false);

    let checker = build_checker(r"\B", "wide");
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
    let checker = build_checker(r"\ba", "wide");
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
    let checker = build_checker(r"\Ba", "wide");
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
    let checker = build_checker(r"a\b", "wide");
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
    let checker = build_checker(r"a\B", "wide");
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
    let checker = build_checker(r"<.+\bA\b.+>", "wide");
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
    let checker = build_checker(r"<.+\BA\B.+>", "wide");
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
    let checker = build_checker(r"<\w+\b.a>", "wide");
    checker.check(&to_wide(b"<ave|a>"), true);
    checker.check(&to_wide(b"<aveva>"), false);
    checker.check(&to_wide("<avéva>".as_bytes()), false);
    checker.check(&to_wide("<avé|a>".as_bytes()), false);
}

#[test]
fn test_variable_regex_word_boundaries_edge_cases() {
    let build_checker = |regex: &str, modifiers: &str| {
        Checker::new(&format!(
            r#"
rule a {{
    strings:
        $a = /{}/ {}
        $z = "z"
    condition:
        (#z == 0 and #a == 0) or (!a == #z)
}}"#,
            regex, modifiers,
        ))
    };

    // The difference between a regex with a boundary, and one without it with post match checking,
    // is that the boundary does not factor in the resolution of repetitions.

    // This works, because we recheck after the initial match, and the repetition is greedy, hence
    // the post match will only reduce the match.
    let checker = build_checker(r"a.{0,4}\b", "");
    checker.check(b"z a", true);
    checker.check(b"zz a1", true);
    checker.check(b"zzz a12", true);
    checker.check(b"zzzzz a1234", true);
    checker.check(b"a12345", true);
    checker.check(b"zzzzz a1234>", true);
    checker.check(b"zzzz a12>34", true);
    checker.check(b"zzzz a>>>34", true);
    let checker = build_checker(r"a.{0,4}\b", "wide");
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
    let checker = build_checker(r"a.{0,4}?\b", "");
    checker.check(b"z a", true);
    checker.check(b"zz a1", true);
    checker.check(b"zzz a12", true);
    checker.check(b"zzzzz a1234", true);
    checker.check(b"a12345", true);
    checker.check(b"zzzzz a1234>", true);
    checker.check(b"zzz a12>34", true);
    checker.check(b"z a>>>34", true);
    let checker = build_checker(r"a.{0,4}?\b", "wide");
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
fn test_variable_string_modifiers() {
    // \x76 is 'v'
    let checker = Checker::new(
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

    let checker = Checker::new(
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
fn test_variable_base64_small() {
    let checker = Checker::new(
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
    checker.check(base64::encode("`").as_bytes(), true);
    checker.check(base64::encode("b").as_bytes(), true);
    checker.check(base64::encode("c").as_bytes(), true);

    // TODO: this is not matching, contrary to yara doc. report this
    checker.check(base64::encode("!").as_bytes(), false);
    checker.check(base64::encode(b"\xA1").as_bytes(), false);
    checker.check(base64::encode(b"\xE1").as_bytes(), false);

    checker.check(base64::encode(b"\xA0").as_bytes(), false);
    checker.check(base64::encode(b"ha").as_bytes(), false);
}

#[test]
fn test_variable_base64() {
    let checker = Checker::new(
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
    checker.check(base64::encode("mangue").as_bytes(), false);
    checker.check(base64::encode(" mangue").as_bytes(), false);
    checker.check(base64::encode("  mangue").as_bytes(), false);
    // not matching on ascii base64wide
    checker.check(b"b\0W\0F\0u\0Z\x003\0V\0l\0", false);
    checker.check(b"1\0h\0b\0m\0d\x001\0Z\0", false);
    checker.check(b"t\0Y\0W\x005\0n\0d\0W\0", false);
    // matching on wide, then base64
    checker.check(base64::encode("m\0a\0n\0g\0u\0e\0").as_bytes(), true);
    checker.check(base64::encode(" m\0a\0n\0g\0u\0e\0").as_bytes(), true);
    checker.check(base64::encode("  m\0a\0n\0g\0u\0e\0").as_bytes(), true);

    // "fraise" ascii and wide, then base64

    checker.check(b"fraise", false);
    // matching on ascii, then base64
    checker.check(base64::encode("fraise").as_bytes(), true);
    checker.check(base64::encode(" fraise").as_bytes(), true);
    checker.check(base64::encode("  fraise").as_bytes(), true);
    // not matching on ascii base64wide
    checker.check(b"Z\0n\0J\0h\0a\0X\0N\0l\0", false);
    checker.check(b"Z\0y\0Y\0W\0l\0z\0Z\0", false);
    checker.check(b"m\0c\0m\0F\0p\0c\x002\0", false);
    // matching on wide, then base64
    checker.check(base64::encode("f\0r\0a\0i\0s\0e\0").as_bytes(), true);
    checker.check(base64::encode(" f\0r\0a\0i\0s\0e\0").as_bytes(), true);
    checker.check(base64::encode("  f\0r\0a\0i\0s\0e\0").as_bytes(), true);
}

#[test]
fn test_variable_base64wide() {
    let checker = Checker::new(
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
    checker.check(base64::encode("framboise").as_bytes(), false);
    checker.check(base64::encode(" framboise").as_bytes(), false);
    checker.check(base64::encode("  framboise").as_bytes(), false);
    // matching on ascii base64wide
    checker.check(b"Z\0n\0J\0h\0b\0W\0J\0v\0a\0X\0N\0l\0", true);
    checker.check(b"Z\0y\0Y\0W\x001\0i\0b\x002\0l\0z\0Z\0", true);
    checker.check(b"m\0c\0m\0F\0t\0Y\0m\09\0p\0c\x002\0", true);
    // not matching on wide, then base64
    checker.check(
        base64::encode("f\0r\0a\0m\0b\0o\0i\0s\0e\0").as_bytes(),
        false,
    );
    checker.check(
        base64::encode(" f\0r\0a\0m\0b\0o\0i\0s\0e\0").as_bytes(),
        false,
    );
    checker.check(
        base64::encode("  f\0r\0a\0m\0b\0o\0i\0s\0e\0").as_bytes(),
        false,
    );

    // "mures" wide base64wide

    checker.check(b"mures", false);
    // not matching on ascii, then base64
    checker.check(base64::encode("mures").as_bytes(), false);
    checker.check(base64::encode(" mures").as_bytes(), false);
    checker.check(base64::encode("  mures").as_bytes(), false);
    // not matching on ascii base64wide
    checker.check(base64::encode("b\0X\0V\0y\0Z\0X\0").as_bytes(), false);
    checker.check(base64::encode("1\x01\0c\0m\0V\0z\0").as_bytes(), false);
    checker.check(base64::encode("t\0d\0X\0J\0l\0c\0").as_bytes(), false);

    // not matching on "mures" wide, then base64
    checker.check(base64::encode("m\0u\0r\0e\0s\0").as_bytes(), false);
    checker.check(base64::encode(" m\0u\0r\0e\0s\0").as_bytes(), false);
    checker.check(base64::encode("  m\0u\0r\0e\0s\0").as_bytes(), false);

    // Matches on "mures" wide, then base64wide
    checker.check(b"b\0Q\0B\x001\0A\0H\0I\0A\0Z\0Q\0B\0z\0A\0", true);
    checker.check(b"0\0A\0d\0Q\0B\0y\0A\0G\0U\0A\0c\0w\0", true);
    checker.check(b"t\0A\0H\0U\0A\0c\0g\0B\0l\0A\0H\0M\0A\0", true);

    // "myrtille" wide base64wide

    checker.check(b"myrtille", false);
    // not matching on ascii, then base64
    checker.check(base64::encode("myrtille").as_bytes(), false);
    checker.check(base64::encode(" myrtille").as_bytes(), false);
    checker.check(base64::encode("  myrtille").as_bytes(), false);
    // matching on ascii base64wide
    checker.check(b"b\0X\0l\0y\0d\0G\0l\0s\0b\0G\0", true);
    checker.check(b"1\x005\0c\0n\0R\0p\0b\0G\0x\0l\0", true);
    checker.check(b"t\0e\0X\0J\x000\0a\0W\0x\0s\0Z\0", true);

    // not matching on wide, then base64
    checker.check(base64::encode("m\0y\0r\0t\0i\0l\0l\0e\0").as_bytes(), false);
    checker.check(
        base64::encode(" m\0y\0r\0t\0i\0l\0l\0e\0").as_bytes(),
        false,
    );
    checker.check(
        base64::encode("  m\0y\0r\0t\0i\0l\0l\0e\0").as_bytes(),
        false,
    );

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
    let checker = Checker::new(
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
    checker.check(base64::encode("boreal forest").as_bytes(), true);
    checker.check(base64::encode(" boreal forest").as_bytes(), true);
    checker.check(base64::encode("  boreal forest").as_bytes(), true);
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
        base64::encode("b\0o\0r\0e\0a\0l\0 \0f\0o\0r\0e\0s\0t\0").as_bytes(),
        false,
    );
    checker.check(
        base64::encode(" b\0o\0r\0e\0a\0l\0 \0f\0o\0r\0e\0s\0t\0").as_bytes(),
        false,
    );
    checker.check(
        base64::encode("  b\0o\0r\0e\0a\0l\0 \0f\0o\0r\0e\0s\0t\0").as_bytes(),
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
    checker.check(base64::encode("noix de coco").as_bytes(), false);
    checker.check(base64::encode(" noix de coco").as_bytes(), false);
    checker.check(base64::encode("  noix de coco").as_bytes(), false);
    // not matching on ascii base64wide
    checker.check(b"b\0m\09\0p\0e\0C\0B\0k\0Z\0S\0B\0j\0b\x002\0N\0v\0", false);
    checker.check(b"5\0v\0a\0X\0g\0g\0Z\0G\0U\0g\0Y\x002\09\0j\0b\0", false);
    checker.check(
        b"u\0b\x002\0l\x004\0I\0G\0R\0l\0I\0G\0N\0v\0Y\x002\0",
        false,
    );
    // matching on wide, then base64
    checker.check(
        base64::encode("n\0o\0i\0x\0 \0d\0e\0 \0c\0o\0c\0o\0").as_bytes(),
        true,
    );
    checker.check(
        base64::encode(" n\0o\0i\0x\0 \0d\0e\0 \0c\0o\0c\0o\0").as_bytes(),
        true,
    );
    checker.check(
        base64::encode("  n\0o\0i\0x\0 \0d\0e\0 \0c\0o\0c\0o\0").as_bytes(),
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
    checker.check(base64::encode("comcombre").as_bytes(), true);
    checker.check(base64::encode(" comcombre").as_bytes(), true);
    checker.check(base64::encode("  comcombre").as_bytes(), true);
    // matching on ascii base64wide
    checker.check(b"Y\x002\09\0t\0Y\x002\09\0t\0Y\0n\0J\0l\0", true);
    checker.check(b"N\0v\0b\0W\0N\0v\0b\0W\0J\0y\0Z\0", true);
    checker.check(b"j\0b\x002\x001\0j\0b\x002\x001\0i\0c\0m\0", true);
    // matching on wide, then base64
    checker.check(
        base64::encode("c\0o\0m\0c\0o\0m\0b\0r\0e\0").as_bytes(),
        true,
    );
    checker.check(
        base64::encode(" c\0o\0m\0c\0o\0m\0b\0r\0e\0").as_bytes(),
        true,
    );
    checker.check(
        base64::encode("  c\0o\0m\0c\0o\0m\0b\0r\0e\0").as_bytes(),
        true,
    );
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
    let checker = Checker::new(
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

    let checker = Checker::new(
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

    let checker = Checker::new(
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

    let checker = Checker::new(
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
    fn check_at(mem: &[u8], at: u64, res: bool) {
        let rule = format!(
            r#"
    rule a {{
        strings:
            $a = "34"
            $b = /[a-z]{{2}}/
        condition:
            for any of them: ($ at {})
    }}"#,
            at
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
}

#[test]
fn test_variable_find_in() {
    fn check_in(mem: &[u8], from: u64, to: u64, res: bool) {
        let rule = format!(
            r#"
    rule a {{
        strings:
            $a = "345"
        condition:
            $a in ({}..{})
    }}"#,
            from, to
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
}

#[test]
fn test_variable_find_at_invalid() {
    // Negative index gives a defined result, but false
    check(&build_rule("defined ($a0 at (#a0-10))"), b"", true);
    check(&build_rule("$a0 at (#a0-10)"), b"", false);

    // Undefined value
    // TODO(4.3): See https://github.com/VirusTotal/yara/pull/1759
    check(
        &build_rule("defined ($a0 at tests.integer_array[5])"),
        b"",
        true,
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
