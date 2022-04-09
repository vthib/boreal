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
    checker.check(b"b\0W\0F\0u\0Z\03\0V\0l\0", false);
    checker.check(b"1\0h\0b\0m\0d\01\0Z\0", false);
    checker.check(b"t\0Y\0W\05\0n\0d\0W\0", false);
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
    checker.check(b"m\0c\0m\0F\0p\0c\02\0", false);
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
    checker.check(b"Z\0y\0Y\0W\01\0i\0b\02\0l\0z\0Z\0", true);
    checker.check(b"m\0c\0m\0F\0t\0Y\0m\09\0p\0c\02\0", true);
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
    checker.check(base64::encode("1\01\0c\0m\0V\0z\0").as_bytes(), false);
    checker.check(base64::encode("t\0d\0X\0J\0l\0c\0").as_bytes(), false);

    // not matching on "mures" wide, then base64
    checker.check(base64::encode("m\0u\0r\0e\0s\0").as_bytes(), false);
    checker.check(base64::encode(" m\0u\0r\0e\0s\0").as_bytes(), false);
    checker.check(base64::encode("  m\0u\0r\0e\0s\0").as_bytes(), false);

    // Matches on "mures" wide, then base64wide
    checker.check(b"b\0Q\0B\01\0A\0H\0I\0A\0Z\0Q\0B\0z\0A\0", true);
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
    checker.check(b"1\05\0c\0n\0R\0p\0b\0G\0x\0l\0", true);
    checker.check(b"t\0e\0X\0J\00\0a\0W\0x\0s\0Z\0", true);

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
        b"b\0Q\0B\05\0A\0H\0I\0A\0d\0A\0B\0p\0A\0G\0w\0A\0b\0A\0B\0l\0A\0",
        true,
    );
    checker.check(
        b"0\0A\0e\0Q\0B\0y\0A\0H\0Q\0A\0a\0Q\0B\0s\0A\0G\0w\0A\0Z\0Q\0",
        true,
    );
    checker.check(
        b"t\0A\0H\0k\0A\0c\0g\0B\00\0A\0G\0k\0A\0b\0A\0B\0s\0A\0G\0U\0A\0",
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
    checker.check(b"J\0v\0c\0m\0V\0h\0b\0C\0B\0m\0b\03\0J\0l\0c\03\0", true);
    checker.check(b"i\0b\03\0J\0l\0Y\0W\0w\0g\0Z\0m\09\0y\0Z\0X\0N\00\0", true);
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
        b"i\0A\0G\08\0A\0c\0g\0B\0l\0A\0G\0E\0A\0b\0A\0A\0g\0A\0G\0Y\0A\0b\0w\0B\0y\0A\0G\0U\0A\0c\0w\0B\00\0A\0",
        false,
    );

    // "noix de coco", wide, base64 and base64wide

    checker.check(b"noix de coco", false);
    // not matching on ascii base64
    checker.check(base64::encode("noix de coco").as_bytes(), false);
    checker.check(base64::encode(" noix de coco").as_bytes(), false);
    checker.check(base64::encode("  noix de coco").as_bytes(), false);
    // not matching on ascii base64wide
    checker.check(b"b\0m\09\0p\0e\0C\0B\0k\0Z\0S\0B\0j\0b\02\0N\0v\0", false);
    checker.check(b"5\0v\0a\0X\0g\0g\0Z\0G\0U\0g\0Y\02\09\0j\0b\0", false);
    checker.check(b"u\0b\02\0l\04\0I\0G\0R\0l\0I\0G\0N\0v\0Y\02\0", false);
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
        b"u\0A\0G\08\0A\0a\0Q\0B\04\0A\0C\0A\0A\0Z\0A\0B\0l\0A\0C\0A\0A\0Y\0w\0B\0v\0A\0G\0M\0A\0b\0w\0",
        true,
    );

    // "comcombre", ascii and wide, base64 and base64wide

    checker.check(b"comcombre", false);
    // not matching on ascii base64
    checker.check(base64::encode("comcombre").as_bytes(), true);
    checker.check(base64::encode(" comcombre").as_bytes(), true);
    checker.check(base64::encode("  comcombre").as_bytes(), true);
    // matching on ascii base64wide
    checker.check(b"Y\02\09\0t\0Y\02\09\0t\0Y\0n\0J\0l\0", true);
    checker.check(b"N\0v\0b\0W\0N\0v\0b\0W\0J\0y\0Z\0", true);
    checker.check(b"j\0b\02\01\0j\0b\02\01\0i\0c\0m\0", true);
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
        b"Y\0w\0B\0v\0A\0G\00\0A\0Y\0w\0B\0v\0A\0G\00\0A\0Y\0g\0B\0y\0A\0G\0U\0A\0",
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
