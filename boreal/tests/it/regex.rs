use crate::utils::Checker;

#[test]
fn test_regex_unicode_handling() {
    // The '+' will apply on the last byte of the 'é' utf-8 char, not on the char itself,
    // so this is: `<\xC3\xA9+>`.
    let checker = Checker::new(
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
    checker.check("<éé>".as_bytes(), false);
    checker.check(b"<\xC3\xA9\xA9>", true);
    checker.check(b"<\xC3\xA9\xA9\xA9\xA9>", true);
    checker.check(b"<\xC3\xA9\xA9\xA9\xA9", false);
    checker.check(b"\xC3\xA9\xA9\xA9\xA9>", false);
}
