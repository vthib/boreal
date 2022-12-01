use crate::utils::Checker;

#[test]
fn test_limit_match_max_length() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $r1 = /ba+b/
    condition:
        any of them
}
"#,
    );

    let mut full_text: Vec<_> = Vec::new();
    full_text.push(b'b');
    full_text.extend(std::iter::repeat(b'a').take(1024));
    full_text.push(b'b');

    checker.check_full_matches(
        &full_text,
        vec![
            // r1 match but is trimmed to 512 chars
            (
                "default:a".to_owned(),
                vec![("r1", vec![(&full_text[0..512], 0, 1026)])],
            ),
        ],
    );
}

#[test]
fn test_limit_string_max_nb_matches() {
    let mem: Vec<_> = std::iter::repeat(0).take(1_100_000).collect();

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { 00 }
    condition:
        #a == 1000
}
"#,
    );
    checker.check_boreal(&mem, true);

    // For YARA this is 1_000_000, but it exhibits the same behavior.
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { 00 }
    condition:
        #a == 1000000
}
"#,
    );
    checker.check_libyara(&mem, true);

    // Do this with a non-atomizable regex, to check the limit is also done outside of the ac scan
    // pass.
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { ?? }
    condition:
        #a == 1000
}
"#,
    );
    checker.check_boreal(&mem, true);
}
