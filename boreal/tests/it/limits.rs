use crate::utils::Compiler;

#[test]
fn test_limit_match_max_length() {
    let mut compiler = Compiler::new();
    compiler.add_rules(
        r#"
rule a {
    strings:
        $r1 = /ba+b/
    condition:
        any of them
}
"#,
    );
    let checker = compiler.into_checker();

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
