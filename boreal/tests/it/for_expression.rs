use crate::utils::{build_rule, check, check_boreal, check_err, Checker};

#[test]
fn test_for_identifiers_errors() {
    check_err(
        "rule a { condition: for any a, b in (0..3): (true) }",
        "mem:1:29: error: expected 1 identifiers to bind, got 2",
    );

    check_err(
        "rule a { condition: for any i in (/a/): (true) }",
        "mem:1:35: error: expression has an invalid type",
    );

    check_err(
        "rule a { condition: for any i in (j): (true) }",
        "mem:1:35: error: unknown identifier \"j\"",
    );
}

#[test]
fn test_for_identifiers() {
    let build = |cond: &str| {
        format!(
            r#"rule a {{
    strings:
        $a = /ba+/
    condition:
        {}
}}"#,
            cond
        )
    };

    let checker = Checker::new(&build("for any a in (1..(#a)): (!a[a] == 4)"));
    checker.check(b"", false);
    checker.check(b"ba baa baaaa baa", false);
    checker.check(b"ba baa baaa baa", true);
    checker.check(b"baaa baa", true);
    checker.check(b"ba ba baaa", true);

    let checker = Checker::new(&build("for all a in (1..(#a-1)): (!a[a] == 4)"));
    checker.check(b"", false);
    checker.check(b"ba baa baaaa baa", false);
    checker.check(b"baaa baaa baaa", true);
    checker.check(b"baaa baaa ba", true);
    checker.check(b"baaa baa baaa", false);
    checker.check(b"baaa baaa", true);
    checker.check(b"baaa", false);

    let checker = Checker::new(&build("for any a in (1, #a): (!a[a] == 4)"));
    checker.check(b"", false);
    checker.check(b"ba baa baaaa baa", false);
    checker.check(b"baaa ba ba", true);
    checker.check(b"ba baaa ba", false);
    checker.check(b"ba ba baaa", true);

    let checker = Checker::new(&build("for all a in (1, #a-1): (!a[a] == 4)"));
    checker.check(b"", false);
    checker.check(b"ba baa baaaa baa", false);
    checker.check(b"baaa ba ba", false);
    checker.check(b"baaa baaa ba", true);
    checker.check(b"baaa ba baaa", false);
    checker.check(b"baaa ba", true);
    checker.check(b"baaa", false);

    let checker = Checker::new(
        r#"
rule a {
    condition:
        for any i in (1..5): (
            for any j in (6..10): (
                for any k in (11..15): (
                    i == 3 and j == 10 and k == 12
                )
            )
            and
            for any j in (16..20): (
                for any k in (21..25): (
                    for any l in (26..30): (
                        i == 3 and j == 17 and l == 28 and k == 21
                    )
                )
            )
        )
}"#,
    );
    checker.check(b"", true);
}

#[test]
fn test_for_expression_all() {
    let checker = Checker::new(&build_rule("all of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("all of ($*)"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("all of ($a0, $b1, $c0)"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("all of ($a*)"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1", false);
    checker.check(b"a0a1a2", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);
}

#[test]
fn test_for_expression_any() {
    let checker = Checker::new(&build_rule("any of them"));
    checker.check(b"", false);
    checker.check(b"a0", true);
    checker.check(b"a1", true);
    checker.check(b"a2", true);
    checker.check(b"b0", true);
    checker.check(b"b1", true);
    checker.check(b"c0", true);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);
}

#[test]
// FIXME: this is broken for libyara, not sure why
#[ignore]
fn test_for_expression_none() {
    let checker = Checker::new(&build_rule("none of them"));
    checker.check(b"", true);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", false);

    let checker = Checker::new(&build_rule("none of ($b*)"));
    checker.check(b"", true);
    checker.check(b"a0", true);
    checker.check(b"a1", true);
    checker.check(b"a2", true);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", true);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", false);
}

#[test]
fn test_for_expression_number() {
    let checker = Checker::new(&build_rule("-1 of them"));
    checker.check(b"", true);
    checker.check(b"a0", true);
    checker.check(b"a1", true);
    checker.check(b"a2", true);
    checker.check(b"b0", true);
    checker.check(b"b1", true);
    checker.check(b"c0", true);
    checker.check(b"a0b1", true);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("0 of them"));
    checker.check(b"", true);
    checker.check(b"a0", true);
    checker.check(b"a1", true);
    checker.check(b"a2", true);
    checker.check(b"b0", true);
    checker.check(b"b1", true);
    checker.check(b"c0", true);
    checker.check(b"a0b1", true);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("3 of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("6 of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("7 of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", false);
}

#[test]
fn test_for_expression_percent() {
    let checker = Checker::new(&build_rule("(#c0 - 2)% of them"));
    checker.check(b"", true);
    checker.check(b"a0", true);
    checker.check(b"a1", true);
    checker.check(b"a2", true);
    checker.check(b"b0", true);
    checker.check(b"b1", true);
    checker.check(b"c0", true);
    checker.check(b"a0b1", true);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("(#c0)% of them"));
    checker.check(b"", true);
    checker.check(b"a0", true);
    checker.check(b"a1", true);
    checker.check(b"a2", true);
    checker.check(b"b0", true);
    checker.check(b"b1", true);
    checker.check(b"a0b1", true);
    checker.check(b"a0a1a2b0b1", true);

    let checker = Checker::new(&build_rule("50% of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);

    // Gets rounded up to 4 of them
    let checker = Checker::new(&build_rule("51% of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0b0b1c0", true);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("100% of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", true);

    let checker = Checker::new(&build_rule("(101 + #c0)% of them"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", false);
    checker.check(b"a0a1a2b0b1c0", false);
}

#[test]
fn test_for_expression_err() {
    check_err(
        &build_rule("all of ($d)"),
        "mem:12:9: error: unknown variable $d",
    );
    check_err(
        &build_rule("all of ($d*)"),
        "mem:12:9: error: unknown variable $d",
    );
}

// Test behavior of for expression evaluation with undefined values
#[test]
fn test_for_expression_undefined() {
    check(&build_rule("tests.integer_array[5] of them"), b"a0", false);
    check(
        &build_rule("defined tests.integer_array[5] of them"),
        b"a0",
        true,
    );

    check(&build_rule("tests.integer_array[5]% of them"), b"a0", false);
    // TODO: this is a weird behavior from YARA
    check_boreal(
        &build_rule("defined tests.integer_array[5]% of them"),
        b"a0",
        true,
    );

    check(
        &build_rule("for any of them: (tests.integer_array[5] == 1)"),
        b"a0",
        false,
    );
    check(
        &build_rule("defined (for any of them: (tests.integer_array[5] == 1))"),
        b"a0",
        true,
    );
}
