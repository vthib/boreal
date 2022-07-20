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

    check_err(
        r#"
rule a {
    condition:
        for any a in (1, 2): (
            for any b in (3, 4): (
                for any a in (5..10): (
                    b == 4 and a >= 8
                )
            )
            and a == 2
        )
}
"#,
        "mem:6:25: error: duplicated loop identifier a",
    );
}

#[test]
fn test_for_identifiers_modules_errors() {
    // Cannot iterate on scalar, object, function
    check_err(
        &build_rule("for any i in tests.constants.one: (true)"),
        "mem:12:22: error: identifier is not iterable",
    );
    check_err(
        &build_rule("for any i in tests.constants.foo: (true)"),
        "mem:12:22: error: identifier is not iterable",
    );
    check_err(
        &build_rule("for any i in tests.constants: (true)"),
        "mem:12:22: error: identifier is not iterable",
    );
    check_err(
        &build_rule("for any i in tests.match: (true)"),
        "mem:12:22: error: identifier is not iterable",
    );
    check_err(
        &build_rule("for any i in tests: (true)"),
        "mem:12:22: error: wrong use of identifier",
    );

    // Wrong number of identifiers
    check_err(
        &build_rule("for any i in tests.integer_dict: (true)"),
        "mem:12:17: error: expected 2 identifiers to bind, got 1",
    );
    check_err(
        &build_rule("for any i,j,k in tests.integer_dict: (true)"),
        "mem:12:17: error: expected 2 identifiers to bind, got 3",
    );
    check_err(
        &build_rule("for any a,b in tests.integer_array: (true)"),
        "mem:12:17: error: expected 1 identifiers to bind, got 2",
    );

    // Wrong operations on iterated value
    check_err(
        &build_rule("for any i in tests.struct_array: (i.i.s == 3)"),
        "mem:12:43: error: invalid identifier type",
    );
    check_err(
        &build_rule("for any i in tests.struct_array: (i == 3)"),
        "mem:12:43: error: wrong use of identifier",
    );
    check_err(
        &build_rule("for any i in tests.struct_array: (i[0] == 3)"),
        "mem:12:43: error: invalid identifier type",
    );
    check_err(
        &build_rule("for any i in tests.struct_array: (i() == 3)"),
        "mem:12:43: error: invalid identifier type",
    );

    // Type checking fails on use of bounded identifier
    check_err(
        &build_rule(r#"for all i in tests.integer_array: (i == "foo")"#),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule("for all s in tests.string_array: (s == 1)"),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule("for all k,v in tests.integer_dict: (k == 1)"),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule("for all k,v in tests.integer_dict: (k.d == 1)"),
        "mem:12:45: error: invalid identifier type",
    );
    check_err(
        &build_rule(r#"for all k,v in tests.integer_dict: (v == "foo")"#),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule(r#"for all k,v in tests.struct_dict: (v.i == "foo")"#),
        "error: expressions have invalid types",
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
fn test_for_modules() {
    check(
        &build_rule(
            r#"
        for all s in tests.string_array: (
            s == "foo" or s == "bar" or s == "baz" or s == "foo\x00bar"
        )
        "#,
        ),
        b"",
        true,
    );

    check(
        &build_rule(
            r#"for all k,v in tests.string_dict: (
            (k == "foo" and v == "foo") or (k == "bar" and v == k)
        )"#,
        ),
        b"",
        true,
    );
    check(
        &build_rule(
            r#"for any k,v in tests.struct_dict: (
            (k == "foo" and v.i == 1 and v.s == "foo")
        )"#,
        ),
        b"",
        true,
    );

    // Check with number
    check(
        &build_rule(
            r#"for 3 s in tests.string_array: (
            (s startswith "ba" or s contains "\x00")
        )"#,
        ),
        b"",
        true,
    );
}

#[test]
fn test_for_identifiers_shadowing() {
    // Bounded identifier shadows a rule name.
    let checker = Checker::new(
        r#"
rule a { condition: true }
rule b { condition: for any a in (2): (a == 2) }
rule c { condition: for any i in (3): (i == 3 and a and b) }
"#,
    );
    checker.check_count(b"", 3);

    // Bounded identifier shadows imports
    check(
        r#"
import "tests"
rule a { condition: for any tests in (2): (tests == 2) }
"#,
        b"",
        true,
    );
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
// TODO: broken on libyara 4.2, fixed on master need 4.3 release
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

    let checker = Checker::new(&build_rule("50% of ($a*)"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a0a1a2b0b1c0", true);
    checker.check(b"a0b0b1c0", false);
    checker.check(b"a0a1", true);
    checker.check(b"a0a2", true);
    checker.check(b"a1a2", true);

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

    let checker = Checker::new(&build_rule("51% of ($a0, $a1, $a2, $c0)"));
    checker.check(b"", false);
    checker.check(b"a0", false);
    checker.check(b"a1", false);
    checker.check(b"a2", false);
    checker.check(b"b0", false);
    checker.check(b"b1", false);
    checker.check(b"c0", false);
    checker.check(b"a0b1", false);
    checker.check(b"a0b1c0", false);
    checker.check(b"a0b0b1c0", false);
    checker.check(b"a0a1b0b1c0", true);
    checker.check(b"a0a1b0b1", false);
    checker.check(b"a0a1a2b0b1", true);
    checker.check(b"a1a2b0b1", false);
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

// It is possible for a variable to be reused multiple times in a variable set.
#[test]
fn test_for_expression_overlap() {
    // Even if the selection number is bigger than the number of variables, this does not
    // mean the for expression is false: a variable can be reused.
    let checker = Checker::new(
        r#"
    rule a {
        strings:
            $a = "abc"
            $b = "def"
        condition:
            for 3 of ($a, $b, $a): ($)
    }"#,
    );
    checker.check(b"", false);
    checker.check(b"def", false);
    checker.check(b"abc", false);
    checker.check(b"abcdef", true);

    // Same for wildcards
    let checker = Checker::new(
        r#"
    rule a {
        strings:
            $a   = "a"
            $aa  = "bb"
            $aaa = "ccc"
        condition:
            // This include "$a, $aa, $aaa", "$aa, $aaa", "$aaa", so 6 variables total
            for 6 of ($a*, $aa*, $aaa*): ($)
    }"#,
    );
    checker.check(b"", false);
    checker.check(b"a", false);
    checker.check(b"bb", false);
    checker.check(b"ccc", false);
    checker.check(b"abbccc", true);

    // This is also the case for identifiers
    check(
        &build_rule("for 4 i in tests.string_array : ( true )"),
        b"",
        true,
    );
    check(
        &build_rule("for 5 i in tests.string_array : ( true )"),
        b"",
        false,
    );
}

#[test]
fn test_for_expression_err() {
    check_err(
        &build_rule("all of ($d)"),
        "mem:12:9: error: unknown variable $d",
    );
    check_err(
        &build_rule("all of ($d*)"),
        "mem:12:9: error: unknown variable $d*",
    );

    check_err(
        "rule a { condition: any of () }",
        "mem:1:29: error: syntax error",
    );
    check_err(
        "rule a { condition: all of them }",
        "mem:1:21: error: unknown variable $*",
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
