use crate::utils::{check, check_err};

#[test]
fn test_imports() {
    check_err(
        r#"import "a"
rule foo { condition: true }"#,
        "error: unknown import a",
    );

    check_err(
        r#"
rule foo { condition: pe.nb_sections > 0 }"#,
        "mem:2:23: error: unknown identifier \"pe\"",
    );

    check(
        r#"
import "tests"
import "tests"
rule foo { condition: true }"#,
        b"",
        true,
    );
}

#[test]
fn test_value_wrong_op() {
    // Field not existing in a dictionary
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.do_not_exist
}"#,
        "mem:4:21: error: unknown field \"do_not_exist\"",
    );

    // Using array syntax on a dictionary, scalar and function
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.constants[0]
}"#,
        "mem:4:16: error: invalid identifier type",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.constants.one[0]
}"#,
        "mem:4:16: error: invalid identifier type",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.isum[0]
}"#,
        "mem:4:16: error: invalid identifier type",
    );

    // Using dict syntax on a array, scalar and function
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.integer_array.foo
}"#,
        "mem:4:16: error: invalid identifier type",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.constants.one_half.bar
}"#,
        "mem:4:16: error: invalid identifier type",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.isum.foo
}"#,
        "mem:4:16: error: invalid identifier type",
    );

    // Using function call on dictionary, array and scalar
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.constants(5)
}"#,
        "mem:4:16: error: invalid identifier type",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.struct_array()
}"#,
        "mem:4:16: error: invalid identifier type",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.constants.regex(2, 3)
}"#,
        "mem:4:16: error: invalid identifier type",
    );

    // Cannot use compound values as expressions
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.constants > 0
}"#,
        "mem:4:16: error: wrong use of identifier",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.string_array > 0
}"#,
        "mem:4:16: error: wrong use of identifier",
    );
    check_err(
        r#"import "tests"

rule foo {
    condition: tests.isum > 0
}"#,
        "mem:4:16: error: wrong use of identifier",
    );
}

#[test]
fn test_value_wrong_type() {
    #[track_caller]
    fn check_invalid_types(condition: &str) {
        check_err(
            &format!(
                r#"import "tests"
rule foo {{
    condition: {}
}}"#,
                condition
            ),
            "error: expressions have invalid types",
        );
    }

    // Check direct primitives
    check_invalid_types("tests.constants.one == \"foo\"");
    check_invalid_types("tests.constants.one_half == \"foo\"");
    check_invalid_types("tests.constants.str + 1 > 0");
    check_invalid_types("tests.constants.regex + 1 > 0");
    check_invalid_types("tests.constants.true + 1 > 0");

    // Check lazy values
    check_invalid_types("tests.lazy().one == \"foo\"");
    check_invalid_types("tests.lazy().one_half == \"foo\"");
    check_invalid_types("tests.lazy().str + 1 > 0");
    check_invalid_types("tests.lazy().regex + 1 > 0");
    check_invalid_types("tests.lazy().true + 1 > 0");
}
