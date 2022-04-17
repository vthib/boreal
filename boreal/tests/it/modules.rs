use crate::utils::{check, check_boreal, check_err};

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

#[test]
fn test_eval() {
    #[track_caller]
    fn check_ok(condition: &str) {
        check_boreal(
            &format!(
                r#"import "tests"
rule foo {{
    strings:
        $a = "abc"
    condition: {} and #a >= 0
}}"#,
                condition
            ),
            b"",
            true,
        );
    }

    // check immediate values
    check_ok("tests.constants.one == 1");
    check_ok("tests.constants.one_half == 0.5");
    check_ok("tests.constants.str == \"str\"");
    check_ok("tests.constants.true");
    check_ok("tests.string_dict.foo == \"foo\"");
    check_ok("tests.string_dict.bar == \"bar\"");

    // Check array eval
    check_ok("tests.integer_array[0] == 0");
    check_ok("tests.integer_array[1] == 1");
    check_ok("tests.struct_array[1].i == 1");
    check_ok("not defined tests.struct_array[1].s");
    check_ok("not defined tests.struct_array[0].i");
    check_ok("not defined tests.integer_array[3]");
    check_ok("not defined tests.integer_array[#a - 1]");

    // Check lazy eval into primitive
    check_ok("tests.lazy().one == 1");
    check_ok("tests.lazy().one_half == 0.5");
    check_ok("tests.lazy().str == \"str\"");
    check_ok("tests.lazy().true");
    check_ok("tests.lazy().dict.i == 3");
    check_ok("tests.lazy().dict.s == \"<acb>\"");
    check_ok("tests.lazy().isum(2, 3+5) == 10");
    check_ok("tests.lazy().str_array[1] == \"bar\"");
    check_ok("tests.lazy().str_array[1] == \"bar\"");
    check_ok("not defined tests.lazy().str_array[10]");
    check_ok("not defined tests.lazy().str_array[#a - 5]");

    // Test discrepancies between declared type, and returned type.
    check_ok("not defined tests.lazy().dict.oops");
    check_ok("not defined tests.lazy().fake_bool_to_array");
    check_ok("not defined tests.lazy().fake_bool_to_dict");
    check_ok("not defined tests.lazy().fake_bool_to_fun");
    check_ok("not defined tests.lazy().fake_dict_to_bool.i");
    check_ok("not defined tests.lazy().fake_array_to_bool[2]");
    check_ok("not defined tests.lazy().fake_fun_to_bool()");

    // Test passing undefined values to subscripts/functions
    check_ok("not defined tests.undefined()");
    check_ok("not defined tests.isum(tests.undefined())");
    check_ok("not defined tests.integer_array[tests.undefined()]");
    check_ok("not defined tests.lazy().str_array[tests.undefined()]");
    check_ok("not defined tests.lazy().isum(1, tests.undefined())");
}
