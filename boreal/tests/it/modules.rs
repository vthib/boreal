use crate::utils::{check, check_boreal, check_err};

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
    check_ok("not defined tests.undefined_str()");
    check_ok("not defined tests.undefined_int()");
    check_ok("not defined tests.length(tests.undefined_str())");
    check_ok("not defined tests.integer_array[tests.undefined_int()]");
    check_ok("not defined tests.lazy().str_array[tests.undefined_int()]");
    check_ok("not defined tests.lazy().isum(1, tests.undefined_int())");
}

#[test]
fn test_functions() {
    #[track_caller]
    fn check_invalid_args(condition: &str, expected_err: &str) {
        check_err(
            &format!(
                r#"import "tests"
rule foo {{
    condition: {}
}}"#,
                condition
            ),
            expected_err,
        );
    }

    // Check direct primitives
    check_invalid_args(
        "tests.lazy(3).constants.one",
        "mem:3:26: error: invalid arguments types: [integer]",
    );
    check_ok("tests.lazy().one");

    check_invalid_args(
        "tests.match()",
        "mem:3:27: error: invalid arguments types: []",
    );
    check_invalid_args(
        "tests.match(\"a\")",
        "mem:3:27: error: invalid arguments types: [string]",
    );
    check_invalid_args(
        "tests.match(\"a\", true)",
        "mem:3:27: error: invalid arguments types: [string, boolean]",
    );
    check_ok("tests.match(\"a\", /a/)");

    check_invalid_args(
        "tests.isum(2)",
        "mem:3:26: error: invalid arguments types: [integer]",
    );
    check_invalid_args(
        "tests.isum(2, 3.5)",
        "mem:3:26: error: invalid arguments types: [integer, floating-point number]",
    );
    check_invalid_args(
        "tests.isum(2, 3, 4, 5)",
        "mem:3:26: error: invalid arguments types: [integer, integer, integer, integer]",
    );
    check_ok("tests.isum(2, 3) == 5");
    check_ok("tests.isum(2, 3, -2) == 3");

    check_invalid_args(
        "tests.fsum(2, 3)",
        "mem:3:26: error: invalid arguments types: [integer, integer]",
    );
    check_invalid_args(
        "tests.fsum(2.5, 3)",
        "mem:3:26: error: invalid arguments types: [floating-point number, integer]",
    );
    check_ok("tests.fsum(2.5, 3.5) == 6.0");
    check_invalid_args(
        "tests.fsum(2.5, 3.5, false)",
        "mem:3:26: error: invalid arguments types: [floating-point number, floating-point number, boolean]",
    );
    check_ok("tests.fsum(2.5, 3.5, 1) == 7.0");

    check_invalid_args(
        "tests.empty(3)",
        "mem:3:27: error: invalid arguments types: [integer]",
    );
    check_ok("tests.empty() == \"\"");

    check_invalid_args(
        "tests.log()",
        "mem:3:25: error: invalid arguments types: []",
    );
    check_ok("tests.log(3)");
    check_invalid_args(
        "tests.log(/a/)",
        "mem:3:25: error: invalid arguments types: [regex]",
    );
    check_ok("tests.log(true, /a/, \"b\")");
    check_ok("tests.log(true, /a/)");
    check_ok("tests.log(3, true)");
}
