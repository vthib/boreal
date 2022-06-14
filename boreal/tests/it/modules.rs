use crate::utils::{check, check_boreal, check_err};

#[track_caller]
fn check_tests_err(condition: &str, expected_err: &str) {
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

    check_err(
        r#"
rule foo { condition: tests.constants.one == 1 }
import "tests"
rule bar { condition: tests.constants.one == 1 }
"#,
        "mem:2:23: error: unknown identifier \"tests\"",
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
    // Wrong operations on the initial value
    check_tests_err("tests > 0", "mem:3:16: error: wrong use of identifier");
    check_tests_err("tests[2] > 0", "mem:3:16: error: invalid identifier type");
    check_tests_err("tests() > 0", "mem:3:16: error: invalid identifier type");

    // Field not existing in an object
    check_tests_err(
        "tests.do_not_exist",
        "mem:3:21: error: unknown field \"do_not_exist\"",
    );

    // Using array syntax on an object, scalar and function
    check_tests_err(
        "tests.constants[0]",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err(
        "tests.constants.one[0]",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err("tests.isum[0]", "mem:3:16: error: invalid identifier type");

    // Using object syntax on a array, dict, scalar and function
    check_tests_err(
        "tests.integer_array.foo",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err(
        "tests.integer_dict.foo",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err(
        "tests.constants.one_half.bar",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err("tests.isum.foo", "mem:3:16: error: invalid identifier type");

    // Using function call on object, dict, array and scalar
    check_tests_err(
        "tests.constants(5)",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err(
        "tests.integer_array()",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err(
        "tests.struct_array()",
        "mem:3:16: error: invalid identifier type",
    );
    check_tests_err(
        "tests.constants.regex(2, 3)",
        "mem:3:16: error: invalid identifier type",
    );

    // Cannot use compound values as expressions
    check_tests_err(
        "tests.constants > 0",
        "mem:3:16: error: wrong use of identifier",
    );
    check_tests_err(
        "tests.string_array > 0",
        "mem:3:16: error: wrong use of identifier",
    );
    check_tests_err(
        "tests.string_dict > 0",
        "mem:3:16: error: wrong use of identifier",
    );
    check_tests_err("tests.isum > 0", "mem:3:16: error: wrong use of identifier");

    // Array subscript must be an integer
    check_tests_err(
        "tests.integer_array[/a/] > 0",
        "mem:3:36: error: expected an expression of type integer",
    );

    // Dict subscript must be a string
    check_tests_err(
        "tests.integer_dict[/a/] > 0",
        "mem:3:35: error: expected an expression of type bytes",
    );

    // Subscript on array/subscript must be the right type
    check_tests_err(
        "tests.integer_array[\"a\"] > 0",
        "mem:3:36: error: expected an expression of type integer",
    );
    check_tests_err(
        "tests.integer_dict[5] > 0",
        "mem:3:35: error: expected an expression of type bytes",
    );
}

#[test]
fn test_value_wrong_type() {
    #[track_caller]
    fn check_invalid_types(condition: &str) {
        check_tests_err(condition, "error: expressions have invalid types");
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

    // Check array eval
    check_ok("tests.integer_array[0] == 0");
    check_ok("tests.integer_array[1] == 1");
    check_ok("tests.struct_array[1].i == 1");
    check_ok("not defined tests.struct_array[1].s");
    check_ok("not defined tests.struct_array[2].i");
    check_ok("not defined tests.integer_array[3]");
    check_ok("not defined tests.integer_array[#a - 1]");

    // Check dict eval
    check_ok("tests.integer_dict[\"foo\"] == 1");
    check_ok("tests.integer_dict[\"bar\"] == 2");
    check_ok("tests.string_dict[\"bar\"] == \"bar\"");
    check_ok("tests.struct_dict[\"foo\"].i == 1");
    check_ok("not defined tests.integer_dict[\"\"]");

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
    check_ok("tests.lazy().string_dict[\"foo\"] == \"foo\"");
    check_ok("not defined tests.lazy().str_array[10]");
    check_ok("not defined tests.lazy().str_array[#a - 5]");

    // Multiple lazy calls
    check_ok("tests.lazy().lazy().lazy_int() == 3");

    // Test discrepancies between declared type, and returned type.
    check_ok("not defined tests.lazy().dict.oops");
    check_ok("not defined tests.lazy().fake_bool_to_array");
    check_ok("not defined tests.lazy().fake_bool_to_dict");
    check_ok("not defined tests.lazy().fake_bool_to_fun");
    check_ok("not defined tests.lazy().fake_dict_to_bool.i");
    check_ok("not defined tests.lazy().fake_array_to_bool[2]");
    check_ok("not defined tests.lazy().fake_fun_to_bool()");

    // Test passing undefined values to subscripts/functions
    check_ok("not defined tests.undefined_str");
    check_ok("not defined tests.undefined_int");
    check_ok("not defined tests.length(tests.undefined_str)");
    check_ok("not defined tests.integer_array[tests.undefined_int]");
    check_ok("not defined tests.integer_dict[tests.undefined_str]");
    check_ok("not defined tests.lazy().str_array[tests.undefined_int]");
    check_ok("not defined tests.lazy().isum(1, tests.undefined_int)");
}

#[test]
fn test_functions() {
    // Check direct primitives
    check_tests_err(
        "tests.lazy(3).constants.one",
        "mem:3:26: error: invalid arguments types: [integer]",
    );
    check_ok("tests.lazy().one");

    check_tests_err(
        "tests.match()",
        "mem:3:27: error: invalid arguments types: []",
    );
    check_tests_err(
        "tests.match(\"a\")",
        "mem:3:27: error: invalid arguments types: [bytes]",
    );
    check_tests_err(
        "tests.match(/a/, true)",
        "mem:3:27: error: invalid arguments types: [regex, boolean]",
    );
    check_ok("tests.match(/a/, \"a\")");

    check_tests_err(
        "tests.isum(2)",
        "mem:3:26: error: invalid arguments types: [integer]",
    );
    check_tests_err(
        "tests.isum(2, 3.5)",
        "mem:3:26: error: invalid arguments types: [integer, floating-point number]",
    );
    check_tests_err(
        "tests.isum(2, 3, 4, 5)",
        "mem:3:26: error: invalid arguments types: [integer, integer, integer, integer]",
    );
    check_ok("tests.isum(2, 3) == 5");
    check_ok("tests.isum(2, 3, -2) == 3");

    check_tests_err(
        "tests.fsum(2, 3)",
        "mem:3:26: error: invalid arguments types: [integer, integer]",
    );
    check_tests_err(
        "tests.fsum(2.5, 3)",
        "mem:3:26: error: invalid arguments types: [floating-point number, integer]",
    );
    check_ok("tests.fsum(2.5, 3.5) == 6.0");
    check_tests_err(
        "tests.fsum(2.5, 3.5, false)",
        "mem:3:26: error: invalid arguments types: [floating-point number, floating-point number, boolean]",
    );
    check_ok("tests.fsum(2.5, 3.5, 1.0) == 7.0");

    check_tests_err(
        "tests.empty(3)",
        "mem:3:27: error: invalid arguments types: [integer]",
    );
    check_ok("tests.empty() == \"\"");

    check_tests_err(
        "tests.log()",
        "mem:3:25: error: invalid arguments types: []",
    );
    check_ok("tests.log(3)");
    check_tests_err(
        "tests.log(/a/)",
        "mem:3:25: error: invalid arguments types: [regex]",
    );
    check_ok("tests.log(true, /a/, \"b\")");
    check_ok("tests.log(true, /a/)");
    check_ok("tests.log(3, true)");
}

#[test]
fn test_module_time() {
    check(
        "import \"time\"
rule a {
    condition: time.now() > 0
}",
        b"",
        true,
    );
}

#[test]
#[cfg(feature = "hash")]
fn test_module_hash() {
    #[track_caller]
    fn test(cond: &str) {
        check(
            &format!(
                "import \"hash\"
    rule a {{
        condition: {}
    }}",
                cond
            ),
            b"gabuzomeu",
            true,
        )
    }

    test("hash.md5(0, 500) == \"ecac3b377a507fec74b2f4c512ed9554\"");
    test("hash.md5(0, filesize) == hash.md5(\"gabuzomeu\")");
    test("hash.md5(2, 9) == \"7b73eda4ba472912fff88c5e6b7ea103\"");
    test("hash.md5(0, 8) == \"aca342eca8df22ac40b939b15095950f\"");
    test("hash.md5(0, 0) == \"d41d8cd98f00b204e9800998ecf8427e\"");
    test("not defined hash.md5(0, -1)");
    test("not defined hash.md5(-1, 0)");
    test("not defined hash.md5(100, 2)");

    test("hash.sha1(0, 500) == \"86cfb1983fb9daaabbd865e16dc3f9870fe76474\"");
    test("hash.sha1(0, filesize) == hash.sha1(\"gabuzomeu\")");
    test("hash.sha1(2, 9) == \"57bbcd8d2706dc88dd5831efa7cfe11e92ae3f3a\"");
    test("hash.sha1(0, 8) == \"634d0c2b932e8f7f68ad56cc42c590e1052a6491\"");
    test("hash.sha1(0, 0) == \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"");
    test("not defined hash.sha1(0, -1)");
    test("not defined hash.sha1(-1, 0)");
    test("not defined hash.sha1(100, 2)");

    test(
        "hash.sha256(0, 500) == \"f94ba43d9d5949c608563293761495e2f0335fbffba1a05760d1ae609d061fc0\"",
    );
    test("hash.sha256(0, filesize) == hash.sha256(\"gabuzomeu\")");
    test(
        "hash.sha256(2, 9) == \"3e3cb308199e801415e4991209043f40bde2352f5bc61625b137e1cd6c51fd3e\"",
    );
    test(
        "hash.sha256(0, 8) == \"d89026b06cb9d69a9185096cf6f67d700d860c4c49a17922399221165ff051b8\"",
    );
    test(
        "hash.sha256(0, 0) == \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
    test("not defined hash.sha256(0, -1)");
    test("not defined hash.sha256(-1, 0)");
    test("not defined hash.sha256(100, 2)");

    test("hash.checksum32(0, 500) == 975");
    test("hash.checksum32(0, 500) == hash.checksum32(\"gabuzomeu\")");
    test("hash.checksum32(2, 9) == 775");
    test("hash.checksum32(0, 8) == 858");
    test("not defined hash.checksum32(0, -1)");
    test("not defined hash.checksum32(-1, 0)");
    test("not defined hash.checksum32(100, 2)");

    test("hash.crc32(0, 500) == 759284801");
    test("hash.crc32(0, 500) == hash.crc32(\"gabuzomeu\")");
    test("hash.crc32(2, 9) == 1919370201");
    test("hash.crc32(0, 8) == 1279376556");
    test("not defined hash.crc32(0, -1)");
    test("not defined hash.crc32(-1, 0)");
    test("not defined hash.crc32(100, 2)");
}
