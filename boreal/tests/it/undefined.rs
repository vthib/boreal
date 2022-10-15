/// Test handling of "undefined" value on all operators
use crate::utils::{build_rule, check, check_boreal};

// Expression used to get an undefined value
const UNDEF_INT: &str = "tests.integer_array[5]";
const UNDEF_STR: &str = "tests.string_array[5]";

fn assert_is_defined(cond: &str, expected_res: bool) {
    check(
        &build_rule(&format!("defined ({})", cond)),
        b"abcd",
        expected_res,
    );
}

fn assert_is_defined_boreal(cond: &str, expected_res: bool) {
    check_boreal(
        &build_rule(&format!("defined ({})", cond)),
        b"abcd",
        expected_res,
    );
}

#[test]
fn test_undefined_read_integer() {
    // propagate undefined value from inner expr
    assert_is_defined(&format!("uint8({})", UNDEF_INT), false);
    // emit undefined if inner value is negative
    assert_is_defined("uint8(-1)", false);
    // emit undefined if offset is out of bounds
    assert_is_defined("uint8(500)", false);
    // emit undefined if offset is in bounds, but size makes it out of bounds
    assert_is_defined("uint16(2)", true);
    assert_is_defined("uint16(3)", false);
    assert_is_defined("uint32(0)", true);
    assert_is_defined("uint32(1)", false);
    assert_is_defined("uint32be(1)", false);

    assert_is_defined("uint8(0)", true);
}

#[test]
fn test_undefined_count_in_range() {
    // propagate undefined value from inner exprs
    assert_is_defined(&format!("#a0 in (0..{})", UNDEF_INT), false);
    assert_is_defined(&format!("#a0 in ({}..5)", UNDEF_INT), false);

    // emit undefined if values are not positive
    // TODO(4.3): bug in libyara 4.2, returns internal error, fixed in 4.3
    assert_is_defined_boreal("#a0 in ((#a1 - 1)..5)", false);
    assert_is_defined_boreal("#a0 in (0..(#a1 - 1))", false);

    // emit undefined if from > to
    assert_is_defined_boreal("#a0 in (5..(4 + #a1))", false);
}

#[test]
fn test_undefined_offset_length() {
    // propagate undefined value from inner expr
    assert_is_defined(&format!("@a0[{}]", UNDEF_INT), false);
    assert_is_defined(&format!("!a0[{}]", UNDEF_INT), false);

    // emit undefined if values are not > 0
    assert_is_defined("@a0[#a1 - 1]", false);
    assert_is_defined("!a0[#a1 - 1]", false);
    assert_is_defined("@a0[#a1]", false);
    assert_is_defined("!a0[#a1]", false);
}

#[test]
fn test_undefined_arith_op() {
    // propagate undefined value from inner exprs
    assert_is_defined(&format!("-{}", UNDEF_INT), false);
    assert_is_defined(&format!("1 + {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} + 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 - {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} - 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 * {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} * 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 \\ {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} \\ 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 % {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} % 1", UNDEF_INT), false);

    // For div and mod, undefined on div by zero or overflow
    // TODO: report this issue on libyara
    assert_is_defined_boreal("1 \\ #a0", false);
    assert_is_defined_boreal("1 % #a0", false);
    assert_is_defined_boreal("(#a0 + -0x7FFFFFFFFFFFFFFF - 1) \\ -1", false);
    assert_is_defined_boreal("(#a0 + -0x7FFFFFFFFFFFFFFF - 1) % -1", false);
}

#[test]
fn test_undefined_bitwise_op() {
    // propagate undefined value from inner exprs
    assert_is_defined(&format!("1 ^ {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} ^ 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 & {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} & 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 | {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} | 1", UNDEF_INT), false);
    assert_is_defined(&format!("~{}", UNDEF_INT), false);
}

#[test]
fn test_undefined_bitwise_shifts() {
    // propagate undefined value from inner exprs
    assert_is_defined(&format!("1 << {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} << 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 >> {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} >> 1", UNDEF_INT), false);

    // emit undefined if shift value is negative
    assert_is_defined("1 >> (-1 + #a0)", false);
    assert_is_defined("1 << (-1 + #a0)", false);
}

#[test]
fn test_undefined_cmp() {
    // propagate undefined value from inner exprs
    assert_is_defined(&format!("1 == {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} == 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 != {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} != 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 < {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} < 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 <= {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} <= 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 > {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} > 1", UNDEF_INT), false);
    assert_is_defined(&format!("1 >= {}", UNDEF_INT), false);
    assert_is_defined(&format!("{} >= 1", UNDEF_INT), false);
}

#[test]
fn test_undefined_string_cmp() {
    // propagate undefined value from inner exprs
    assert_is_defined(&format!("\"a\" contains {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} contains \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("\"a\" icontains {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} icontains \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("\"a\" startswith {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} startswith \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("\"a\" istartswith {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} istartswith \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("\"a\" endswith {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} endswith \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("\"a\" iendswith {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} iendswith \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("\"a\" iequals {}", UNDEF_STR), false);
    assert_is_defined(&format!("{} iequals \"a\"", UNDEF_STR), false);
    assert_is_defined(&format!("{} matches /a/", UNDEF_STR), false);
}

#[test]
fn test_undefined_not() {
    // propagate undefined value from inner expr
    assert_is_defined(&format!("not ({} matches /a/)", UNDEF_STR), false);
}

#[test]
fn test_undefined_var_at_in() {
    // For AT, it is not propagate the undefined value
    assert_is_defined(&format!("$a0 at {}", UNDEF_INT), true);
    // propagate undefined value from inner expr
    assert_is_defined(&format!("$a0 in ({}..5)", UNDEF_INT), false);
    assert_is_defined(&format!("$a0 in (0..{})", UNDEF_INT), false);

    // Invalid bounds gives a defined value, which is a bit weird.
    assert_is_defined("$a0 at (#a0 - 1)", true);
    assert_is_defined("$a0 in ((#a0 - 1)..5)", true);
    assert_is_defined("$a0 in (0..(#a0 - 1))", true);
    assert_is_defined("$a0 in (5..(4 + #a0))", true);
}

#[test]
fn test_for_expression_undefined() {
    assert_is_defined(&format!("{} of them", UNDEF_INT), true);
    assert_is_defined_boreal(&format!("{}% of them", UNDEF_INT), true);
    assert_is_defined(&format!("for {} of them: (true)", UNDEF_INT), true);

    assert_is_defined(&format!("for {} i in (0..1): (true)", UNDEF_INT), true);
    assert_is_defined(&format!("for all i in ({}..1): (true)", UNDEF_INT), true);
    assert_is_defined(&format!("for all i in (0..{}): (true)", UNDEF_INT), true);
    assert_is_defined(&format!("for all i in (0..{}): (true)", UNDEF_INT), true);
    assert_is_defined("for all i in (5..(4 + #a0)): (true)", true);

    assert_is_defined(&format!("for all i in ({}): (true)", UNDEF_INT), true);
    assert_is_defined(&format!("for all i in (1, {}): (true)", UNDEF_INT), true);

    assert_is_defined("for all i in tests.empty_struct_array: (true)", true);
}
