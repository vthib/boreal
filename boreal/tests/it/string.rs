use crate::utils::{check, check_err};

fn make_rule(cond: &str) -> String {
    format!(
        r#"
import "string"

rule test {{
    condition: {cond}
}}"#,
    )
}

#[track_caller]
fn test(cond: &str) {
    check(&make_rule(cond), b"", true);
}

#[track_caller]
fn test_err(cond: &str, expected_err: &str) {
    check_err(&make_rule(cond), expected_err);
}

#[test]
fn test_string_to_int() {
    test(r#"string.to_int("0") == 0"#);
    test(r#"string.to_int("-0") == 0"#);
    test(r#"string.to_int("+0") == 0"#);
    test(r#"string.to_int("1287") == 1287"#);
    test(r#"string.to_int("1287", 10) == 1287"#);
    test(r#"string.to_int("1287", 16) == 4743"#);
    test(r#"string.to_int("1287", 9) == 970"#);
    test(r#"string.to_int("-1287") == -1287"#);
    test(r#"string.to_int("-1287", 10) == -1287"#);
    test(r#"string.to_int("-1287", 16) == -4743"#);
    test(r#"string.to_int("-1287", 9) == -970"#);
    test(r#"string.to_int("+1287") == 1287"#);
    test(r#"string.to_int("+1287", 10) == 1287"#);
    test(r#"string.to_int("+1287", 16) == 4743"#);
    test(r#"string.to_int("+1287", 9) == 970"#);

    test(r#"string.to_int("9223372036854775807") == 9223372036854775807"#);
    test(r#"string.to_int("-9223372036854775808") == -9223372036854775807 - 1"#);

    // parsing with radix 0 gives special meaning to 0x or 0 prefix
    test(r#"string.to_int("0xFC") == 252"#);
    test(r#"string.to_int("0XFC") == 252"#);
    test(r#"string.to_int("-0xFC") == -252"#);
    test(r#"string.to_int("-0Xfc") == -252"#);
    test(r#"string.to_int("0255") == 173"#);
    test(r#"string.to_int("0255", 0) == 173"#);
    test(r#"string.to_int("0255", 10) == 255"#);
    test(r#"string.to_int("-0255") == -173"#);
    test(r#"string.to_int("-0255", 0) == -173"#);
    test(r#"string.to_int("-0255", 10) == -255"#);
    // "0" without anything acts as the number, and not the octal prefix...
    test(r#"string.to_int("0") == 0"#);
    test(r#"string.to_int("0", 0) == 0"#);
    test(r#"string.to_int("0", 10) == 0"#);
    test(r#"string.to_int("-0") == 0"#);
    test(r#"string.to_int("-0", 0) == 0"#);
    test(r#"string.to_int("-0", 10) == 0"#);
    test(r#"string.to_int("0") == 0"#);
    test(r#"string.to_int("0", 0) == 0"#);
    test(r#"string.to_int("0", 10) == 0"#);
    test(r#"string.to_int("0p", 30) == 25"#);

    // parsing trims early whitespaces
    test(r#"string.to_int("   12") == 12"#);
    test("string.to_int(\"\t+12\") == 12");
    test(r#"string.to_int(" \n\x0a\t\r\x0C-12") == -12"#);

    // Test undefined error cases

    // trailing chars
    test(r#"not defined string.to_int("ABC")"#);
    test(r#"not defined string.to_int("123 ", 11)"#);

    test(r#"not defined string.to_int("1ff3")"#);
    test(r#"string.to_int("1ff3", 16) == 8179"#);
    test(r#"not defined string.to_int("1ff3g", 16)"#);
    test(r#"not defined string.to_int("-1ff3")"#);
    test(r#"string.to_int("-1ff3", 16) == -8179"#);
    test(r#"not defined string.to_int("-1ff3g", 16)"#);
    test(r#"not defined string.to_int("+1ff3")"#);
    test(r#"string.to_int("+1ff3", 16) == 8179"#);
    test(r#"not defined string.to_int("+1ff3g", 16)"#);

    // invalid base
    test(r#"not defined string.to_int("1", -1)"#);
    test(r#"not defined string.to_int("1", 1)"#);
    test(r#"not defined string.to_int("1", 37)"#);
    // empty string
    test(r#"not defined string.to_int("")"#);
    // empty after sign
    test(r#"not defined string.to_int("   -")"#);
    test(r#"not defined string.to_int("   +")"#);
    // empty after prefix in radix 0
    test(r#"not defined string.to_int("   -0x")"#);
    test(r#"not defined string.to_int("   +0X")"#);
    test(r#"not defined string.to_int("   0X")"#);
    test(r#"not defined string.to_int("   0x")"#);
    // empty on invalid char
    test(r#"not defined string.to_int(" p")"#);
    test(r#"not defined string.to_int(" +p")"#);
    test(r#"not defined string.to_int(" -p")"#);

    test(r#"not defined string.to_int("1\xFF")"#);

    // overflow
    test(r#"not defined string.to_int("9223372036854775808")"#);
    test(r#"not defined string.to_int("92233720368547758050")"#);
    test(r#"not defined string.to_int("-9223372036854775809")"#);

    test_err(
        "string.to_int(5)",
        "mem:5:29: error: invalid arguments types: [integer]",
    );
}

#[test]
fn test_string_length() {
    test(r#"string.length("") == 0"#);
    test(r#"string.length("a\xFF\tz") == 4"#);
    test(r#"string.length("é") == 2"#);

    test_err(
        "string.length(5)",
        "mem:5:29: error: invalid arguments types: [integer]",
    );
}
