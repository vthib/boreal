use crate::utils::{check, check_boreal, check_err};

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
fn test_boreal(cond: &str) {
    check_boreal(&make_rule(cond), b"", true);
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

    // parsing stops at the first non valid char
    test(r#"string.to_int("1ff3") == 1"#);
    test(r#"string.to_int("1ff3", 16) == 8179"#);
    test(r#"string.to_int("1ff3g", 16) == 8179"#);
    test(r#"string.to_int("-1ff3") == -1"#);
    test(r#"string.to_int("-1ff3", 16) == -8179"#);
    test(r#"string.to_int("-1ff3g", 16) == -8179"#);
    test(r#"string.to_int("+1ff3") == 1"#);
    test(r#"string.to_int("+1ff3", 16) == 8179"#);
    test(r#"string.to_int("+1ff3g", 16) == 8179"#);

    // parsing trims early whitespaces
    test(r#"string.to_int("   12") == 12"#);
    test("string.to_int(\"\t+12\") == 12");
    test(r#"string.to_int(" \n\x0a\t\r\x0C-12") == -12"#);

    // Test undefined error cases

    // invalid base
    test(r#"not defined string.to_int("1", -1)"#);
    test(r#"not defined string.to_int("1", 1)"#);
    test(r#"not defined string.to_int("1", 37)"#);
    // empty string
    test(r#"not defined string.to_int("")"#);
    // empty after sign
    test(r#"not defined string.to_int("   -")"#);
    test(r#"not defined string.to_int("   +")"#);
    // empty on invalid char
    test(r#"not defined string.to_int(" p")"#);
    test(r#"not defined string.to_int(" +p")"#);
    test(r#"not defined string.to_int(" -p")"#);

    // FIXME: a non ascii byte string should be fine
    // test(r#"string.to_int("1\xFF") == 1"#);

    // overflow
    // TODO: libyara does not handle overflows nicely
    test_boreal(r#"not defined string.to_int("9223372036854775808")"#);
    test_boreal(r#"not defined string.to_int("92233720368547758050")"#);
    test_boreal(r#"not defined string.to_int("-9223372036854775809")"#);

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
