use crate::{
    libyara_compat::util::ELF32_MIPS_FILE,
    utils::{check, check_err},
};

fn make_rule(cond: &str) -> String {
    format!(
        r#"
import "math"

rule test {{
    condition: {cond}
}}"#
    )
}

#[track_caller]
fn test(cond: &str, input: &[u8]) {
    check(&make_rule(cond), input, true);
}

#[track_caller]
fn test_err(cond: &str, expected_err: &str) {
    check_err(&make_rule(cond), expected_err);
}

#[test]
fn test_math_in_range() {
    test("not math.in_range(-1.2, -0.5, 0.75)", b"");
    test("math.in_range(0.5, 0.5, 0.75)", b"");
    test("math.in_range(0.6, 0.5, 0.75)", b"");
    test("math.in_range(0.75, 0.5, 0.75)", b"");
    test("not math.in_range(1.0, 0.5, 0.75)", b"");
}

#[test]
fn test_math_max_min() {
    test("math.max(5, 6) == 6", b"");
    test("math.max(6, 6) == 6", b"");
    test("math.max(6, 5) == 6", b"");
    test("math.min(5, 6) == 5", b"");
    test("math.min(5, 5) == 5", b"");
    test("math.min(6, 5) == 5", b"");

    // Yes, this is "working as expected". libyara defines those operators as operating
    // on uint64 values, and if those values are negative, undefined is not returned, but values
    // are type casted to and from uint64
    test("math.max(7, -2) == -2", b"");
    test("math.min(7, -2) == 7", b"");
}

#[test]
fn test_math_to_number() {
    test("math.to_number(false) == 0", b"");
    test("math.to_number(true) == 1", b"");
    test_err(
        "math.to_number(1) == 0",
        "mem:5:30: error: invalid arguments types: [integer]",
    );
}

#[test]
fn test_math_abs() {
    test("math.abs(5) == 5", b"");
    test("math.abs(0) == 0", b"");
    test("math.abs(-2) == 2", b"");
    test_err(
        "math.abs(-1.2) == 1",
        "mem:5:24: error: invalid arguments types: [floating-point number]",
    );
}

#[test]
fn test_math_mean() {
    test(r#"math.mean("A") == 65"#, b"");
    test(r#"math.mean("AC") == 66"#, b"");
    test(r#"math.mean("5'%") == 43"#, b"");
    test(r#"math.mean("\x00\x00\x00\x00") == 0 "#, b"");
    test(r#"math.mean("0As5+!") == 59.5"#, b"");
    test(r#"math.mean("ABCDEFG") == 68.0"#, b"");
    test(
        "math.in_range(math.mean(0, 20000), 32.096, 32.097)",
        ELF32_MIPS_FILE,
    );
    test("math.mean(150, 250) == 28.864", ELF32_MIPS_FILE);

    // NAN
    test(r#"not defined math.mean("")"#, b"");

    test("not defined math.mean(-5, 2)", b"");
    test("not defined math.mean(2, -2)", b"");

    test_err(
        "math.mean(1) == 1",
        "mem:5:25: error: invalid arguments types: [integer]",
    );
}

#[test]
fn test_math_serial_correlation() {
    test(r#"math.serial_correlation("A") == -100000"#, b"");
    test(r#"math.serial_correlation("AC") == -1"#, b"");
    test(r#"math.serial_correlation("5'%") == -0.5"#, b"");
    test(
        r#"math.serial_correlation("\x00\x00\x00\x00") == -100000"#,
        b"",
    );
    test(
        r#"math.in_range(math.serial_correlation("0As5+!"), 0.17149, 0.17150)"#,
        b"",
    );
    test(r#"math.serial_correlation("ABCDEFG") == 0.25"#, b"");
    test(
        "math.in_range(math.serial_correlation(0, 20000), 0.45982, 0.45983)",
        ELF32_MIPS_FILE,
    );
    test(
        "math.in_range(math.serial_correlation(150, 250), 0.12753, 0.12754)",
        ELF32_MIPS_FILE,
    );

    test(r#"math.serial_correlation("") == -100000"#, b"");

    test("not defined math.serial_correlation(-5, 2)", b"");
    test("not defined math.serial_correlation(2, -2)", b"");

    test_err(
        "math.serial_correlation(1) == 1",
        "mem:5:39: error: invalid arguments types: [integer]",
    );
}

#[test]
fn test_math_monte_carlo_pi() {
    test(r#"not defined math.monte_carlo_pi("A")"#, b"");
    test(r#"not defined math.monte_carlo_pi("ABCDE")"#, b"");
    test(
        r#"math.in_range(math.monte_carlo_pi("ABCDEF"), 0.27323, 0.27324)"#,
        b"",
    );
    test(
        r#"math.in_range(math.monte_carlo_pi("5'%E^2ft93c:-"), 0.27323, 0.27324)"#,
        b"",
    );
    test(
        "math.in_range(math.monte_carlo_pi(0, 20000), 0.25693, 0.25694)",
        ELF32_MIPS_FILE,
    );
    test(
        "math.in_range(math.monte_carlo_pi(10, 530), 0.25877, 0.25878)",
        ELF32_MIPS_FILE,
    );

    test("not defined math.monte_carlo_pi(-5, 2)", b"");
    test("not defined math.monte_carlo_pi(2, -2)", b"");

    test_err(
        "math.monte_carlo_pi(1) == 1",
        "mem:5:35: error: invalid arguments types: [integer]",
    );
}

#[test]
fn test_math_entropy() {
    test(r#"math.entropy("") == 0"#, b"");
    test(r#"math.entropy("A") == 0"#, b"");
    test(r#"math.entropy("AC") == 1.0"#, b"");
    test(
        r#"math.in_range(math.entropy("5'%"), 1.58496, 1.58497)"#,
        b"",
    );
    test(r#"math.entropy("\x00\x00\x00\x00") == 0"#, b"");
    test(
        r#"math.in_range(math.entropy("0As5+!"), 2.58496, 2.58497)"#,
        b"",
    );
    test(
        r#"math.in_range(math.entropy("ABCDEFG"), 2.80735, 2.80736)"#,
        b"",
    );
    test(
        "math.in_range(math.entropy(0, 20000), 3.71766, 3.71767)",
        ELF32_MIPS_FILE,
    );
    test(
        "math.in_range(math.entropy(150, 250), 2.70690, 2.70691)",
        ELF32_MIPS_FILE,
    );

    test("not defined math.entropy(-5, 2)", b"");
    test("not defined math.entropy(2, -2)", b"");

    test_err(
        "math.entropy(1) == 1",
        "mem:5:28: error: invalid arguments types: [integer]",
    );
}

#[test]
fn test_math_deviation() {
    test(r#"not defined math.deviation("", 0.0)"#, b"");

    test(r#"math.deviation("A", 0.0) == 65.0"#, b"");
    test(r#"math.deviation("A", 65.0) == 0"#, b"");
    test(r#"math.deviation("A", 15.0) == 50"#, b"");

    test(r#"math.deviation("AC", 66.0) == 1.0"#, b"");
    test(r#"math.deviation("AC", math.mean("AC")) == 1.0"#, b"");
    test(r#"math.deviation("5'%", math.MEAN_BYTES) == 84.5"#, b"");

    test(
        "math.in_range(math.deviation(0, 20000, 0.0), 32.0969, 32.0970)",
        ELF32_MIPS_FILE,
    );
    test(
        "math.deviation(150, 250, math.MEAN_BYTES) == 109.056",
        ELF32_MIPS_FILE,
    );

    test("not defined math.deviation(-5, 2, 0.5)", b"");
    test("not defined math.deviation(2, -2, 0.5)", b"");

    test_err(
        "math.deviation(1, 0) == 1",
        "mem:5:30: error: invalid arguments types: [integer, integer]",
    );
}

#[test]
fn test_math_count() {
    test("math.count(0) == 0", b"");
    test("math.count(255) == 0", b"");
    test("math.count(65) == 3", b"ABCDEFABCDEFABCDEF");
    test("math.count(65, 5, 15) == 2", b"ABCDEFABCDEFABCDEF");
    test("math.count(65, 0, 1) == 1", b"ABCDEFABCDEFABCDEF");
    test("math.count(65, 1, 2) == 0", b"ABCDEFABCDEFABCDEF");

    test("math.count(0, 0, 20000) == 5441", ELF32_MIPS_FILE);
    test("math.count(0, 150, 250) == 158", ELF32_MIPS_FILE);
    test("math.count(115) == 112", ELF32_MIPS_FILE);

    // Value is casted to a u8
    test("math.count(-1) == 1", b"\xFF");
    test("math.count(258) == 1", b"\x02");

    test("not defined math.count(0, -1, 5)", b"");
    test("not defined math.count(0, 0, -2)", b"");
    test("not defined math.count(0, 1, 5)", b"");

    test_err(
        "math.count(0.2) == 1",
        "mem:5:26: error: invalid arguments types: [floating-point number]",
    );
}

#[test]
fn test_math_percentage() {
    test("not defined math.percentage(0)", b"");
    test("math.percentage(0) == 0.0", b"A");
    test("math.percentage(0) == 1.0", b"\x00");
    test("math.percentage(48) == 0.125", b"01234567");

    test(
        "math.in_range(math.percentage(65), 0.16666, 0.16667)",
        b"ABCDEFABCDEFABCDEF",
    );
    test(
        "math.in_range(math.percentage(65, 5, 15), 0.15384, 0.15385)",
        b"ABCDEFABCDEFABCDEF",
    );
    test("math.percentage(65, 0, 1) == 1", b"ABCDEFABCDEFABCDEF");
    test("math.percentage(65, 1, 2) == 0", b"ABCDEFABCDEFABCDEF");

    test(
        "math.in_range(math.percentage(0, 0, 20000), 0.58031, 0.58032)",
        ELF32_MIPS_FILE,
    );
    test(
        "math.in_range(math.percentage(0, 150, 250), 0.6319, 0.6321)",
        ELF32_MIPS_FILE,
    );
    test(
        "math.in_range(math.percentage(115), 0.011945, 0.011946)",
        ELF32_MIPS_FILE,
    );

    test("not defined math.percentage(-1)", b"");
    test("not defined math.percentage(12345678)", b"");
    test("not defined math.percentage(0, -1, 5)", b"");
    test("not defined math.percentage(0, 0, -2)", b"");
    test("not defined math.percentage(0, 1, 5)", b"");

    test_err(
        "math.percentage(true) == 1",
        "mem:5:31: error: invalid arguments types: [boolean]",
    );
}

#[test]
fn test_math_mode() {
    test("math.mode() == 0", b"");
    test("math.mode() == 65", b"A");
    test("math.mode() == 48", b"01234567");

    test("math.mode() == 50", b"234523455432");
    test("math.mode(0, 10) == 52", b"234523455432");
    test("math.mode(0, 9) == 53", b"234523455432");
    test("math.mode(1, 4) == 50", b"234523455432");
    test("math.mode(1, 6) == 51", b"234523455432");

    test("math.mode() == 0", ELF32_MIPS_FILE);
    test("math.mode(5216, 160) == 45", ELF32_MIPS_FILE);

    test("not defined math.mode(-1, 5)", b"");
    test("not defined math.mode(0, -2)", b"");

    test_err(
        "math.mode(0.2, 1) == 1",
        "mem:5:25: error: invalid arguments types: [floating-point number, integer]",
    );
}

#[test]
fn test_math_to_string() {
    test(r#"math.to_string(28974917) == "28974917""#, b"");
    test(r#"math.to_string(28974917, 10) == "28974917""#, b"");
    test(r#"math.to_string(28974917, 16) == "1ba1f45""#, b"");
    test(r#"math.to_string(28974917, 8) == "156417505""#, b"");

    test(r#"math.to_string(-28974917) == "-28974917""#, b"");
    test(r#"math.to_string(-28974917, 10) == "-28974917""#, b"");
    test(
        r#"math.to_string(-28974917, 16) == "fffffffffe45e0bb""#,
        b"",
    );
    test(
        r#"math.to_string(-28974917, 8) == "1777777777777621360273""#,
        b"",
    );

    test("not defined math.to_string(5, 9)", b"");

    test_err(
        "math.to_string(/a/)",
        "mem:5:30: error: invalid arguments types: [regex]",
    );
}
