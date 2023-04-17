use std::time::Duration;

use boreal::scanner::ScanParams;

use crate::utils::{Checker, Compiler};

#[test]
fn test_limit_match_max_length() {
    let rule = r#"
rule a {
    strings:
        $r1 = /ba+b/
    condition:
        any of them
}
"#;

    let mut full_text: Vec<_> = Vec::new();
    full_text.push(b'b');
    full_text.extend(std::iter::repeat(b'a').take(1024));
    full_text.push(b'b');

    let checker = Checker::new(rule);
    checker.check_full_matches(
        &full_text,
        vec![
            // r1 match but is trimmed to 512 chars
            (
                "default:a".to_owned(),
                vec![("r1", vec![(&full_text[0..512], 0, 1026)])],
            ),
        ],
    );

    let mut checker = Checker::new_without_yara(rule);
    checker.set_scan_params(ScanParams::default().match_max_length(100_000));
    checker.check_full_matches(
        &full_text,
        vec![
            // r1 match but is trimmed to 512 chars
            (
                "default:a".to_owned(),
                vec![("r1", vec![(&full_text, 0, 1026)])],
            ),
        ],
    );
}

#[test]
fn test_limit_string_max_nb_matches() {
    let mem: Vec<_> = std::iter::repeat(0).take(1_100_000).collect();

    // Default for boreal is limited to 1_000
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { 00 }
    condition:
        #a == 1000
}
"#,
    );
    checker.check_boreal(&mem, true);

    // For YARA this is 1_000_000, but it exhibits the same behavior.
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { 00 }
    condition:
        #a == 1000000
}
"#,
    );
    checker.set_scan_params(ScanParams::default().string_max_nb_matches(1_000_000));
    checker.check(&mem, true);

    // Do this with a non-atomizable regex, to check the limit is also done outside of the ac scan
    // pass.
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = { ?? }
    condition:
        #a == 1000
}
"#,
    );
    checker.check_boreal(&mem, true);
}

#[test]
fn test_limit_max_condition_depth() {
    let max_depth = 15;
    let params = boreal::compiler::CompilerParams::default().max_condition_depth(max_depth);

    let mut rule = String::new();
    rule.push_str(
        r#"
import "math"

rule a {
  condition:
"#,
    );

    // We need an expression that does not trigger the recursion limit during parsing,
    // but still has enough depth. This means stacking different operations.
    for _ in 0..=(max_depth / 10) {
        rule.push_str("    true and not 6 <= 5 | 4 & 3 >> 2 + 1 * -math.to_number(\n");
    }
    rule.push_str("    true\n");
    for _ in 0..=(max_depth / 10) {
        rule.push_str("    )\n");
    }
    rule.push('}');

    let mut compiler = Compiler::new_without_yara();
    // Bring the limit down from the default, as the default is still too high in debug mode.
    // This allows running this test (and thus the whole test suite) in debug mode.
    compiler.set_params(params.clone());
    compiler.check_add_rules_err(
        &rule,
        "mem:7:23: error: condition is too complex and reached max depth",
    );

    let mut compiler = Compiler::new_without_yara();
    compiler.set_params(params.max_condition_depth(max_depth + 10));
    compiler.add_rules(&rule);
}

#[test]
fn test_timeout_eval_rule_without_matches() {
    let params = ScanParams::default().timeout_duration(Some(Duration::from_millis(100)));
    let infinite_cond = r#"
for all i in (0..9223372036854775807) : (
    for all j in (0..9223372036854775807) : (
        for all k in (0..9223372036854775807) : (
            for all l in (0..9223372036854775807) : (
                i + j + k + l >= 0
            )
        )
    )
)"#;

    // Rule that takes too long while evaluating without variables
    let mut checker = Checker::new_without_yara(&format!(
        "
rule a {{
    condition: {infinite_cond}
}}"
    ));
    checker.set_scan_params(params.clone());
    let res = checker.check_rule_matches(b"", &[]);
    assert!(res.timeout);

    // Same with global rule
    let mut checker = Checker::new_without_yara(&format!(
        "
global rule a {{
    condition: {infinite_cond}
}}"
    ));
    checker.set_scan_params(params);
    let res = checker.check_rule_matches(b"", &[]);
    assert!(res.timeout);
}

#[test]
fn test_timeout_eval_rule() {
    let params = ScanParams::default().timeout_duration(Some(Duration::from_millis(100)));
    let infinite_cond = r#"
for all i in (#var..9223372036854775807) : (
    for all j in (0..9223372036854775807) : (
        for all k in (0..9223372036854775807) : (
            for all l in (0..9223372036854775807) : (
                i + j + k + l >= 0
            )
        )
    )
)"#;

    // Global rule that takes too long
    let mut compiler = Compiler::new_without_yara();
    compiler.add_rules(
        r#"
global rule first {
    strings:
        $a = "aaa"
    condition:
        $a
}"#,
    );
    compiler.add_rules(&format!(
        r#"
global rule second {{
    strings:
        $var = "var"
    condition:
        {infinite_cond}
}}"#,
    ));
    let mut checker = compiler.into_checker();
    checker.set_scan_params(params.clone());
    let res = checker.check_rule_matches(b"aaa", &["default:first"]);
    assert!(res.timeout);

    // Normal rule that takes too long
    let mut compiler = Compiler::new_without_yara();
    compiler.add_rules(
        r#"
global rule first {
    strings:
        $a = "aaa"
    condition:
        $a
}

rule second { condition: true }
"#,
    );
    compiler.add_rules(&format!(
        r#"
rule third {{
    strings:
        $var = "var"
    condition:
        {infinite_cond}
}}"#,
    ));
    compiler.add_rules(
        r#"
rule fourth { condition: true }
"#,
    );
    let mut checker = compiler.into_checker();
    checker.set_scan_params(params);
    let res = checker.check_rule_matches(b"aaa", &["default:first", "default:second"]);
    assert!(res.timeout);
}

#[test]
fn test_timeout_eval_ac_matches() {
    let infinite_match_rule = r#"
    strings:
        $a = { 00 00 [0-] 00 }
        $c = { 00 00 [1-] 00 }
        $d = { 00 00 [2-] 00 }
        $e = { 00 00 [3-] 00 }
    condition:
        all of them
"#;

    let mut compiler = Compiler::new_without_yara();
    compiler.add_rules(
        r#"
rule first {
    condition: true
}"#,
    );
    compiler.add_rules(&format!(
        r#"
rule second {{
    {infinite_match_rule}
}}"#,
    ));

    let mut checker = compiler.into_checker();
    checker
        .set_scan_params(ScanParams::default().timeout_duration(Some(Duration::from_millis(100))));

    let mem = vec![0; 10 * 1024 * 1024];
    let res = checker.check_rule_matches(&mem, &[]);
    assert!(res.timeout);
}

#[test]
fn test_max_split_match_length_hex_string() {
    // Turns out yara works fine for the commented string.
    // TODO: investigate why
    let checker = Checker::new(
        r#"
rule a {
    strings:
        // $a = { AA [1-] BB CC DD EE [1-] FF }
        $a = { AA ?? [1-] BB CC DD EE [1-] ?? FF }
    condition:
        any of them
}
"#,
    );

    // A normal sized string will match
    checker.check(b"        \xAA   \xBB\xCC\xDD\xEE   \xFF   ", true);

    // If the \xFF is too far, it won't match.
    let mut mem = Vec::new();
    mem.extend(b"\xAA \xBB\xCC\xDD\xEE");
    mem.resize(5_000, 0);
    mem.push(b'\xFF');
    // checker.check(&mem, false);

    // If the \xFF is too far, it won't match.
    let mut mem = Vec::new();
    mem.push(b'\xAA');
    mem.resize(5_000, 0);
    mem.extend(b"\xBB\xCC\xDD\xEE \xFF");
    checker.check(&mem, false);
}

#[test]
fn test_max_split_match_length_regex() {
    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /a[^r]*?string/
    condition:
        any of them
}
"#,
    );

    // A normal sized string will match
    checker.check(b"abcvlkjstring", true);

    // If the \xFF is too far, it won't match.
    let mut mem = Vec::new();
    mem.push(b'a');
    mem.resize(5_000, 0);
    mem.extend(b"string");
    checker.check(&mem, false);

    let checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /string[^r]*?a/
    condition:
        any of them
}
"#,
    );

    // A normal sized string will match
    checker.check(b"stringmflgkdopa", true);

    // If the \xFF is too far, it won't match.
    let mut mem = Vec::new();
    mem.extend(b"string");
    mem.resize(5_000, 0);
    mem.push(b'a');
    checker.check(&mem, false);
}
