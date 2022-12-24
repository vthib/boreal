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
