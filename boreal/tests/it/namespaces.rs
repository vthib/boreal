use crate::utils::new_compiler;

#[test]
fn test_reuse_of_imports() {
    let mut compiler = new_compiler();

    compiler
        .add_rules_from_str(
            r#"
import "tests"
rule bar { condition: tests.constants.one == 1 }
"#,
        )
        .unwrap();

    // This one reuses imported modes in the namespace
    compiler
        .add_rules_from_str(
            r#"
rule foo { condition: tests.constants.two == 2 }
"#,
        )
        .unwrap();

    let scanner = compiler.into_scanner();
    assert_eq!(scanner.scan_mem(b"").matching_rules.len(), 2);
}
