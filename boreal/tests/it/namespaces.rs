use crate::utils::new_compiler;

#[test]
fn test_reuse_of_imports() {
    let mut compiler = new_compiler();

    compiler
        .add_rules_str(
            r#"
import "tests"
rule bar { condition: tests.constants.one == 1 }
"#,
        )
        .unwrap();

    // This one reuses imported modes in the namespace
    compiler
        .add_rules_str(
            r#"
rule foo { condition: tests.constants.two == 2 }
"#,
        )
        .unwrap();

    // Adding in a new namespace loses the import
    compiler
        .add_rules_str_in_namespace(
            r#"
rule foo { condition: tests.constants.two == 2 }
"#,
            "namespace",
        )
        .unwrap_err();

    let scanner = compiler.into_scanner();
    assert_eq!(scanner.scan_mem(b"").matching_rules.len(), 2);
}
