use crate::utils::Compiler;

#[test]
fn test_reuse_of_imports() {
    // An import is reused in the same namespace
    let mut compiler = Compiler::new();
    compiler.add_rules(
        r#"
import "tests"
rule bar { condition: tests.constants.one == 1 }"#,
    );
    compiler.add_rules(
        r#"
rule foo { condition: tests.constants.two == 2 }"#,
    );
    let checker = compiler.into_checker();
    checker.check_count(b"", 2);

    let mut compiler = Compiler::new();
    compiler.add_rules_in_namespace(
        r#"
import "tests"
rule bar { condition: tests.constants.one == 1 }"#,
        "ns1",
    );
    compiler.add_rules_in_namespace(
        r#"
rule foo { condition: tests.constants.two == 2 }"#,
        "ns1",
    );
    let checker = compiler.into_checker();
    checker.check_count(b"", 2);

    // But importing in one namespace does not bring it in others
    let mut compiler = Compiler::new();
    compiler.add_rules_in_namespace(
        r#"
import "tests"
rule bar { condition: tests.constants.one == 1 }"#,
        "ns1",
    );
    compiler.check_add_rules_err(
        r#"rule foo { condition: tests.constants.two == 2 }"#,
        "mem:1:23: error: unknown identifier \"tests\"",
    );
}
