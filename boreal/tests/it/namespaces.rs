use crate::utils::Compiler;

// An import is reused in the same namespace
#[test]
fn test_reuse_of_imports() {
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

// Errors related to namespaces
#[test]
fn test_namespaces_errors() {
    // Rule name must be unique
    let mut compiler = Compiler::new();
    compiler.add_rules("rule a { condition: true }");
    compiler.check_add_rules_err(
        "rule a { condition: true }",
        "error: rule `a` is already declared in this namespace",
    );

    // Multiple rules can have the same name in different namespaces
    let mut compiler = Compiler::new();
    compiler.add_rules("rule a { condition: true }");
    compiler.add_rules_in_namespace("rule a { condition: true }", "ns1");
    compiler.add_rules_in_namespace("rule a { condition: true }", "ns2");
    let checker = compiler.into_checker();
    checker.check_count(b"", 3);

    // Cannot depend on itself
    // TODO: yara does not catch that!
    let compiler = Compiler::new_without_yara();
    compiler.check_add_rules_err(
        "rule a { condition: a }",
        "mem:1:21: error: unknown identifier \"a\"",
    );
}

// Dependencies on other rules in a given namespace
#[test]
fn test_rule_dependencies() {
    let mut compiler = Compiler::new();

    compiler.add_rules("rule a { strings: $a = /a/ condition: $a }");
    compiler.add_rules("rule b { strings: $b = /b/ condition: a and $b }");

    compiler.add_rules_in_namespace("rule a { strings: $c = /c/ condition: $c }", "ns1");
    compiler.add_rules_in_namespace("rule b { strings: $d = /d/ condition: a or $d }", "ns1");

    let checker = compiler.into_checker();
    checker.check_matches(b"", &[]);

    checker.check_matches(b"a", &["default:a"]);
    checker.check_matches(b"ab", &["default:a", "default:b"]);
    checker.check_matches(b"b", &[]);

    checker.check_matches(b"c", &["ns1:a", "ns1:b"]);
    checker.check_matches(b"cd", &["ns1:a", "ns1:b"]);
    checker.check_matches(b"d", &["ns1:b"]);
    checker.check_matches(b"bd", &["ns1:b"]);
}

// Test the identifier is resolved to the import first, then the rule names
#[test]
fn test_identifier_precedence() {
    // An identifier resolved to a rule, until an import shadows the rule.
    let mut compiler = Compiler::new();
    compiler.add_rules(
        r#"
rule tests { strings: $c = "tests" condition: $c }
rule a1 { condition: tests }
import "tests"
rule a2 { condition: tests.constants.one == 1 }
        "#,
    );
    compiler.add_rules(
        r#"
rule a3 { condition: tests.constants.two == 2 }
        "#,
    );

    // The opposite works: declaring a rule with the same name as an import is valid, but the rule
    // cannot be depended upon
    compiler.add_rules_in_namespace(
        r#"
import "tests"
rule tests { condition: tests.constants.one == 1 }
        "#,
        "nsa",
    );
    compiler.add_rules_in_namespace(
        r#"
rule b2 { condition: tests.constants.two == 2 }
        "#,
        "nsa",
    );

    let checker = compiler.into_checker();
    checker.check_matches(b"", &["default:a2", "default:a3", "nsa:tests", "nsa:b2"]);
    checker.check_matches(
        b"<tests>",
        &[
            "default:tests",
            "default:a1",
            "default:a2",
            "default:a3",
            "nsa:tests",
            "nsa:b2",
        ],
    );
}
