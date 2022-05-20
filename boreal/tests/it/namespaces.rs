use crate::utils::{check_err, Compiler};

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
    checker.check_rule_matches(b"", &[]);

    checker.check_rule_matches(b"a", &["default:a"]);
    checker.check_rule_matches(b"ab", &["default:a", "default:b"]);
    checker.check_rule_matches(b"b", &[]);

    checker.check_rule_matches(b"c", &["ns1:a", "ns1:b"]);
    checker.check_rule_matches(b"cd", &["ns1:a", "ns1:b"]);
    checker.check_rule_matches(b"d", &["ns1:b"]);
    checker.check_rule_matches(b"bd", &["ns1:b"]);
}

#[test]
fn test_for_expression_rules_err() {
    check_err(
        "rule a { condition: all of (b) }",
        "mem:1:21: error: unknown identifier \"b\"",
    );
    check_err(
        "rule a { condition: all of (b*) }",
        "mem:1:21: error: unknown identifier \"b*\"",
    );
    check_err(
        "rule a { condition: true } rule c { condition: all of (a, b) }",
        "mem:1:48: error: unknown identifier \"b\"",
    );
    check_err(
        "rule a0 { condition: true }
         rule b0 { condition: all of (a*) }
         rule b1 { condition: true }
         rule b2 { condition: all of (b*) }
         rule b3 { condition: true }",
        r#"error: rule "b3" matches a previous rule set "b*""#,
    );
}

#[test]
fn test_for_expression_rules() {
    let mut compiler = Compiler::new();

    compiler.add_rules("rule a0 { strings: $a = /a0/ condition: $a }");
    compiler.add_rules("rule a1 { strings: $a = /a1/ condition: $a }");
    compiler.add_rules("rule a2 { strings: $a = /a2/ condition: $a }");
    compiler.add_rules("rule a3 { strings: $a = /a3/ condition: $a }");
    compiler.add_rules_in_namespace("rule a2p { strings: $a = /a2/ condition: $a }", "ns1");
    compiler.add_rules("rule b0 { condition: 3 of (a*) }");
    compiler.add_rules("rule b1 { condition: all of (a1, a3) }");
    compiler.add_rules("rule b2 { condition: 4 of (a0, a*) }");

    let checker = compiler.into_checker();
    checker.check_rule_matches(b"", &[]);

    checker.check_rule_matches(b"a0", &["default:a0"]);
    checker.check_rule_matches(
        b"a0a1a2",
        &[
            "default:a0",
            "default:a1",
            "default:a2",
            "ns1:a2p",
            "default:b0",
            "default:b2",
        ],
    );
    checker.check_rule_matches(b"a1a3", &["default:a1", "default:a3", "default:b1"]);
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
    checker.check_rule_matches(b"", &["default:a2", "default:a3", "nsa:tests", "nsa:b2"]);
    checker.check_rule_matches(
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
