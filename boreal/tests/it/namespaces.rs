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
        "mem:1:6: error: rule `a` is already declared in this namespace",
    );

    // Multiple rules can have the same name in different namespaces
    let mut compiler = Compiler::new();
    compiler.add_rules("rule a { condition: true }");
    compiler.add_rules_in_namespace("rule a { condition: true }", "ns1");
    compiler.add_rules_in_namespace("rule a { condition: true }", "ns2");
    let checker = compiler.into_checker();
    checker.check_count(b"", 3);

    // Cannot depend on itself
    // DIFF: This is different from yara, boreal refuses this type of dependency.
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
        "mem:1:29: error: unknown identifier \"b\"",
    );
    check_err(
        "rule a { condition: all of (b*) }",
        "mem:1:29: error: unknown identifier \"b*\"",
    );
    check_err(
        "rule a { condition: true } rule c { condition: all of (a, b) }",
        "mem:1:59: error: unknown identifier \"b\"",
    );
    check_err(
        "rule a0 { condition: true }
         rule b0 { condition: all of (a*) }
         rule b1 { condition: true }
         rule b2 { condition: all of (b*) }
         rule b3 { condition: true }",
        r#"mem:5:15: error: rule "b3" matches a previous rule set "b*""#,
    );

    // It should be OK if the rule that added the wildcard failed to compile.
    // This cannot be tested with yara since yara invalidates the compiler as soon as one
    // error is reached.
    let mut compiler = Compiler::new();
    compiler.add_rules("rule a0 { condition: true }");
    // Fails to compile because a string is not used
    compiler.check_add_rules_err_boreal(
        r#"rule b {
        strings:
            $t = "abc"
        condition:
            all of (a*)
    }"#,
        "mem:3:13: error: variable $t is unused",
    );
    // Adding a rule prefixed by "a" should thus be allowed.
    compiler.add_rules("rule a1 { condition: true }");

    // Do the same, but trigger an error very late: if the rule's name is already in the namespace.
    compiler.check_add_rules_err_boreal(
        "rule a1 { condition: all of (a*) }",
        "mem:1:6: error: rule `a1` is already declared in this namespace",
    );
    // This should again work
    compiler.add_rules("rule a2 { condition: true }");
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
    compiler.add_rules("rule b3 { condition: 50% of (a1, a2, a3) }");

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
            "default:b3",
        ],
    );
    checker.check_rule_matches(
        b"a1a3",
        &["default:a1", "default:a3", "default:b1", "default:b3"],
    );
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

// Test includes implementation, including wrt namespaces
#[test]
fn test_includes() {
    // [test_dir]
    //     root.yar depends on dir1/sub1/b
    //     root2.yar depends on dir1/sub1/../sub2/c
    //     [dir1]
    //         a.yar depends on ../dir2/sub1/d
    //         [sub1]
    //           b.yar depends on ../a
    //         [sub2]
    //           c.yar depends on ../../dir2/sub1/e
    //     [dir2]
    //         d.yar depends on sub2/f
    //         [sub]
    //             e.yar depends on f
    //             f.yar
    let test_dir = tempfile::TempDir::new().unwrap();
    let path = test_dir.path();
    std::fs::create_dir_all(path.join("dir1").join("sub1")).unwrap();
    std::fs::create_dir_all(path.join("dir1").join("sub2")).unwrap();
    std::fs::create_dir_all(path.join("dir2").join("sub")).unwrap();
    std::fs::write(
        path.join("root.yar"),
        r#"
include "dir1/sub1/b.yar"
rule root {
    strings:
         $ = "root"
    condition: b and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("root2.yar"),
        r#"
include "dir1/sub1/../sub2/c.yar"
rule root2 {
    strings:
        $ = "root2"
    condition: c and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("dir1").join("a.yar"),
        r#"
include "../dir2/d.yar"
rule a {
    strings:
        $ = "aaaa"
    condition: d and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("dir1").join("sub1").join("b.yar"),
        r#"
include "../a.yar"
rule b {
    strings:
        $ = "bbbb"
    condition: a and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("dir1").join("sub2").join("c.yar"),
        r#"
include "../../dir2/sub/e.yar"
rule c {
    strings:
        $ = "bbbb"
    condition: e and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("dir2").join("d.yar"),
        r#"
include "sub/f.yar"
rule d {
    strings:
        $ = "dddd"
    condition: f and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("dir2").join("sub").join("e.yar"),
        r#"
include "f.yar"
rule e {
    strings:
        $ = "eeee"
    condition: f and all of them
}"#,
    )
    .unwrap();
    std::fs::write(
        path.join("dir2").join("sub").join("f.yar"),
        r#"
rule f {
    strings:
        $ = "ffff"
    condition: all of them
}"#,
    )
    .unwrap();

    let mut compiler = Compiler::new();
    compiler.add_file(&path.join("root.yar"));
    compiler.add_file_in_namespace(&path.join("root2.yar"), "ns2");

    let checker = compiler.into_checker();

    checker.check_rule_matches(
        b"root2 aaaa bbbb cccc dddd eeee ffff",
        &[
            "default:root",
            "default:a",
            "default:b",
            "default:d",
            "default:f",
            "ns2:root2",
            "ns2:c",
            "ns2:e",
            "ns2:f",
        ],
    );
}
