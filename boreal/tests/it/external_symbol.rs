use crate::utils::{build_rule, check, check_err, Checker, Compiler};

#[test]
fn test_define_symbol_err() {
    let mut compiler = Compiler::new();

    compiler.define_symbol_int("a", 1, true);
    compiler.define_symbol_bool("b", true, true);
    compiler.define_symbol_int("a", 2, false);
    compiler.define_symbol_bool("a", false, false);
    compiler.define_symbol_float("a", 1.5, false);
    compiler.define_symbol_str("a", "bb", false);
    compiler.define_symbol_int("c", 3, true);
}

#[test]
fn test_symbol_type_err() {
    check_err(
        &build_rule("sym_int == /a/"),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule("sym_bool == /a/"),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule("sym_float == /a/"),
        "error: expressions have invalid types",
    );
    check_err(
        &build_rule("sym_str == /a/"),
        "error: expressions have invalid types",
    );

    let checker = Checker::new(&build_rule("sym_int < 1"));
    let mut scanner = checker.scanner();
    scanner.define_symbol_int("a", 3, Some("unknown symbol name"));
    scanner.define_symbol_str("sym_int", "a", Some("invalid value type"));
    scanner.define_symbol_int("sym_str", 5, Some("invalid value type"));
    scanner.define_symbol_bool("sym_float", true, Some("invalid value type"));
    scanner.define_symbol_float("sym_bool", -1.2, Some("invalid value type"));
}

#[test]
fn test_symbol_eval() {
    let checker = Checker::new(&build_rule("sym_int <= 1"));
    let mut scanner1 = checker.scanner();
    let mut scanner2 = checker.scanner();

    scanner1.check(b"", true);
    scanner2.check(b"", true);
    scanner1.define_symbol_int("sym_int", 3, None);
    scanner1.check(b"", false);
    scanner1.check(b"", false);
    scanner2.check(b"", true);
    scanner1.define_symbol_int("sym_int", -1, None);
    scanner1.check(b"", true);
    scanner2.check(b"", true);
    scanner2.define_symbol_int("sym_int", 23, None);
    scanner1.check(b"", true);
    scanner2.check(b"", false);

    check(&build_rule("sym_int == 1"), b"", true);

    let checker = Checker::new(&build_rule("sym_bool"));
    let mut scanner = checker.scanner();
    scanner.check(b"", true);
    scanner.define_symbol_bool("sym_bool", false, None);
    scanner.check(b"", false);

    let checker = Checker::new(&build_rule("sym_float == 1.23"));
    let mut scanner = checker.scanner();
    scanner.check(b"", true);
    scanner.define_symbol_float("sym_float", -1.23, None);
    scanner.check(b"", false);

    let checker = Checker::new(&build_rule("sym_str == \"rge\""));
    let mut scanner = checker.scanner();
    scanner.check(b"", true);
    scanner.define_symbol_str("sym_str", "odo", None);
    scanner.check(b"", false);
}
