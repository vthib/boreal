use crate::utils::{build_rule, Compiler};

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

fn build_compiler() -> Compiler {
    let mut compiler = Compiler::new();
    compiler.define_symbol_int("sym_int", 1, true);
    compiler.define_symbol_bool("sym_bool", true, true);
    compiler.define_symbol_float("sym_float", 1.23, true);
    compiler.define_symbol_str("sym_str", "rge", true);
    compiler
}

#[test]
fn test_symbol_type_err() {
    build_compiler().check_add_rules_err(
        &build_rule("sym_int == /a/"),
        "error: expressions have invalid types",
    );
    build_compiler().check_add_rules_err(
        &build_rule("sym_bool == /a/"),
        "error: expressions have invalid types",
    );
    build_compiler().check_add_rules_err(
        &build_rule("sym_float == /a/"),
        "error: expressions have invalid types",
    );
    build_compiler().check_add_rules_err(
        &build_rule("sym_str == /a/"),
        "error: expressions have invalid types",
    );
}
