use std::sync::Arc;

use super::expression::{compile_expression, Type};
use super::module::compile_module;
use super::rule::RuleCompiler;
use super::{
    AddRuleError, AddRuleErrorKind, AddRuleStatus, AvailableModule, CompilationError, Compiler,
    CompilerParams, CompilerProfile, ImportedModule, IncludeCallback, ModuleLocation, Namespace,
};
use crate::bytes_pool::BytesPoolBuilder;
use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};
use boreal_parser::parse;

#[track_caller]
fn compile_expr(expression_str: &str, expected_type: Type) {
    let rule_str = format!("rule a {{ strings: $a = /a/ condition: {expression_str} }}");
    let file = parse(&rule_str).unwrap();

    let rule = file
        .components
        .into_iter()
        .next()
        .map(|v| match v {
            boreal_parser::file::YaraFileComponent::Rule(v) => v,
            _ => panic!(),
        })
        .unwrap();
    let mut compiler = Compiler::new();
    assert!(compiler.define_symbol("sym_int", 32));
    assert!(compiler.define_symbol("sym_flt", -2.34));
    assert!(compiler.define_symbol("sym_bool", true));
    assert!(compiler.define_symbol("sym_bytes", "keyboard"));

    let mut bytes_pool = BytesPoolBuilder::default();
    let ns = Namespace::default();
    let mut rule_compiler = RuleCompiler::new(
        &rule.variables,
        &ns,
        &compiler.external_symbols,
        &compiler.params,
        &mut bytes_pool,
    )
    .unwrap();
    let res = compile_expression(&mut rule_compiler, rule.condition).unwrap();
    assert_eq!(res.ty, expected_type);
}

#[track_caller]
fn compile_expr_err(expression_str: &str) {
    compile_rule_err(&format!("rule a {{ condition: {expression_str} }}"));
}

#[track_caller]
fn compile_rule_err(rule_str: &str) {
    let mut compiler = Compiler::new();
    let res = compiler.add_rules_str(rule_str);
    assert!(res.is_err());
}

#[test]
fn test_primary_expression_types() {
    compile_expr_err("uint8(/a/)");

    compile_expr_err("1 | /a/");
    compile_expr_err("/a/ | 1");
    compile_expr_err("1 ^ /a/");
    compile_expr_err("/a/ ^ 1");
    compile_expr_err("1 & /a/");
    compile_expr_err("/a/ & 1");
    compile_expr_err("1.2 << 1");
    compile_expr_err("1 << 1.2");
    compile_expr_err("1.2 >> 1");
    compile_expr_err("1 >> 1.2");

    compile_expr_err("1 + /a/");
    compile_expr_err("\"a\" + 1");
    compile_expr_err("1 - /a/");
    compile_expr_err("\"a\" - 1");

    compile_expr_err("1 * /a/");
    compile_expr_err("\"a\" * 1");

    compile_expr_err("1 \\ /a/");
    compile_expr_err("\"a\" \\ 1");

    compile_expr_err("1 % 1.2");
    compile_expr_err("1.2 % 1");

    compile_expr_err("~1.2");
    compile_expr_err("-/a/");
}

#[test]
fn test_expression_types() {
    compile_expr_err("1 contains \"a\"");
    compile_expr_err("\"a\" contains 1");

    compile_expr_err("1 icontains \"a\"");
    compile_expr_err("\"a\" icontains 1");

    compile_expr_err("1 startswith \"a\"");
    compile_expr_err("\"a\" startswith 1");

    compile_expr_err("1 istartswith \"a\"");
    compile_expr_err("\"a\" istartswith 1");

    compile_expr_err("1 endswith \"a\"");
    compile_expr_err("\"a\" endswith 1");

    compile_expr_err("1 iendswith \"a\"");
    compile_expr_err("\"a\" iendswith 1");

    compile_expr_err("1 iequals \"a\"");
    compile_expr_err("\"a\" iequals 1");

    compile_expr_err("1 matches /a/");

    compile_expr_err("$a at 1.2");

    compile_expr_err("$a in (1..\"a\")");
    compile_expr_err("$a in (/a/ .. 1)");

    compile_expr_err("!foo [ 1.2 ]");
    compile_expr_err("!foo[/a/]");
    compile_expr_err("#foo in (0../a/)");
    compile_expr_err("#foo in (1.2 .. 3)");
}

#[test]
fn test_compilation_cmp() {
    compile_expr("1 < 2", Type::Boolean);
    compile_expr("1 <= 2.2", Type::Boolean);
    compile_expr("1.1 > 2", Type::Boolean);
    compile_expr("1.1 >= 2.2", Type::Boolean);

    compile_expr("\"a\" > \"b\"", Type::Boolean);
    compile_expr("\"a\" == \"b\"", Type::Boolean);
    compile_expr("\"a\" != \"b\"", Type::Boolean);

    compile_expr_err("\"a\" < 1");
    compile_expr_err("2 == \"b\"");
    compile_expr_err("/a/ != 1");
}

#[test]
fn test_compilation_for_expression() {
    compile_expr("any of them", Type::Boolean);
    compile_expr("all of ($a, $*)", Type::Boolean);
    compile_expr("all of them in (1..3)", Type::Boolean);
    compile_expr("for any of them: (true)", Type::Boolean);
    compile_expr("for all i in (1, 2): (true)", Type::Boolean);
    compile_expr("for any of them: (1)", Type::Boolean);

    compile_expr_err("/a/ of them");
    compile_expr_err("1.2% of them");
    compile_expr_err("1.2% of them");
    compile_expr_err("any of them in (1../a/)");
    compile_expr_err("any of them in (/a/..2)");
    compile_expr_err("for any i in (1../a/): (true)");
    compile_expr_err("for any i in (/a/..1): (true)");
}

#[test]
fn test_compilation_types() {
    fn test_cmp(op: &str) {
        compile_expr(&format!("1 {op} 3"), Type::Boolean);
        compile_expr(&format!("1 {op} 3.5"), Type::Boolean);
        compile_expr(&format!("1.2 {op} 3"), Type::Boolean);
        compile_expr(&format!("1.2 {op} 3.5"), Type::Boolean);
        compile_expr(&format!("\"a\" {op} \"b\""), Type::Boolean);
    }

    compile_expr("filesize", Type::Integer);
    compile_expr("entrypoint", Type::Integer);

    compile_expr("uint16(0)", Type::Integer);

    compile_expr("5", Type::Integer);
    compile_expr("5.3", Type::Float);
    compile_expr("-5", Type::Integer);
    compile_expr("-5.3", Type::Float);

    compile_expr("#a in (0..10)", Type::Integer);
    compile_expr("#a", Type::Integer);

    compile_expr("!a", Type::Integer);
    compile_expr("@a", Type::Integer);

    compile_expr("5 + 3", Type::Integer);
    compile_expr("5 + 3.3", Type::Float);
    compile_expr("5.2 + 3", Type::Float);
    compile_expr("5.2 + 3.3", Type::Float);

    compile_expr("5 - 3", Type::Integer);
    compile_expr("5 - 3.3", Type::Float);
    compile_expr("5.2 - 3", Type::Float);
    compile_expr("5.2 - 3.3", Type::Float);

    compile_expr("5 * 3", Type::Integer);
    compile_expr("5 * 3.3", Type::Float);
    compile_expr("5.2 * 3", Type::Float);
    compile_expr("5.2 * 3.3", Type::Float);

    compile_expr("5 \\ 3", Type::Integer);
    compile_expr("5 \\ 3.3", Type::Float);
    compile_expr("5.2 \\ 3", Type::Float);
    compile_expr("5.2 \\ 3.3", Type::Float);

    compile_expr("5 % 3", Type::Integer);

    compile_expr("5 ^ 3", Type::Integer);
    compile_expr("5 | 3", Type::Integer);
    compile_expr("5 & 3", Type::Integer);
    compile_expr("~5", Type::Integer);

    compile_expr("5 << 3", Type::Integer);
    compile_expr("5 >> 3", Type::Integer);

    compile_expr("true and false", Type::Boolean);
    compile_expr("true or false", Type::Boolean);

    test_cmp("<");
    test_cmp("<=");
    test_cmp("<");
    test_cmp(">=");
    test_cmp("==");
    test_cmp("!=");

    compile_expr("\"a\" contains \"b\"", Type::Boolean);
    compile_expr("\"a\" icontains \"b\"", Type::Boolean);
    compile_expr("\"a\" startswith \"b\"", Type::Boolean);
    compile_expr("\"a\" istartswith \"b\"", Type::Boolean);
    compile_expr("\"a\" endswith \"b\"", Type::Boolean);
    compile_expr("\"a\" iequals \"b\"", Type::Boolean);

    compile_expr("\"a\" matches /b/", Type::Boolean);

    compile_expr("defined 5", Type::Boolean);
    compile_expr("not true", Type::Boolean);

    compile_expr("true and 1", Type::Boolean);
    compile_expr("1 and true", Type::Boolean);

    compile_expr("true or 1", Type::Boolean);
    compile_expr("1 or true", Type::Boolean);

    compile_expr("not 1", Type::Boolean);

    compile_expr("$a", Type::Boolean);
    compile_expr("$a at 100", Type::Boolean);
    compile_expr("$a in (0..10)", Type::Boolean);

    compile_expr("\"a\"", Type::Bytes);
    compile_expr("/a/", Type::Regex);

    compile_expr("any of them", Type::Boolean);
    compile_expr("any of them in (0..10)", Type::Boolean);
    compile_expr("for all i in (1,2): (true)", Type::Boolean);

    compile_expr("sym_bytes", Type::Bytes);
    compile_expr("sym_int", Type::Integer);
    compile_expr("sym_flt", Type::Float);
    compile_expr("sym_bool", Type::Boolean);
}

#[test]
fn test_compilation_variables() {
    compile_rule_err("rule a { strings: $a=/a/ $a=/b/ condition: all of them }");
    compile_rule_err("rule a { condition: $a }");
}

#[test]
fn test_types_traits() {
    test_type_traits_non_clonable(Compiler::new());
    test_type_traits_non_clonable(Namespace::default());
    test_type_traits_non_clonable(AvailableModule {
        compiled_module: Arc::new(compile_module(&crate::module::Time)),
        location: ModuleLocation::Module(Box::new(crate::module::Time)),
    });
    test_type_traits_non_clonable(ImportedModule {
        module: Arc::new(compile_module(&crate::module::Time)),
        module_index: 0,
    });
    test_type_traits_non_clonable(AddRuleError {
        path: None,
        kind: Box::new(AddRuleErrorKind::Compilation(
            CompilationError::DuplicatedRuleName {
                name: "a".to_owned(),
                span: 0..1,
            },
        )),
        desc: String::new(),
    });
    test_type_traits(CompilerParams::default());
    test_type_traits(CompilerProfile::default());
    test_type_traits_non_clonable(AddRuleStatus {
        warnings: Vec::new(),
        statistics: Vec::new(),
    });
    test_type_traits_non_clonable(IncludeCallback(Box::new(|_, _, _| Ok(String::new()))));
}
