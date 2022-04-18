use std::collections::HashMap;

use super::{expression::Type, FileContext, RuleCompiler};
use crate::compiler::compile_file;
use crate::AddRuleError;
use boreal_parser::parse_str;

#[track_caller]
fn compile_expr(expression_str: &str, expected_type: Type) {
    let rule_str = format!(
        "rule a {{ strings: $a = /a/ condition: {} }}",
        expression_str
    );
    let file = parse_str(&rule_str).unwrap_or_else(|err| {
        panic!(
            "failed parsing: {}",
            AddRuleError::ParseError(err).to_short_description("mem", &rule_str)
        )
    });

    let modules = HashMap::new();
    let file_context = FileContext::new(&file, &modules).unwrap();
    let rule = file.rules.into_iter().next().unwrap();
    let compiler = RuleCompiler::new(&rule, &file_context).unwrap();
    let res = super::compile_expression(&compiler, rule.condition).unwrap();
    assert_eq!(res.ty, expected_type);
}

#[track_caller]
fn compile_expr_err(expression_str: &str) {
    compile_rule_err(&format!("rule a {{ condition: {} }}", expression_str));
}

#[track_caller]
fn compile_rule_err(rule_str: &str) {
    let file = parse_str(&rule_str).unwrap();

    let modules = HashMap::new();
    let res = compile_file(file, &modules);
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
        compile_expr(&format!("1 {} 3", op), Type::Boolean);
        compile_expr(&format!("1 {} 3.5", op), Type::Boolean);
        compile_expr(&format!("1.2 {} 3", op), Type::Boolean);
        compile_expr(&format!("1.2 {} 3.5", op), Type::Boolean);
        compile_expr(&format!("\"a\" {} \"b\"", op), Type::Boolean);
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

    compile_expr("\"a\"", Type::String);
    compile_expr("/a/", Type::Regex);

    compile_expr("any of them", Type::Boolean);
    compile_expr("any of them in (0..10)", Type::Boolean);
    compile_expr("for all i in (1,2): (true)", Type::Boolean);
}

#[test]
fn test_compilation_variables() {
    compile_rule_err("rule a { strings: $a=/a/ $a=/b/ condition: all of them }");
    compile_rule_err("rule a { condition: $a }");
}
