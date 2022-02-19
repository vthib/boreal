use super::{boolean_expression::boolean_expression, Type};
use crate::types::Input;

#[track_caller]
fn test_validation(expression_str: &str, expected_type: Type) {
    let input = Input::new(expression_str);
    let (_, expr) = boolean_expression(input).unwrap();
    assert_eq!(expr.ty, expected_type);
}

#[track_caller]
fn test_validation_err(expression_str: &str) {
    let input = Input::new(expression_str);
    let _err = boolean_expression(input).unwrap_err();
}

#[test]
fn test_primary_expression_types() {
    test_validation_err("uint8(/a/)");

    test_validation_err("1 | /a/");
    test_validation_err("/a/ | 1");
    test_validation_err("1 ^ /a/");
    test_validation_err("/a/ ^ 1");
    test_validation_err("1 & /a/");
    test_validation_err("/a/ & 1");
    test_validation_err("1.2 << 1");
    test_validation_err("1 << 1.2");
    test_validation_err("1.2 >> 1");
    test_validation_err("1 >> 1.2");

    test_validation_err("1 + /a/");
    test_validation_err("\"a\" + 1");
    test_validation_err("1 - /a/");
    test_validation_err("\"a\" - 1");

    test_validation_err("1 * /a/");
    test_validation_err("\"a\" * 1");

    test_validation_err("1 \\ /a/");
    test_validation_err("\"a\" \\ 1");

    test_validation_err("1 % 1.2");
    test_validation_err("1.2 % 1");

    test_validation_err("~1.2");
    test_validation_err("-/a/");
}

#[test]
fn test_expression_types() {
    test_validation_err("1 contains \"a\"");
    test_validation_err("\"a\" contains 1");

    test_validation_err("1 icontains \"a\"");
    test_validation_err("\"a\" icontains 1");

    test_validation_err("1 startswith \"a\"");
    test_validation_err("\"a\" startswith 1");

    test_validation_err("1 istartswith \"a\"");
    test_validation_err("\"a\" istartswith 1");

    test_validation_err("1 endswith \"a\"");
    test_validation_err("\"a\" endswith 1");

    test_validation_err("1 iendswith \"a\"");
    test_validation_err("\"a\" iendswith 1");

    test_validation_err("1 iequals \"a\"");
    test_validation_err("\"a\" iequals 1");

    test_validation_err("1 matches /a/");

    test_validation_err("$a at 1.2");

    test_validation_err("$a in (1..\"a\")");
    test_validation_err("$a in (/a/ .. 1)");

    test_validation_err("!foo [ 1.2 ]");
    test_validation_err("!foo[/a/]");
    test_validation_err("#foo in (0../a/)");
    test_validation_err("#foo in (1.2 .. 3)");
}

#[test]
fn test_validation_cmp() {
    test_validation("1 < 2", Type::Boolean);
    test_validation("1 <= 2.2", Type::Boolean);
    test_validation("1.1 > 2", Type::Boolean);
    test_validation("1.1 >= 2.2", Type::Boolean);

    test_validation("\"a\" > \"b\"", Type::Boolean);
    test_validation("\"a\" == \"b\"", Type::Boolean);
    test_validation("\"a\" != \"b\"", Type::Boolean);

    test_validation_err("\"a\" < 1");
    test_validation_err("2 == \"b\"");
    test_validation_err("/a/ != 1");
}

#[test]
fn test_validation_for_expression() {
    test_validation("any of them", Type::Boolean);
    test_validation("all of ($a, $b*)", Type::Boolean);
    test_validation("all of them in (1..3)", Type::Boolean);
    test_validation("for any of them: (true)", Type::Boolean);
    test_validation("for all i in (1, 2): (true)", Type::Boolean);
    test_validation("for any of them: (1)", Type::Boolean);

    test_validation_err("/a/ of them");
    test_validation_err("1.2% of them");
    test_validation_err("1.2% of them");
    test_validation_err("any of them in (1../a/)");
    test_validation_err("any of them in (/a/..2)");
    test_validation_err("for any i in (1../a/): (true)");
    test_validation_err("for any i in (/a/..1): (true)");
}

#[test]
fn test_validation_types() {
    fn test_cmp(op: &str) {
        test_validation(&format!("1 {} 3", op), Type::Boolean);
        test_validation(&format!("1 {} 3.5", op), Type::Boolean);
        test_validation(&format!("1.2 {} 3", op), Type::Boolean);
        test_validation(&format!("1.2 {} 3.5", op), Type::Boolean);
        test_validation(&format!("\"a\" {} \"b\"", op), Type::Boolean);
    }

    test_validation("filesize", Type::Integer);
    test_validation("entrypoint", Type::Integer);

    test_validation("uint16(0)", Type::Integer);

    test_validation("5", Type::Integer);
    test_validation("5.3", Type::Float);
    test_validation("-5", Type::Integer);
    test_validation("-5.3", Type::Float);

    test_validation("#a in (0..10)", Type::Integer);
    test_validation("#a", Type::Integer);

    test_validation("!a", Type::Integer);
    test_validation("@a", Type::Integer);

    test_validation("5 + 3", Type::Integer);
    test_validation("5 + 3.3", Type::Float);
    test_validation("5.2 + 3", Type::Float);
    test_validation("5.2 + 3.3", Type::Float);

    test_validation("5 - 3", Type::Integer);
    test_validation("5 - 3.3", Type::Float);
    test_validation("5.2 - 3", Type::Float);
    test_validation("5.2 - 3.3", Type::Float);

    test_validation("5 * 3", Type::Integer);
    test_validation("5 * 3.3", Type::Float);
    test_validation("5.2 * 3", Type::Float);
    test_validation("5.2 * 3.3", Type::Float);

    test_validation("5 \\ 3", Type::Integer);
    test_validation("5 \\ 3.3", Type::Float);
    test_validation("5.2 \\ 3", Type::Float);
    test_validation("5.2 \\ 3.3", Type::Float);

    test_validation("5 % 3", Type::Integer);

    test_validation("5 ^ 3", Type::Integer);
    test_validation("5 | 3", Type::Integer);
    test_validation("5 & 3", Type::Integer);
    test_validation("~5", Type::Integer);

    test_validation("5 << 3", Type::Integer);
    test_validation("5 >> 3", Type::Integer);

    test_validation("true && false", Type::Boolean);
    test_validation("true || false", Type::Boolean);

    test_cmp("<");
    test_cmp("<=");
    test_cmp("<");
    test_cmp(">=");
    test_cmp("==");
    test_cmp("!=");

    test_validation("\"a\" contains \"b\"", Type::Boolean);
    test_validation("\"a\" icontains \"b\"", Type::Boolean);
    test_validation("\"a\" startswith \"b\"", Type::Boolean);
    test_validation("\"a\" istartswith \"b\"", Type::Boolean);
    test_validation("\"a\" endswith \"b\"", Type::Boolean);
    test_validation("\"a\" iequals \"b\"", Type::Boolean);

    test_validation("\"a\" matches /b/", Type::Boolean);

    test_validation("defined b", Type::Boolean);
    test_validation("not true", Type::Boolean);

    test_validation("true and 1", Type::Boolean);
    test_validation("1 and true", Type::Boolean);

    test_validation("true or 1", Type::Boolean);
    test_validation("1 or true", Type::Boolean);

    test_validation("not 1", Type::Boolean);

    test_validation("$a", Type::Boolean);
    test_validation("$a at 100", Type::Boolean);
    test_validation("$a in (0..10)", Type::Boolean);

    test_validation("pe", Type::Undefined);

    test_validation("\"a\"", Type::String);
    test_validation("/a/", Type::Regex);

    test_validation("any of them", Type::Boolean);
    test_validation("any of them in (0..10)", Type::Boolean);
    test_validation("for all i in (1,2): (true)", Type::Boolean);
}
