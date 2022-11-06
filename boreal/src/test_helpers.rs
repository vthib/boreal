use boreal_parser::hex_string::Token;
use boreal_parser::{parse, Regex, VariableDeclarationValue};

#[track_caller]
pub fn parse_hex_string(hex_string: &str) -> Vec<Token> {
    let rule_str = format!("rule a {{ strings: $a = {} condition: $a }}", hex_string);
    let mut file = parse(&rule_str).unwrap();
    let mut rule = file
        .components
        .pop()
        .map(|v| match v {
            boreal_parser::YaraFileComponent::Rule(v) => v,
            _ => panic!(),
        })
        .unwrap();
    let var = rule.variables.pop().unwrap();
    match var.value {
        VariableDeclarationValue::HexString(s) => s,
        _ => panic!(),
    }
}

#[track_caller]
pub fn parse_regex_string(hex_string: &str) -> Regex {
    let rule_str = format!("rule a {{ strings: $a = /{}/ condition: $a }}", hex_string);
    let mut file = parse(&rule_str).unwrap();
    let mut rule = file
        .components
        .pop()
        .map(|v| match v {
            boreal_parser::YaraFileComponent::Rule(v) => v,
            _ => panic!(),
        })
        .unwrap();
    let var = rule.variables.pop().unwrap();
    match var.value {
        VariableDeclarationValue::Regex(s) => s,
        _ => panic!(),
    }
}