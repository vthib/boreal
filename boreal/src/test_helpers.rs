use boreal_parser::hex_string::Token;
use boreal_parser::{parse, Regex, VariableDeclarationValue};

#[track_caller]
pub fn parse_hex_string(hex_string: &str) -> Vec<Token> {
    let rule_str = format!("rule a {{ strings: $a = {hex_string} condition: $a }}");
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
    let rule_str = format!("rule a {{ strings: $a = /{hex_string}/ condition: $a }}");
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

// Those helpers serves two purposes:
// - Ensure public types have expected impls: Clone, Debug, Send & Sync
// - Instrument those impls to avoid having those derive be marked as missed in coverage...
pub fn test_type_traits<T: Clone + std::fmt::Debug + Send + Sync>(t: T) {
    #[allow(clippy::redundant_clone)]
    let _r = t.clone();
    let _r = format!("{:?}", &t);
}

pub fn test_type_traits_non_clonable<T: std::fmt::Debug + Send + Sync>(t: T) {
    let _r = format!("{:?}", &t);
}
