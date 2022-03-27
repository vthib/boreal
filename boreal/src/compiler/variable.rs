use grep_regex::{RegexMatcher, RegexMatcherBuilder};

use boreal_parser::{HexMask, HexToken};
use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue};

use super::CompilationError;

#[derive(Debug)]
pub struct Variable {
    pub matcher: RegexMatcher,
}

pub(crate) fn compile_variable(decl: VariableDeclaration) -> Result<Variable, CompilationError> {
    // TODO: handle modifiers
    let mut matcher = RegexMatcherBuilder::new();
    let matcher = matcher.unicode(false).octal(false);

    let res = match decl.value {
        VariableDeclarationValue::String(s) => matcher.build_literals(&[s]),
        VariableDeclarationValue::Regex(Regex {
            expr,
            case_insensitive,
            dot_all,
        }) => matcher
            .case_insensitive(case_insensitive)
            .multi_line(dot_all)
            .dot_matches_new_line(dot_all)
            .build(&expr),
        VariableDeclarationValue::HexString(hex_string) => {
            let mut regex = String::new();
            hex_string_to_regex(hex_string, &mut regex);

            matcher.build(&regex)
        }
    };

    Ok(Variable {
        matcher: res.map_err(|error| CompilationError::VariableCompilation {
            variable_name: decl.name,
            error,
        })?,
    })
}

fn hex_string_to_regex(hex_string: Vec<HexToken>, regex: &mut String) {
    for token in hex_string {
        hex_token_to_regex(token, regex);
    }
}

fn hex_token_to_regex(token: HexToken, regex: &mut String) {
    use std::fmt::Write;

    match token {
        HexToken::Byte(b) => write!(regex, "\\x{:02X}", b).unwrap(),
        HexToken::MaskedByte(b, mask) => match mask {
            HexMask::Left => {
                regex.push('[');
                for i in 0..=0xF {
                    write!(regex, "\\x{:1X}{:1X}", i, b).unwrap();
                }
                regex.push(']');
            }
            HexMask::Right => write!(regex, "[\\x{:1X}0-\\x{:1X}F]", b, b).unwrap(),
            HexMask::All => regex.push('.'),
        },
        HexToken::Jump(jump) => match (jump.from, jump.to) {
            (from, None) => write!(regex, ".{{{},}}", from).unwrap(),
            (from, Some(to)) => {
                if from == to {
                    write!(regex, ".{{{}}}", from).unwrap();
                } else {
                    write!(regex, ".{{{},{}}}", from, to).unwrap();
                }
            }
        },
        HexToken::Alternatives(left, right) => {
            regex.push_str("((");
            hex_string_to_regex(left, regex);
            regex.push_str(")|(");
            hex_string_to_regex(right, regex);
            regex.push_str("))");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boreal_parser::parse_str;

    #[track_caller]
    fn test(hex_string: &str, expected_regex: &str) {
        let rule_str = format!("rule a {{ strings: $a = {} condition: $a }}", hex_string);
        let mut rules = parse_str(&rule_str).unwrap();
        let mut rule = rules.pop().unwrap();
        let var = rule.variables.pop().unwrap();
        let hex_string = match var.value {
            VariableDeclarationValue::HexString(s) => s,
            _ => panic!(),
        };

        let mut regex = String::new();
        hex_string_to_regex(hex_string, &mut regex);
        assert_eq!(regex, expected_regex);
    }

    #[test]
    fn test_hex_string_to_regex() {
        test(
            "{ AB ?D 01 }",
            r"\xAB[\x0D\x1D\x2D\x3D\x4D\x5D\x6D\x7D\x8D\x9D\xAD\xBD\xCD\xDD\xED\xFD]\x01",
        );
        test(
            "{ C7 [3] 5? 03 [6] C7 ( FF 15 | E8 ) [4] 6A ( FF D? | E8 [3] ??) }",
            r"\xC7.{3}[\x50-\x5F]\x03.{6}\xC7((\xFF\x15)|(\xE8)).{4}\x6A((\xFF[\xD0-\xDF])|(\xE8.{3}.))",
        );
    }
}
