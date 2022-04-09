use std::fmt::Write;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use grep_regex::{RegexMatcher, RegexMatcherBuilder};

use boreal_parser::{HexMask, HexToken, VariableFlags, VariableModifiers};
use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue};

use super::base64::encode_base64;
use super::CompilationError;

#[derive(Debug)]
pub struct Variable {
    pub matcher: VariableMatcher,

    // Those three modifiers are used to handle fullword check on matches.
    pub is_fullword: bool,
    pub is_wide: bool,
    pub is_ascii: bool,
}

#[derive(Debug)]
pub enum VariableMatcher {
    Regex(RegexMatcher),
    AhoCorasick(AhoCorasick),
}

pub(crate) fn compile_variable(decl: VariableDeclaration) -> Result<Variable, CompilationError> {
    let VariableDeclaration {
        name,
        value,
        modifiers,
    } = decl;
    let mut is_fullword = modifiers.flags.contains(VariableFlags::FULLWORD);
    let mut is_wide = modifiers.flags.contains(VariableFlags::WIDE);
    let is_ascii = !is_wide || modifiers.flags.contains(VariableFlags::ASCII);

    // TODO: handle private flag
    //
    let matcher = match value {
        VariableDeclarationValue::String(s) => build_string_matcher(s, &modifiers),
        VariableDeclarationValue::Regex(regex) => {
            let matcher = build_regex_matcher(regex, &modifiers);
            matcher.map_err(|error| CompilationError::VariableCompilation {
                variable_name: name,
                error,
            })?
        }
        VariableDeclarationValue::HexString(hex_string) => {
            let mut regex = String::new();
            hex_string_to_regex(hex_string, &mut regex);

            // Fullword and wide is not compatible with hex strings
            is_fullword = false;
            is_wide = false;

            let mut matcher = RegexMatcherBuilder::new();
            let matcher = matcher
                .unicode(false)
                .octal(false)
                .dot_matches_new_line(true)
                .build(&regex);
            VariableMatcher::Regex(matcher.map_err(|error| {
                CompilationError::VariableCompilation {
                    variable_name: name,
                    error,
                }
            })?)
        }
    };

    Ok(Variable {
        matcher,
        is_fullword,
        is_wide,
        is_ascii,
    })
}

fn build_string_matcher(value: String, modifiers: &VariableModifiers) -> VariableMatcher {
    let mut builder = AhoCorasickBuilder::new();
    let mut literals = Vec::with_capacity(2);

    let case_insensitive = modifiers.flags.contains(VariableFlags::NOCASE);

    let value = value.into_bytes();
    if modifiers.flags.contains(VariableFlags::WIDE) {
        if modifiers.flags.contains(VariableFlags::ASCII) {
            literals.push(string_to_wide(&value));
            literals.push(value);
        } else {
            literals.push(string_to_wide(&value));
        }
    } else {
        literals.push(value);
    }

    if modifiers.flags.contains(VariableFlags::XOR) {
        // For each literal, for each byte in the xor range, build a new literal
        let xor_range = modifiers.xor_range.0..=modifiers.xor_range.1;
        let xor_range_len = xor_range.len(); // modifiers.xor_range.1.saturating_sub(modifiers.xor_range.0) + 1;
        let mut new_literals: Vec<Vec<u8>> = Vec::with_capacity(literals.len() * xor_range_len);
        for lit in literals {
            for xor_byte in xor_range.clone() {
                new_literals.push(lit.iter().map(|c| c ^ xor_byte).collect());
            }
        }
        let literals = new_literals;
        return VariableMatcher::AhoCorasick(builder.auto_configure(&literals).build(&literals));
    }

    if modifiers.flags.contains(VariableFlags::BASE64)
        || modifiers.flags.contains(VariableFlags::BASE64WIDE)
    {
        let mut old_literals = Vec::with_capacity(literals.len() * 3);
        std::mem::swap(&mut old_literals, &mut literals);

        if modifiers.flags.contains(VariableFlags::BASE64) {
            for lit in &old_literals {
                for offset in 0..=2 {
                    if let Some(lit) = encode_base64(&lit, &modifiers.base64_alphabet, offset) {
                        if modifiers.flags.contains(VariableFlags::BASE64WIDE) {
                            literals.push(string_to_wide(&lit));
                        }
                        literals.push(lit);
                    }
                }
            }
        } else if modifiers.flags.contains(VariableFlags::BASE64WIDE) {
            for lit in &old_literals {
                for offset in 0..=2 {
                    if let Some(lit) = encode_base64(&lit, &modifiers.base64_alphabet, offset) {
                        literals.push(string_to_wide(&lit));
                    }
                }
            }
        }
    }

    VariableMatcher::AhoCorasick(
        builder
            .ascii_case_insensitive(case_insensitive)
            .auto_configure(&literals)
            .build(&literals),
    )
}

/// Convert an ascii string to a wide string
fn string_to_wide(s: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(s.len() * 2);
    for b in s {
        res.push(*b);
        res.push(b'\0');
    }
    res
}

fn build_regex_matcher(
    regex: Regex,
    modifiers: &VariableModifiers,
) -> Result<VariableMatcher, grep_regex::Error> {
    let mut matcher = RegexMatcherBuilder::new();
    let Regex {
        expr,
        mut case_insensitive,
        dot_all,
    } = regex;

    if modifiers.flags.contains(VariableFlags::NOCASE) {
        case_insensitive = true;
    }

    if modifiers.flags.contains(VariableFlags::WIDE) {
        // TODO: hmmmmm this is gonna be fun
        if modifiers.flags.contains(VariableFlags::ASCII) {
            todo!();
        }
        todo!();
    }

    matcher
        .unicode(false)
        .octal(false)
        .case_insensitive(case_insensitive)
        .multi_line(dot_all)
        .dot_matches_new_line(dot_all)
        .build(&expr)
        .map(VariableMatcher::Regex)
}

fn hex_string_to_regex(hex_string: Vec<HexToken>, regex: &mut String) {
    for token in hex_string {
        hex_token_to_regex(token, regex);
    }
}

fn hex_token_to_regex(token: HexToken, regex: &mut String) {
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
            (from, None) => write!(regex, ".{{{},}}?", from).unwrap(),
            (from, Some(to)) => {
                if from == to {
                    write!(regex, ".{{{}}}?", from).unwrap();
                } else {
                    write!(regex, ".{{{},{}}}?", from, to).unwrap();
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
        test("{ C7 [-] ?? }", r"\xC7.{0,}?.");
        // TODO: replacing [2-4] by [-] leads to a failed nom parsing? to investigate
        test(
            "{ C7 [3-] 5? 03 [-6] C7 ( FF 15 | E8 ) [4] 6A ( FF D? | E8 [2-4] ??) }",
            r"\xC7.{3,}?[\x50-\x5F]\x03.{0,6}?\xC7((\xFF\x15)|(\xE8)).{4}?\x6A((\xFF[\xD0-\xDF])|(\xE8.{2,4}?.))",
        );
    }
}
