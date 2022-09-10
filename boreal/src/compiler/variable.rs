use std::fmt::Write;

use ::regex::bytes::{Regex, RegexBuilder};

use boreal_parser::regex::{
    BracketedClass, BracketedClassItem, ClassKind, Node, RepetitionKind, RepetitionRange,
};
use boreal_parser::{HexMask, HexToken, VariableFlags, VariableModifiers};
use boreal_parser::{VariableDeclaration, VariableDeclarationValue};

use crate::regex::add_ast_to_string;

use super::base64::encode_base64;
use super::CompilationError;

mod regex;

#[derive(Debug)]
pub struct Variable {
    pub name: String,

    pub regex_expr: String,
    pub regex: Regex,

    // This is only set for the specific case of a regex variable, with a wide modifier, that
    // contains word boundaries.
    // In this case, the regex expression cannot be "widened", and this regex is used to post
    // check matches.
    pub non_wide_regex: Option<Regex>,

    flags: VariableFlags,
}

impl Variable {
    pub fn is_ascii(&self) -> bool {
        self.flags.contains(VariableFlags::ASCII)
    }

    pub fn is_fullword(&self) -> bool {
        self.flags.contains(VariableFlags::FULLWORD)
    }

    pub fn is_private(&self) -> bool {
        self.flags.contains(VariableFlags::PRIVATE)
    }

    pub fn is_wide(&self) -> bool {
        self.flags.contains(VariableFlags::WIDE)
    }
}

pub(crate) fn compile_variable(decl: VariableDeclaration) -> Result<Variable, CompilationError> {
    let VariableDeclaration {
        name,
        value,
        modifiers,
        span,
    } = decl;
    let mut flags = modifiers.flags;
    if !flags.contains(VariableFlags::WIDE) {
        flags.insert(VariableFlags::ASCII);
    }

    let mut non_wide_regex = None;

    let regex_expr = match value {
        VariableDeclarationValue::Bytes(s) => Ok(build_string_matcher(s, &modifiers)),
        VariableDeclarationValue::Regex(regex) => {
            regex::compile_regex(regex, &modifiers).map(|(expr, v)| {
                non_wide_regex = v;
                expr
            })
        }
        VariableDeclarationValue::HexString(hex_string) => {
            // Fullword and wide is not compatible with hex strings
            flags.remove(VariableFlags::FULLWORD);
            flags.remove(VariableFlags::WIDE);

            let ast = hex_string_to_ast(hex_string);
            let mut expr = String::new();
            expr.push_str("(?s)");
            add_ast_to_string(ast, &mut expr);
            Ok(expr)
        }
    };

    let regex_expr = regex_expr.map_err(|error| CompilationError::VariableCompilation {
        variable_name: name.clone(),
        span: span.clone(),
        error,
    })?;

    let regex = RegexBuilder::new(&regex_expr)
        .unicode(false)
        .octal(false)
        .build()
        .map_err(|error| CompilationError::VariableCompilation {
            variable_name: name.clone(),
            span,
            error: VariableCompilationError::Regex(error.to_string()),
        })?;

    Ok(Variable {
        name,
        regex_expr,
        regex,
        non_wide_regex,
        flags,
    })
}

fn build_string_matcher(value: Vec<u8>, modifiers: &VariableModifiers) -> String {
    let mut literals = Vec::with_capacity(2);

    let case_insensitive = modifiers.flags.contains(VariableFlags::NOCASE);

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
        return literals_to_regex_expr(&new_literals, case_insensitive);
    }

    if modifiers.flags.contains(VariableFlags::BASE64)
        || modifiers.flags.contains(VariableFlags::BASE64WIDE)
    {
        let mut old_literals = Vec::with_capacity(literals.len() * 3);
        std::mem::swap(&mut old_literals, &mut literals);

        if modifiers.flags.contains(VariableFlags::BASE64) {
            for lit in &old_literals {
                for offset in 0..=2 {
                    if let Some(lit) = encode_base64(lit, &modifiers.base64_alphabet, offset) {
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
                    if let Some(lit) = encode_base64(lit, &modifiers.base64_alphabet, offset) {
                        literals.push(string_to_wide(&lit));
                    }
                }
            }
        }
    }

    literals_to_regex_expr(&literals, case_insensitive)
}

fn literals_to_regex_expr(lits: &[Vec<u8>], case_insensitive: bool) -> String {
    let mut expr = String::new();

    if case_insensitive {
        expr.push_str("(?i)");
    }
    for (i, lit) in lits.iter().enumerate() {
        if i > 0 {
            expr.push('|');
        }
        for b in lit {
            let _ = write!(expr, r"\x{:02x}", *b);
        }
    }

    expr
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

fn hex_string_to_ast(hex_string: Vec<HexToken>) -> Node {
    Node::Concat(hex_string.into_iter().map(hex_token_to_ast).collect())
}

fn hex_token_to_ast(token: HexToken) -> Node {
    match token {
        HexToken::Byte(b) => Node::Literal(b),
        HexToken::MaskedByte(b, mask) => match mask {
            HexMask::Left => Node::Class(ClassKind::Bracketed(BracketedClass {
                items: (0..=0xF)
                    .map(|i| BracketedClassItem::Literal((i << 4) + b))
                    .collect(),
                negated: false,
            })),
            HexMask::Right => {
                let b = b << 4;
                Node::Class(ClassKind::Bracketed(BracketedClass {
                    items: vec![BracketedClassItem::Range(b, b + 0x0F)],
                    negated: false,
                }))
            }
            HexMask::All => Node::Dot,
        },
        HexToken::Jump(jump) => {
            let kind = match (jump.from, jump.to) {
                (from, None) => RepetitionKind::Range(RepetitionRange::AtLeast(from)),
                (from, Some(to)) => RepetitionKind::Range(RepetitionRange::Bounded(from, to)),
            };
            Node::Repetition {
                node: Box::new(Node::Dot),
                kind,
                greedy: false,
            }
        }
        HexToken::Alternatives(elems) => Node::Group(Box::new(Node::Alternation(
            elems.into_iter().map(hex_string_to_ast).collect(),
        ))),
    }
}

/// Error during the compilation of a variable.
#[derive(Debug)]
pub enum VariableCompilationError {
    /// Error when compiling a regex variable.
    Regex(String),

    /// Structural error when applying the `wide` modifier to a regex.
    ///
    /// This really should not happen, and indicates a bug in the code
    /// applying this modifier.
    WidenError,
}

impl std::fmt::Display for VariableCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Regex(e) => e.fmt(f),
            // This should not happen. Please report it upstream if it does.
            Self::WidenError => write!(f, "unable to apply the wide modifier to the regex"),
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
        let mut file = parse_str(&rule_str).unwrap();
        let mut rule = file
            .components
            .pop()
            .map(|v| match v {
                boreal_parser::YaraFileComponent::Rule(v) => v,
                _ => panic!(),
            })
            .unwrap();
        let var = rule.variables.pop().unwrap();
        let hex_string = match var.value {
            VariableDeclarationValue::HexString(s) => s,
            _ => panic!(),
        };

        let ast = hex_string_to_ast(hex_string);
        let mut regex = String::new();
        add_ast_to_string(ast, &mut regex);
        assert_eq!(regex, expected_regex);
    }

    #[test]
    fn test_hex_string_to_regex() {
        test(
            "{ AB ?D 01 }",
            r"\xab[\x0d\x1d\x2d=M\x5dm\x7d\x8d\x9d\xad\xbd\xcd\xdd\xed\xfd]\x01",
        );
        test("{ C7 [-] ?? }", r"\xc7.{0,}?.");
        test(
            "{ C7 [3-] 5? 03 [-6] C7 ( FF 15 | E8 ) [4] 6A ( FF D? | E8 [2-4] ??) }",
            r"\xc7.{3,}?[P-_]\x03.{0,6}?\xc7(\xff\x15|\xe8).{4,4}?j(\xff[\xd0-\xdf]|\xe8.{2,4}?.)",
        );
    }
}
