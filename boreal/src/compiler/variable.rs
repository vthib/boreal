use std::fmt::Write;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use grep_regex::{RegexMatcher, RegexMatcherBuilder};

use boreal_parser::{HexMask, HexToken, VariableFlags, VariableModifiers};
use boreal_parser::{Regex, VariableDeclaration, VariableDeclarationValue};
use regex_syntax::hir::{visit, Group, GroupKind, Hir, HirKind, Literal, Repetition, Visitor};
use regex_syntax::ParserBuilder;

use super::base64::encode_base64;
use super::CompilationError;

#[derive(Debug)]
pub struct Variable {
    pub name: String,

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
                variable_name: name.clone(),
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
                    variable_name: name.clone(),
                    error,
                }
            })?)
        }
    };

    Ok(Variable {
        name,
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
        mut expr,
        mut case_insensitive,
        dot_all,
        span: _,
    } = regex;

    if modifiers.flags.contains(VariableFlags::NOCASE) {
        case_insensitive = true;
    }

    if modifiers.flags.contains(VariableFlags::WIDE) {
        let hir = expr_to_hir(&expr, case_insensitive, dot_all).unwrap();
        let wide_hir = hir_to_wide(&hir);

        if modifiers.flags.contains(VariableFlags::ASCII) {
            expr = Hir::alternation(vec![hir, wide_hir]).to_string();
        } else {
            expr = wide_hir.to_string();
        }
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

fn expr_to_hir(
    expr: &str,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Hir, regex_syntax::Error> {
    ParserBuilder::new()
        .octal(false)
        .unicode(false)
        .allow_invalid_utf8(true)
        .case_insensitive(case_insensitive)
        .multi_line(dot_all)
        .dot_matches_new_line(dot_all)
        .build()
        .parse(expr)
}

fn hir_to_wide(hir: &Hir) -> Hir {
    visit(hir, HirWidener::new()).unwrap()
}

#[derive(Debug)]
struct HirWidener {
    // Top-level HIR expr being constructed
    hir: Hir,

    // Accumulation of HIR nodes when building a compound expr.
    nodes: Vec<Nodes>,
}

#[derive(Debug)]
struct Nodes {
    nodes: Vec<Hir>,

    in_concat: bool,
}

impl Nodes {
    fn new(in_concat: bool) -> Self {
        Self {
            nodes: Vec::new(),
            in_concat,
        }
    }

    fn push(&mut self, hir: Hir) {
        self.nodes.push(hir);
    }
}

impl HirWidener {
    fn new() -> Self {
        Self {
            hir: Hir::empty(),
            nodes: Vec::new(),
        }
    }

    fn add(&mut self, hir: Hir) {
        if self.nodes.is_empty() {
            self.hir = hir;
        } else {
            let pos = self.nodes.len() - 1;
            self.nodes[pos].push(hir);
        }
    }

    fn add_wide(&mut self, hir: Hir) {
        let nul_byte = Hir::literal(Literal::Unicode('\0'));

        if self.nodes.is_empty() {
            self.hir = Hir::concat(vec![hir, nul_byte]);
        } else {
            let pos = self.nodes.len() - 1;
            let nodes = &mut self.nodes[pos];
            if nodes.in_concat {
                nodes.nodes.push(hir);
                nodes.nodes.push(nul_byte);
            } else {
                nodes.nodes.push(Hir::group(Group {
                    kind: GroupKind::NonCapturing,
                    hir: Box::new(Hir::concat(vec![hir, nul_byte])),
                }));
            }
        }
    }

    fn pop(&mut self) -> Option<Vec<Hir>> {
        self.nodes.pop().map(|v| v.nodes)
    }
}

#[derive(Debug)]
struct Illformed;

impl Visitor for HirWidener {
    type Output = Hir;
    type Err = Illformed;

    fn finish(self) -> Result<Hir, Self::Err> {
        Ok(self.hir)
    }

    fn visit_pre(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match *hir.kind() {
            HirKind::Empty
            | HirKind::Literal(_)
            | HirKind::Class(_)
            | HirKind::Anchor(_)
            | HirKind::WordBoundary(_) => {}

            HirKind::Repetition(_) | HirKind::Group(_) | HirKind::Alternation(_) => {
                self.nodes.push(Nodes::new(false));
            }
            HirKind::Concat(_) => {
                self.nodes.push(Nodes::new(true));
            }
        }
        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            HirKind::Empty => self.add(Hir::empty()),
            HirKind::Literal(lit) => {
                self.add_wide(Hir::literal(lit.clone()));
            }
            HirKind::Class(cls) => {
                self.add_wide(Hir::class(cls.clone()));
            }
            HirKind::Anchor(anchor) => {
                self.add(Hir::anchor(anchor.clone()));
            }
            HirKind::WordBoundary(boundary) => {
                self.add(Hir::word_boundary(boundary.clone()));
            }

            HirKind::Repetition(repetition) => {
                let hir = self.pop().and_then(|mut v| v.pop()).ok_or(Illformed)?;
                self.add(Hir::repetition(Repetition {
                    kind: repetition.kind.clone(),
                    greedy: repetition.greedy,
                    hir: Box::new(hir),
                }));
            }
            HirKind::Group(group) => {
                let hir = self.pop().and_then(|mut v| v.pop()).ok_or(Illformed)?;
                self.add(Hir::group(Group {
                    kind: group.kind.clone(),
                    hir: Box::new(hir),
                }));
            }
            HirKind::Concat(_) => {
                let vec = self.pop().ok_or(Illformed)?;
                self.add(Hir::concat(vec));
            }
            HirKind::Alternation(_) => {
                let vec = self.pop().ok_or(Illformed)?;
                self.add(Hir::alternation(vec));
            }
        }
        Ok(())
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
