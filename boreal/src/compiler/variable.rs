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
        span,
    } = decl;
    let mut flags = modifiers.flags;
    if !flags.contains(VariableFlags::WIDE) {
        flags.insert(VariableFlags::ASCII);
    }

    let matcher = match value {
        VariableDeclarationValue::Bytes(s) => build_string_matcher(s, &modifiers),
        VariableDeclarationValue::Regex(regex) => {
            let matcher = build_regex_matcher(regex, &modifiers);
            matcher.map_err(|error| CompilationError::VariableCompilation {
                variable_name: name.clone(),
                span,
                error,
            })?
        }
        VariableDeclarationValue::HexString(hex_string) => {
            let mut regex = String::new();
            hex_string_to_regex(hex_string, &mut regex);

            // Fullword and wide is not compatible with hex strings
            flags.remove(VariableFlags::FULLWORD);
            flags.remove(VariableFlags::WIDE);

            let mut matcher = RegexMatcherBuilder::new();
            let matcher = matcher
                .unicode(false)
                .octal(false)
                .dot_matches_new_line(true)
                .build(&regex);
            VariableMatcher::Regex(matcher.map_err(|error| {
                CompilationError::VariableCompilation {
                    variable_name: name.clone(),
                    span,
                    error: VariableCompilationError::GrepRegex(error),
                }
            })?)
        }
    };

    Ok(Variable {
        name,
        matcher,
        flags,
    })
}

fn build_string_matcher(value: Vec<u8>, modifiers: &VariableModifiers) -> VariableMatcher {
    let mut builder = AhoCorasickBuilder::new();
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
) -> Result<VariableMatcher, VariableCompilationError> {
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
        let wide_hir = hir_to_wide(&hir)?;

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
        .map_err(VariableCompilationError::GrepRegex)
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

/// Transform a regex HIR to make the regex match "wide" characters.
///
/// This is intented to transform a regex with the "wide" modifier, that is make it so
/// the regex will not match raw ASCII but UCS-2.
///
/// This means translating every match on a literal or class into this literal/class followed by a
/// nul byte. See the implementation of the [`Visitor`] trait on [`HirWidener`] for more details.
fn hir_to_wide(hir: &Hir) -> Result<Hir, VariableCompilationError> {
    visit(hir, HirWidener::new())
}

/// Struct used to hold state while visiting the original HIR and building the widen one.
#[derive(Debug)]
struct HirWidener {
    /// Top level HIR object
    hir: Option<Hir>,

    /// Stack of HIR objects built.
    ///
    /// Each visit to a compound HIR value (group, alternation, etc) will push a new level
    /// to the stack. Then when we finish visiting the compound value, the level will be pop-ed,
    /// and the new compound HIR value built.
    stack: Vec<StackLevel>,
}

#[derive(Debug)]
struct StackLevel {
    /// HIR values built in this level.
    hirs: Vec<Hir>,

    /// Is this level for a concat HIR value.
    in_concat: bool,
}

impl StackLevel {
    fn new(in_concat: bool) -> Self {
        Self {
            hirs: Vec::new(),
            in_concat,
        }
    }

    fn push(&mut self, hir: Hir) {
        self.hirs.push(hir);
    }
}

impl HirWidener {
    fn new() -> Self {
        Self {
            hir: None,
            stack: Vec::new(),
        }
    }

    fn add(&mut self, hir: Hir) -> Result<(), VariableCompilationError> {
        if self.stack.is_empty() {
            // Empty stack: we should only have a single HIR to set at top-level.
            match self.hir.replace(hir) {
                Some(_) => Err(VariableCompilationError::WidenError),
                None => Ok(()),
            }
        } else {
            let pos = self.stack.len() - 1;
            self.stack[pos].push(hir);
            Ok(())
        }
    }

    fn add_wide(&mut self, hir: Hir) -> Result<(), VariableCompilationError> {
        let nul_byte = Hir::literal(Literal::Unicode('\0'));

        if self.stack.is_empty() {
            match self.hir.replace(Hir::concat(vec![hir, nul_byte])) {
                Some(_) => Err(VariableCompilationError::WidenError),
                None => Ok(()),
            }
        } else {
            let pos = self.stack.len() - 1;
            let level = &mut self.stack[pos];
            if level.in_concat {
                level.hirs.push(hir);
                level.hirs.push(nul_byte);
            } else {
                level.hirs.push(Hir::group(Group {
                    kind: GroupKind::NonCapturing,
                    hir: Box::new(Hir::concat(vec![hir, nul_byte])),
                }));
            }
            Ok(())
        }
    }

    fn pop(&mut self) -> Option<Vec<Hir>> {
        self.stack.pop().map(|v| v.hirs)
    }
}

impl Visitor for HirWidener {
    type Output = Hir;
    type Err = VariableCompilationError;

    fn finish(self) -> Result<Hir, Self::Err> {
        self.hir.ok_or(VariableCompilationError::WidenError)
    }

    fn visit_pre(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match *hir.kind() {
            HirKind::Empty
            | HirKind::Literal(_)
            | HirKind::Class(_)
            | HirKind::Anchor(_)
            | HirKind::WordBoundary(_) => {}

            HirKind::Repetition(_) | HirKind::Group(_) | HirKind::Alternation(_) => {
                self.stack.push(StackLevel::new(false));
            }
            HirKind::Concat(_) => {
                self.stack.push(StackLevel::new(true));
            }
        }
        Ok(())
    }

    fn visit_post(&mut self, hir: &Hir) -> Result<(), Self::Err> {
        match hir.kind() {
            HirKind::Empty => self.add(Hir::empty()),

            // Literal or class: add a nul_byte after it
            HirKind::Literal(lit) => self.add_wide(Hir::literal(lit.clone())),
            HirKind::Class(cls) => self.add_wide(Hir::class(cls.clone())),

            // Anchor: no need to add anything
            HirKind::Anchor(anchor) => self.add(Hir::anchor(anchor.clone())),

            // Boundary is tricky as it looks for a match between two characters:
            // \b means: word on the left side, non-word on the right, or the opposite:
            // - \ta, a\t, \0a, \t\0 matches
            // - ab, \t\n does not match
            // When the input is wide, this is harder:
            // - \t\0a\0, a\0\t\0 matches
            // - a\0b\0, \t\0\b\0 does not match
            //
            // This can be handled if the boundary is the very start or end of the regex.
            // However, if it is in the middle, it is not really possible to translate it.
            // For the moment, reject it, handling it at the start/end of the regex
            // can be implemented without too much issue in the near future.
            HirKind::WordBoundary(_) => Err(VariableCompilationError::WideWithBoundary),

            HirKind::Repetition(repetition) => {
                let hir = self
                    .pop()
                    .and_then(|mut v| v.pop())
                    .ok_or(VariableCompilationError::WidenError)?;
                self.add(Hir::repetition(Repetition {
                    kind: repetition.kind.clone(),
                    greedy: repetition.greedy,
                    hir: Box::new(hir),
                }))
            }
            HirKind::Group(group) => {
                let hir = self
                    .pop()
                    .and_then(|mut v| v.pop())
                    .ok_or(VariableCompilationError::WidenError)?;
                self.add(Hir::group(Group {
                    kind: group.kind.clone(),
                    hir: Box::new(hir),
                }))
            }
            HirKind::Concat(_) => {
                let vec = self.pop().ok_or(VariableCompilationError::WidenError)?;
                self.add(Hir::concat(vec))
            }
            HirKind::Alternation(_) => {
                let vec = self.pop().ok_or(VariableCompilationError::WidenError)?;
                self.add(Hir::alternation(vec))
            }
        }
    }
}

/// Error during the compilation of a variable.
#[derive(Debug)]
pub enum VariableCompilationError {
    /// Error returned by [`grep_regex`] when compiling a variable
    // TODO: this should not be part of the public API
    GrepRegex(grep_regex::Error),

    /// Regexes with boundaries cannot use the `wide` modifier
    WideWithBoundary,

    /// Structural error when applying the `wide` modifier to a regex.
    ///
    /// This really should not happen, and indicates a bug in the code
    /// applying this modifier.
    WidenError,
}

impl std::fmt::Display for VariableCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::GrepRegex(e) => e.fmt(f),
            Self::WideWithBoundary => write!(
                f,
                "wide modifier cannot be applied on regexes containing boundaries"
            ),
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
        test(
            "{ C7 [3-] 5? 03 [-6] C7 ( FF 15 | E8 ) [4] 6A ( FF D? | E8 [2-4] ??) }",
            r"\xC7.{3,}?[\x50-\x5F]\x03.{0,6}?\xC7((\xFF\x15)|(\xE8)).{4}?\x6A((\xFF[\xD0-\xDF])|(\xE8.{2,4}?.))",
        );
    }
}
