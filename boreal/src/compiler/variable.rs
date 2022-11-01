use std::ops::Range;

use ::regex::bytes::{Regex, RegexBuilder};

use boreal_parser::{VariableDeclaration, VariableDeclarationValue};
use boreal_parser::{VariableFlags, VariableModifiers};

use super::base64::encode_base64;
use super::CompilationError;

mod atom;
pub use atom::literals_rank;
mod atomized_regex;
use atomized_regex::AtomizedRegex;
mod hex_string;
mod regex;

/// A compiled variable used in a rule.
#[derive(Debug)]
pub struct Variable {
    /// Name of the variable, without the '$'.
    ///
    /// Anonymous variables are just named "".
    pub name: String,

    /// Is the variable marked as private.
    pub is_private: bool,

    /// Set of literals extracted from the variable.
    ///
    /// Will be used by the AC pass to scan for the variable.
    pub literals: Vec<Vec<u8>>,

    /// Flags related to variable modifiers.
    pub flags: VariableFlags,

    /// Matcher impl for the variable
    pub matcher: Box<dyn Matcher>,
}

impl Variable {
    /// Confirm that an AC match is a match on the given literal.
    ///
    /// This is needed because the AC might optimize literals and get false positive matches.
    /// This function is used to confirm the tentative match does match the literal with the given
    /// index.
    pub fn confirm_ac_literal(&self, mem: &[u8], mat: &Range<usize>, literal_index: usize) -> bool {
        let literal = &self.literals[literal_index];

        if self.flags.contains(VariableFlags::NOCASE) {
            if !literal.eq_ignore_ascii_case(&mem[mat.start..mat.end]) {
                return false;
            }
        } else if literal != &mem[mat.start..mat.end] {
            return false;
        }

        if self.flags.contains(VariableFlags::FULLWORD) && !check_fullword(mem, mat, self.flags) {
            return false;
        }

        true
    }
}

/// A trait used to match the variable on bytes.
pub trait Matcher: std::fmt::Debug {
    /// Check if a match found by the Aho-Corasick scan is valid.
    ///
    /// The `start_position` indicates the index at which matching can be done against the given
    /// `mem` bytes. This is passed as a parameter as the match ranges depend on indices relative
    /// to the start of the mem.
    fn check_ac_match(&self, mem: &[u8], mat: Range<usize>, start_position: usize)
        -> AcMatchStatus;

    /// Find the next match in the given bytes.
    ///
    /// This is only called if either:
    ///
    /// - No literals were returned by [`Self::literals`].
    /// - [`MatchStatus::Unknown`] was returned by [`Self::check_ac_match`].
    ///
    /// If either one of those conditions is true, the variable is scanned on its own by calling
    /// this method.
    fn find_next_match_at(&self, mem: &[u8], offset: usize) -> Option<Range<usize>>;
}

/// State of an aho-corasick match on a [`Matcher`] literals.
#[derive(Clone, Debug)]
pub enum AcMatchStatus {
    /// The literal yields multiple matches (can be empty).
    Multiple(Vec<Range<usize>>),

    /// The literal yields a single match (None if invalid).
    ///
    /// This is an optim to avoid allocating a Vec for the very common case of returning a
    /// single match.
    Single(Range<usize>),

    /// The literal does not give any match.
    None,

    /// Unknown status for the match, will need to be confirmed on its own.
    Unknown,
}

pub(crate) fn compile_variable(decl: VariableDeclaration) -> Result<Variable, CompilationError> {
    let VariableDeclaration {
        name,
        value,
        mut modifiers,
        span,
    } = decl;

    if !modifiers.flags.contains(VariableFlags::WIDE) {
        modifiers.flags.insert(VariableFlags::ASCII);
    }

    let (literals, matcher) = match value {
        VariableDeclarationValue::Bytes(s) => Ok(compile_bytes(s, &modifiers)),
        VariableDeclarationValue::Regex(regex) => {
            if regex.case_insensitive {
                modifiers.flags.insert(VariableFlags::NOCASE);
            }
            regex::compile_regex(regex, modifiers.flags)
        }
        VariableDeclarationValue::HexString(hex_string) => {
            // Fullword and wide is not compatible with hex strings
            modifiers.flags.remove(VariableFlags::FULLWORD);
            modifiers.flags.remove(VariableFlags::WIDE);

            hex_string::compile_hex_string(hex_string, modifiers.flags)
        }
    }
    .map_err(|error| CompilationError::VariableCompilation {
        variable_name: name.clone(),
        span: span.clone(),
        error,
    })?;

    Ok(Variable {
        name,
        is_private: modifiers.flags.contains(VariableFlags::PRIVATE),
        literals,
        flags: modifiers.flags,
        matcher,
    })
}

fn compile_regex_expr(
    expr: &str,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Regex, VariableCompilationError> {
    RegexBuilder::new(expr)
        .unicode(false)
        .octal(false)
        .multi_line(false)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_all)
        .build()
        .map_err(|err| VariableCompilationError::Regex(err.to_string()))
}

fn compile_bytes(
    value: Vec<u8>,
    modifiers: &VariableModifiers,
) -> (Vec<Vec<u8>>, Box<dyn Matcher>) {
    let mut literals = Vec::with_capacity(2);

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
        return (new_literals, Box::new(LiteralsMatcher {}));
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

    (literals, Box::new(LiteralsMatcher {}))
}

/// Matcher on exact literals.
///
/// This can only be used if the variable is expressed exactly by those literals. This variable
/// is matched entirely by the Aho-Corasick scan, and do not need post scanning.
#[derive(Debug)]
struct LiteralsMatcher {}

impl Matcher for LiteralsMatcher {
    fn check_ac_match(
        &self,
        _mem: &[u8],
        mat: Range<usize>,
        _start_position: usize,
    ) -> AcMatchStatus {
        AcMatchStatus::Single(mat)
    }

    fn find_next_match_at(&self, _mem: &[u8], _offset: usize) -> Option<Range<usize>> {
        // This variable should have been covered by the variable set, so we should
        // not be able to reach this code.
        debug_assert!(false);
        None
    }
}

/// Matcher on a variable expressable with a regex.
///
/// Literals can be provided to the Aho-Corasick scan to improve performances.
#[derive(Debug)]
struct RegexMatcher {
    /// Type of regex.
    regex_type: RegexType,

    /// Flags related to variable modifiers, which are needed during scanning.
    flags: VariableFlags,

    /// Regex of the non wide version of the regex.
    ///
    /// This is only set for the specific case of a regex variable, with a wide modifier, that
    /// contains word boundaries.
    /// In this case, the regex expression cannot be "widened", and this regex is used to post
    /// check matches.
    non_wide_regex: Option<Regex>,
}

/// Type of regex to use for matching.
#[derive(Debug)]
enum RegexType {
    /// Raw regex when unable to use atoms.
    Raw(Regex),
    /// Regex with atoms to use in the AC pass
    Atomized(AtomizedRegex),
}

impl Matcher for RegexMatcher {
    fn check_ac_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
    ) -> AcMatchStatus {
        match &self.regex_type {
            RegexType::Atomized(r) => match r.check_literal_match(mem, start_position, mat) {
                AcMatchStatus::Multiple(matches) => AcMatchStatus::Multiple(
                    matches
                        .into_iter()
                        .filter_map(|mat| self.validate_and_update_match(mem, mat))
                        .collect(),
                ),
                AcMatchStatus::Single(mat) => match self.validate_and_update_match(mem, mat) {
                    Some(m) => AcMatchStatus::Single(m),
                    None => AcMatchStatus::None,
                },
                status => status,
            },
            RegexType::Raw(_) => {
                // This variable should not have been covered by the variable set, so we should
                // not be able to reach this code.
                debug_assert!(false);
                AcMatchStatus::Unknown
            }
        }
    }

    fn find_next_match_at(&self, mem: &[u8], mut offset: usize) -> Option<Range<usize>> {
        let regex = match &self.regex_type {
            RegexType::Atomized(_) => {
                // This variable should have been covered by the variable set, so we should
                // not be able to reach this code.
                debug_assert!(false);
                return None;
            }
            RegexType::Raw(r) => r,
        };

        while offset < mem.len() {
            let mat = regex.find_at(mem, offset).map(|m| m.range())?;

            match self.validate_and_update_match(mem, mat.clone()) {
                Some(m) => return Some(m),
                None => {
                    offset = mat.start + 1;
                }
            }
        }
        None
    }
}

impl RegexMatcher {
    fn validate_and_update_match(&self, mem: &[u8], mat: Range<usize>) -> Option<Range<usize>> {
        if self.flags.contains(VariableFlags::FULLWORD) && !check_fullword(mem, &mat, self.flags) {
            return None;
        }

        match self.non_wide_regex.as_ref() {
            Some(regex) => apply_wide_word_boundaries(mat, mem, regex),
            None => Some(mat),
        }
    }
}

/// Check the match respects a possible fullword modifier for the variable.
fn check_fullword(mem: &[u8], mat: &Range<usize>, flags: VariableFlags) -> bool {
    // TODO: We need to know if the match is done on an ascii or wide string to properly check for
    // fullword constraints. This is done in a very ugly way, by going through the match.
    // A better way would be to know which alternation in the match was found.
    let mut match_is_wide = false;

    if flags.contains(VariableFlags::WIDE) {
        match_is_wide = is_match_wide(mat, mem);
        if match_is_wide {
            if mat.start > 1 && mem[mat.start - 1] == b'\0' && is_ascii_alnum(mem[mat.start - 2]) {
                return false;
            }
            if mat.end + 1 < mem.len() && is_ascii_alnum(mem[mat.end]) && mem[mat.end + 1] == b'\0'
            {
                return false;
            }
        }
    }
    if flags.contains(VariableFlags::ASCII) && !match_is_wide {
        if mat.start > 0 && is_ascii_alnum(mem[mat.start - 1]) {
            return false;
        }
        if mat.end < mem.len() && is_ascii_alnum(mem[mat.end]) {
            return false;
        }
    }

    true
}

/// Check the match respects the word boundaries inside the variable.
fn apply_wide_word_boundaries(
    mut mat: Range<usize>,
    mem: &[u8],
    regex: &Regex,
) -> Option<Range<usize>> {
    // The match can be on a non wide regex, if the variable was both ascii and wide. Make sure
    // the match is wide.
    if !is_match_wide(&mat, mem) {
        return Some(mat);
    }

    // Take the previous and next byte, so that word boundaries placed at the beginning or end of
    // the regex can be checked.
    // Note that we must check that the previous/next byte is "wide" as well, otherwise it is not
    // valid.
    let start = if mat.start >= 2 && mem[mat.start - 1] == b'\0' {
        mat.start - 2
    } else {
        mat.start
    };

    // Remove the wide bytes, and then use the non wide regex to check for word boundaries.
    // Since when checking word boundaries, we might match more than the initial match (because of
    // non greedy repetitions bounded by word boundaries), we need to add more data at the end.
    // How much? We cannot know, but including too much would be too much of a performance tank.
    // This is arbitrarily capped at 500 for the moment (or until the string is no longer wide)...
    // TODO bench this
    let unwiden_mem = unwide(&mem[start..std::cmp::min(mem.len(), mat.end + 500)]);

    let expected_start = if start < mat.start { 1 } else { 0 };
    match regex.find(&unwiden_mem) {
        Some(m) if m.start() == expected_start => {
            // Modify the match end. This is needed because the application of word boundary
            // may modify the match. Since we matched on non wide mem though, double the size.
            mat.end = mat.start + 2 * (m.end() - m.start());
            Some(mat)
        }
        _ => None,
    }
}

fn unwide(mem: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();

    for b in mem.chunks_exact(2) {
        if b[1] != b'\0' {
            break;
        }
        res.push(b[0]);
    }

    res
}

// Is a match a wide string or an ascii one
fn is_match_wide(mat: &Range<usize>, mem: &[u8]) -> bool {
    if (mat.end - mat.start) % 2 != 0 {
        return false;
    }
    if mat.is_empty() {
        return true;
    }

    !mem[(mat.start + 1)..mat.end]
        .iter()
        .step_by(2)
        .any(|c| *c != b'\0')
}

fn is_ascii_alnum(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c)
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
    use boreal_parser::{parse_str, HexToken, VariableDeclarationValue};

    #[track_caller]
    pub(super) fn parse_hex_string(hex_string: &str) -> Vec<HexToken> {
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
        match var.value {
            VariableDeclarationValue::HexString(s) => s,
            _ => panic!(),
        }
    }
}
