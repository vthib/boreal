use ::regex::bytes::{Regex, RegexBuilder};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use boreal_parser::{VariableDeclaration, VariableDeclarationValue};
use boreal_parser::{VariableFlags, VariableModifiers};

use super::base64::encode_base64;
use super::CompilationError;

mod atom;
use atom::AtomSet;
mod hex_string;
mod regex;

/// A compiled variable used in a rule.
#[derive(Debug)]
pub struct Variable {
    /// Name of the variable, without the '$'.
    ///
    /// Anonymous variables are just named "".
    pub name: String,

    /// Final expression of the variable.
    ///
    /// This is an option so that it can be moved to the variable set optim.
    pub expr: Option<VariableExpr>,

    /// Matcher that can be used to scan for the variable.
    pub matcher: VariableMatcher,

    /// Regex of the non wide version of the regex.
    ///
    /// This is only set for the specific case of a regex variable, with a wide modifier, that
    /// contains word boundaries.
    /// In this case, the regex expression cannot be "widened", and this regex is used to post
    /// check matches.
    pub non_wide_regex: Option<Regex>,

    /// Flags related to variable modifiers, which are needed during scanning.
    flags: VariableFlags,
}

/// Final expression of a variable.
///
/// This is the final result of the compilation, usable as inputs of scanning utilities, such as
/// regexes, set regexes or aho-corasick algorithms.
#[derive(Debug)]
pub enum VariableExpr {
    /// regex expression.
    Regex {
        /// Complete regex expression.
        expr: String,

        /// Atom set for the variable.
        atom_set: AtomSet,
    },
    /// Set of bytes literal.
    Literals {
        literals: Vec<Vec<u8>>,
        case_insensitive: bool,
    },
}

/// Matcher for a variable.
#[derive(Debug)]
pub enum VariableMatcher {
    Regex(Regex),
    AhoCorasick(Box<AhoCorasick>),
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

    let expr = match value {
        VariableDeclarationValue::Bytes(s) => compile_bytes(s, &modifiers),
        VariableDeclarationValue::Regex(regex) => regex::compile_regex(regex, &modifiers)
            .map(|(expr, v)| {
                non_wide_regex = v;
                expr
            })
            .map_err(|error| CompilationError::VariableCompilation {
                variable_name: name.clone(),
                span: span.clone(),
                error,
            })?,
        VariableDeclarationValue::HexString(hex_string) => {
            // Fullword and wide is not compatible with hex strings
            flags.remove(VariableFlags::FULLWORD);
            flags.remove(VariableFlags::WIDE);

            hex_string::compile_hex_string(hex_string)
        }
    };

    let matcher = build_matcher(&expr).map_err(|error| CompilationError::VariableCompilation {
        variable_name: name.clone(),
        span,
        error,
    })?;

    Ok(Variable {
        name,
        expr: Some(expr),
        matcher,
        non_wide_regex,
        flags,
    })
}

fn build_matcher(expr: &VariableExpr) -> Result<VariableMatcher, VariableCompilationError> {
    match expr {
        VariableExpr::Regex { expr, atom_set: _ } => RegexBuilder::new(expr)
            .unicode(false)
            .octal(false)
            .build()
            .map(VariableMatcher::Regex)
            .map_err(|err| VariableCompilationError::Regex(err.to_string())),
        VariableExpr::Literals {
            literals,
            case_insensitive,
        } => Ok(VariableMatcher::AhoCorasick(Box::new(
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(*case_insensitive)
                .auto_configure(literals)
                .build(literals),
        ))),
    }
}

fn compile_bytes(value: Vec<u8>, modifiers: &VariableModifiers) -> VariableExpr {
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
        return VariableExpr::Literals {
            literals: new_literals,
            case_insensitive,
        };
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

    VariableExpr::Literals {
        literals,
        case_insensitive,
    }
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
