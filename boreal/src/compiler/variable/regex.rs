use boreal_parser::{Regex, VariableFlags, VariableModifiers};
use regex::bytes::RegexBuilder;
use regex_syntax::hir::{visit, Group, GroupKind, Hir, HirKind, Literal, Repetition, Visitor};
use regex_syntax::ParserBuilder;

use crate::regex::add_ast_to_string;

use super::atom::AtomSet;
use super::{VariableCompilationError, VariableExpr};

/// Build a matcher for the given regex and string modifiers.
///
/// This function returns two values:
/// - The regex expression to use to match on this variable
/// - An optional expr used to validate matches, only set in the specific case of a widen regex
///   containing word boundaries.
pub fn compile_regex(
    regex: Regex,
    modifiers: &VariableModifiers,
) -> Result<(VariableExpr, Option<regex::bytes::Regex>), VariableCompilationError> {
    let Regex {
        ast,
        mut case_insensitive,
        dot_all,
        span: _,
    } = regex;

    let mut expr = String::new();
    add_ast_to_string(ast, &mut expr);

    if modifiers.flags.contains(VariableFlags::NOCASE) {
        case_insensitive = true;
    }

    let mut non_wide_regex = None;

    let mods = match (case_insensitive, dot_all) {
        (true, true) => "ism",
        (false, true) => "sm",
        (true, false) => "i",
        (false, false) => "",
    };

    if modifiers.flags.contains(VariableFlags::WIDE) {
        let hir = expr_to_hir(&expr).unwrap();
        let (wide_hir, has_word_boundaries) = hir_to_wide(&hir)?;
        if has_word_boundaries {
            let builder = if mods.is_empty() {
                RegexBuilder::new(&expr)
            } else {
                RegexBuilder::new(&format!("(?{}){}", mods, expr))
            };
            non_wide_regex = Some(
                builder
                    .build()
                    .map_err(|err| VariableCompilationError::Regex(err.to_string()))?,
            );
        }

        if modifiers.flags.contains(VariableFlags::ASCII) {
            expr = Hir::alternation(vec![hir, wide_hir]).to_string();
        } else {
            expr = wide_hir.to_string();
        }
    }

    if !mods.is_empty() {
        expr = format!("(?{}){}", mods, expr);
    }

    Ok((
        VariableExpr::Regex {
            expr,
            atom_set: AtomSet::default(),
        },
        non_wide_regex,
    ))
}

/// Convert a regex expression into a HIR.
fn expr_to_hir(expr: &str) -> Result<Hir, regex_syntax::Error> {
    ParserBuilder::new()
        .octal(false)
        .unicode(false)
        .allow_invalid_utf8(true)
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
fn hir_to_wide(hir: &Hir) -> Result<(Hir, bool), VariableCompilationError> {
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

    /// Does the regex contains word boundaries
    has_word_boundaries: bool,
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
            has_word_boundaries: false,
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
    type Output = (Hir, bool);
    type Err = VariableCompilationError;

    fn finish(self) -> Result<(Hir, bool), Self::Err> {
        match self.hir {
            Some(v) => Ok((v, self.has_word_boundaries)),
            None => Err(VariableCompilationError::WidenError),
        }
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
            // This cannot be transformed properly. Instead, we have two possibilities:
            // - Unwide the input, and run the regex on it.
            // - widen the regex but without the word boundaries. On matches, unwide the match,
            //   then use the non wide regex to check if the match is valid.
            //
            // We use the second solution. Note that there are some differences in results
            // depending on which solution is picked. Those are mostly edge cases on carefully
            // crafted regexes, so it should not matter, but the test
            // `test_variable_regex_word_boundaries_edge_cases` tests some of those.
            //
            // TODO: test and bench the first solution, to build an iterator on all the wide
            // slices that can be found in the input, and run the raw on those unwidden
            // slices.
            HirKind::WordBoundary(_) => {
                self.has_word_boundaries = true;
                self.add(Hir::empty())
            }

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
