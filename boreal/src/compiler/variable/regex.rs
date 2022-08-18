use boreal_parser::{Regex, VariableFlags, VariableModifiers};
use grep_regex::RegexMatcherBuilder;
use regex_syntax::hir::{visit, Group, GroupKind, Hir, HirKind, Literal, Repetition, Visitor};
use regex_syntax::ParserBuilder;

use super::{VariableCompilationError, VariableMatcher};

/// Build a matcher for the given regex and string modifiers.
pub fn build_regex_matcher(
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

/// Convert a regex expression into a HIR.
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