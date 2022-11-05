use std::convert::Infallible;

use boreal_parser::regex::{AssertionKind, Node};
use boreal_parser::VariableFlags;
use regex::bytes::Regex;
use regex_syntax::hir::{visit, Group, GroupKind, Hir, HirKind, Literal, Repetition, Visitor};
use regex_syntax::ParserBuilder;

use crate::regex::{regex_ast_to_string, VisitAction, Visitor as AstVisitor};

use super::atom::AtomsDetails;
use super::{CompiledVariable, MatcherType, VariableCompilationError};

/// Build a matcher for the given regex and string modifiers.
///
/// This function returns two values:
/// - The regex expression to use to match on this variable
/// - An optional expr used to validate matches, only set in the specific case of a widen regex
///   containing word boundaries.
pub(super) fn compile_regex(
    ast: &Node,
    mut case_insensitive: bool,
    dot_all: bool,
    flags: VariableFlags,
) -> Result<CompiledVariable, VariableCompilationError> {
    if flags.contains(VariableFlags::NOCASE) {
        case_insensitive = true;
    }

    let AtomsDetails {
        mut literals,
        mut pre,
        mut post,
    } = super::atom::get_atoms_details(ast);

    let use_ac =
        crate::regex::visit(ast, AcCompatibility::default()).unwrap_or_else(|e| match e {});

    let mut has_wide_word_boundaries = false;
    let matcher_type = if literals.is_empty() || !use_ac {
        let mut expr = regex_ast_to_string(ast);
        has_wide_word_boundaries |= apply_ascii_wide_flags_on_regex_expr(&mut expr, flags)?;
        apply_ascii_wide_flags_on_literals(&mut literals, flags);

        MatcherType::Raw(super::compile_regex_expr(&expr, case_insensitive, dot_all)?)
    } else {
        if let Some(v) = &mut pre {
            has_wide_word_boundaries |= apply_ascii_wide_flags_on_regex_expr(v, flags)?;
        }
        if let Some(v) = &mut post {
            has_wide_word_boundaries |= apply_ascii_wide_flags_on_regex_expr(v, flags)?;
        }
        apply_ascii_wide_flags_on_literals(&mut literals, flags);

        MatcherType::Atomized {
            left_validator: compile_validator(pre, case_insensitive, dot_all)?,
            right_validator: compile_validator(post, case_insensitive, dot_all)?,
        }
    };

    let non_wide_regex = if has_wide_word_boundaries {
        let expr = regex_ast_to_string(ast);
        Some(super::compile_regex_expr(&expr, case_insensitive, dot_all)?)
    } else {
        None
    };

    Ok(CompiledVariable {
        literals,
        matcher_type,
        non_wide_regex,
    })
}

struct AcCompatibility(bool);

impl Default for AcCompatibility {
    fn default() -> Self {
        Self(true)
    }
}

impl AstVisitor for AcCompatibility {
    type Output = bool;
    type Err = Infallible;

    fn visit_pre(&mut self, node: &Node) -> Result<VisitAction, Self::Err> {
        match node {
            Node::Assertion(AssertionKind::StartLine) | Node::Assertion(AssertionKind::EndLine) => {
                // Do not use an AC if anchors are present, it will be much efficient to just run
                // the regex directly.
                self.0 = false;
            }
            Node::Repetition { greedy: true, .. } => {
                // TODO: allow greedy when it does not contain characters from the literals?
                // This would allow matching \s* which would be useful.
                self.0 = false;
            }
            _ => (),
        }

        Ok(VisitAction::Continue)
    }

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self.0)
    }
}

fn compile_validator(
    expr: Option<String>,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Option<Regex>, VariableCompilationError> {
    match expr {
        Some(expr) => Ok(Some(super::compile_regex_expr(
            &expr,
            case_insensitive,
            dot_all,
        )?)),
        None => Ok(None),
    }
}
fn apply_ascii_wide_flags_on_literals(literals: &mut Vec<Vec<u8>>, flags: VariableFlags) {
    if !flags.contains(VariableFlags::WIDE) {
        return;
    }

    if flags.contains(VariableFlags::ASCII) {
        let wide_literals: Vec<_> = literals.iter().map(|v| widen_literal(v)).collect();
        literals.extend(wide_literals);
    } else {
        for lit in literals {
            *lit = widen_literal(lit);
        }
    }
}

fn widen_literal(literal: &[u8]) -> Vec<u8> {
    let mut new_lit = Vec::with_capacity(literal.len() * 2);
    for b in literal {
        new_lit.push(*b);
        new_lit.push(0);
    }
    new_lit
}

pub fn apply_ascii_wide_flags_on_regex_expr(
    expr: &mut String,
    flags: VariableFlags,
) -> Result<bool, VariableCompilationError> {
    if flags.contains(VariableFlags::WIDE) {
        let hir = expr_to_hir(expr).unwrap();
        let (wide_hir, has_wide_word_boundaries) = hir_to_wide(&hir)?;

        *expr = if flags.contains(VariableFlags::ASCII) {
            Hir::alternation(vec![hir, wide_hir]).to_string()
        } else {
            wide_hir.to_string()
        };
        Ok(has_wide_word_boundaries)
    } else {
        Ok(false)
    }
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
