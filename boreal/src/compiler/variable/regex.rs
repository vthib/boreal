use boreal_parser::regex::AssertionKind;
use boreal_parser::VariableModifiers;

use crate::regex::{regex_hir_to_string, visit, Hir, Regex, VisitAction, Visitor};

use super::analysis::HirAnalysis;
use super::literals::LiteralsDetails;
use super::matcher::MatcherKind;
use super::{only_literals, CompiledVariable, VariableCompilationError};

/// Build a matcher for the given regex and string modifiers.
///
/// This function returns two values:
/// - The regex expression to use to match on this variable
/// - An optional expr used to validate matches, only set in the specific case of a widen regex
///   containing word boundaries.
pub(super) fn compile_regex(
    hir: &Hir,
    dot_all: bool,
    modifiers: &VariableModifiers,
) -> Result<CompiledVariable, VariableCompilationError> {
    // Try to convert into only literals if possible
    // TODO: handle more modifiers
    if !modifiers.nocase && !modifiers.wide {
        if let Some(literals) = only_literals::hir_to_only_literals(hir, dot_all) {
            return Ok(CompiledVariable {
                literals,
                matcher_kind: MatcherKind::Literals,
                non_wide_regex: None,
            });
        }
    }

    let LiteralsDetails {
        mut literals,
        pre_hir,
        post_hir,
    } = super::literals::get_literals_details(hir);

    // If some literals are too small, don't use them, they would match too
    // many times.
    if literals.iter().any(|lit| lit.len() < 2) {
        literals.clear();
    }
    apply_ascii_wide_flags_on_literals(&mut literals, modifiers);

    let mut use_ac = !literals.is_empty();

    let analysis = visit(hir, HirAnalysis::default());

    if analysis.has_start_or_end_line {
        // Do not use an AC if anchors are present, it will be much efficient to just run
        // the regex directly.
        use_ac = false;
    }

    if let Some(pre) = &pre_hir {
        let left_analysis = visit(pre, HirAnalysis::default());
        if left_analysis.has_greedy_repetitions {
            // Greedy repetitions on the left side of the literals is not for the moment handled.
            // This is because the repetition can "eat" the literals against which we matched,
            // meaning that the pre/post split is not valid.
            //
            // For example, a regex that looks like: `a.+foo.+b` will extract the literal foo,
            // but against the string `aafoobbaafoobb`, it will match on the entire string,
            // while we will match against both "foo" occurrences.
            use_ac = false;
        }
    }

    let matcher_kind = if use_ac {
        let pre = pre_hir.map(|hir| convert_hir_to_string_with_flags(&hir, modifiers));
        let post = post_hir.map(|hir| convert_hir_to_string_with_flags(&hir, modifiers));

        MatcherKind::Atomized {
            left_validator: compile_validator(pre, modifiers.nocase, dot_all)?,
            right_validator: compile_validator(post, modifiers.nocase, dot_all)?,
        }
    } else {
        let expr = convert_hir_to_string_with_flags(hir, modifiers);

        MatcherKind::Raw(compile_regex_expr(expr, modifiers.nocase, dot_all)?)
    };

    let non_wide_regex = if analysis.has_word_boundaries && modifiers.wide {
        let expr = regex_hir_to_string(hir);
        Some(compile_regex_expr(expr, modifiers.nocase, dot_all)?)
    } else {
        None
    };

    Ok(CompiledVariable {
        literals,
        matcher_kind,
        non_wide_regex,
    })
}

fn compile_validator(
    expr: Option<String>,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Option<Regex>, VariableCompilationError> {
    match expr {
        Some(expr) => Ok(Some(compile_regex_expr(expr, case_insensitive, dot_all)?)),
        None => Ok(None),
    }
}

fn apply_ascii_wide_flags_on_literals(literals: &mut Vec<Vec<u8>>, modifiers: &VariableModifiers) {
    if !modifiers.wide {
        return;
    }

    if modifiers.ascii {
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

/// Convert the AST of a regex variable to a string, taking into account variable modifiers.
fn convert_hir_to_string_with_flags(hir: &Hir, modifiers: &VariableModifiers) -> String {
    if modifiers.wide {
        let wide_hir = visit(hir, HirWidener::new());

        if modifiers.ascii {
            format!(
                "{}|{}",
                regex_hir_to_string(hir),
                regex_hir_to_string(&wide_hir),
            )
        } else {
            regex_hir_to_string(&wide_hir)
        }
    } else {
        regex_hir_to_string(hir)
    }
}

fn compile_regex_expr(
    expr: String,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Regex, VariableCompilationError> {
    Regex::from_string(expr, case_insensitive, dot_all).map_err(VariableCompilationError::Regex)
}

/// Visitor used to transform a regex HIR to make the regex match "wide" characters.
///
/// This is intented to transform a regex with the "wide" modifier, that is make it so
/// the regex will not match raw ASCII but UCS-2.
///
/// This means translating every match on a literal or class into this literal/class followed by a
/// nul byte. See the implementation of the [`Visitor`] trait on [`NodeWidener`] for more details.
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

    fn add(&mut self, hir: Hir) {
        if self.stack.is_empty() {
            // Empty stack: we should only have a single HIR to set at top-level.
            let res = self.hir.replace(hir);
            assert!(res.is_none(), "top level HIR hir already set");
        } else {
            let pos = self.stack.len() - 1;
            self.stack[pos].push(hir);
        }
    }

    fn add_wide(&mut self, hir: Hir) {
        let nul_byte = Hir::Literal(b'\0');

        if self.stack.is_empty() {
            let res = self.hir.replace(Hir::Concat(vec![hir, nul_byte]));
            assert!(res.is_none(), "top level HIR hir already set");
        } else {
            let pos = self.stack.len() - 1;
            let level = &mut self.stack[pos];
            if level.in_concat {
                level.hirs.push(hir);
                level.hirs.push(nul_byte);
            } else {
                level
                    .hirs
                    .push(Hir::Group(Box::new(Hir::Concat(vec![hir, nul_byte]))));
            }
        }
    }
}

impl Visitor for HirWidener {
    type Output = Hir;

    fn finish(self) -> Hir {
        // Safety: there is a top-level node, the one we visit first.
        self.hir.unwrap()
    }

    fn visit_pre(&mut self, node: &Hir) -> VisitAction {
        match node {
            Hir::Dot
            | Hir::Empty
            | Hir::Literal(_)
            | Hir::Mask { .. }
            | Hir::Class(_)
            | Hir::Assertion(_) => (),

            Hir::Repetition { .. } | Hir::Group(_) | Hir::Alternation(_) => {
                self.stack.push(StackLevel::new(false));
            }
            Hir::Concat(_) => {
                self.stack.push(StackLevel::new(true));
            }
        }
        VisitAction::Continue
    }

    fn visit_post(&mut self, hir: &Hir) {
        match hir {
            Hir::Empty => self.add(Hir::Empty),

            // Literal, dot or class: add a nul_byte after it
            Hir::Dot => self.add_wide(Hir::Dot),
            Hir::Literal(lit) => self.add_wide(Hir::Literal(*lit)),
            Hir::Mask { .. } => self.add_wide(hir.clone()),
            Hir::Class(cls) => self.add_wide(Hir::Class(cls.clone())),

            // Anchor: no need to add anything
            Hir::Assertion(AssertionKind::StartLine) | Hir::Assertion(AssertionKind::EndLine) => {
                self.add(hir.clone());
            }

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
            Hir::Assertion(AssertionKind::WordBoundary)
            | Hir::Assertion(AssertionKind::NonWordBoundary) => {
                self.add(Hir::Empty);
            }

            Hir::Repetition {
                hir: _,
                kind,
                greedy,
            } => {
                // Safety:
                // - first pop is guaranteed to contain an element, since this is a "post" visit,
                //   and the pre visit push an element on the stack.
                // - second pop is guaranteed to contain an element, since we walked into the
                //   repetition node, which pushed an element into the stack.
                let hir = self.stack.pop().unwrap().hirs.pop().unwrap();
                self.add(Hir::Repetition {
                    kind: kind.clone(),
                    greedy: *greedy,
                    hir: Box::new(hir),
                });
            }
            Hir::Group(_) => {
                // Safety:
                // - first pop is guaranteed to contain an element, since this is a "post" visit,
                //   and the pre visit push an element on the stack.
                // - second pop is guaranteed to contain an element, since we walked into the
                //   group node, which pushed an element into the stack.
                let node = self.stack.pop().unwrap().hirs.pop().unwrap();
                self.add(Hir::Group(Box::new(node)));
            }
            Hir::Concat(_) => {
                // Safety:
                // - pop is guaranteed to contain an element, since this is a "post" visit,
                //   and the pre visit push an element on the stack.
                let vec = self.stack.pop().unwrap().hirs;
                self.add(Hir::Concat(vec));
            }
            Hir::Alternation(_) => {
                // Safety:
                // - pop is guaranteed to contain an element, since this is a "post" visit,
                //   and the pre visit push an element on the stack.
                let vec = self.stack.pop().unwrap().hirs;
                self.add(Hir::Alternation(vec));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(HirWidener::new());
        test_type_traits_non_clonable(StackLevel::new(false));
    }
}
