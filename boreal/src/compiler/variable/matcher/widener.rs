use boreal_parser::regex::AssertionKind;

use crate::regex::{visit, Hir, VisitAction, Visitor};

pub fn widen_hir(hir: &Hir) -> Hir {
    visit(hir, HirWidener::new())
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
