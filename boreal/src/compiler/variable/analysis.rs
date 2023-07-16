use boreal_parser::regex::AssertionKind;

use crate::regex::{Hir, VisitAction, Visitor};

#[derive(Default)]
pub struct HirAnalysis {
    pub has_start_or_end_line: bool,
    pub has_greedy_repetitions: bool,
    pub has_word_boundaries: bool,
}

impl Visitor for HirAnalysis {
    type Output = Self;

    fn visit_pre(&mut self, hir: &Hir) -> VisitAction {
        match hir {
            Hir::Assertion(AssertionKind::StartLine) | Hir::Assertion(AssertionKind::EndLine) => {
                self.has_start_or_end_line = true;
            }
            Hir::Assertion(AssertionKind::WordBoundary)
            | Hir::Assertion(AssertionKind::NonWordBoundary) => {
                self.has_word_boundaries = true;
            }
            Hir::Repetition { greedy: true, .. } => {
                self.has_greedy_repetitions = true;
            }
            _ => (),
        }

        VisitAction::Continue
    }

    fn finish(self) -> Self::Output {
        self
    }
}
