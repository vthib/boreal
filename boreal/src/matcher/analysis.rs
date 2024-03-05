use boreal_parser::regex::AssertionKind;

use crate::regex::{visit, Class, Hir, VisitAction, Visitor};

pub struct HirAnalysis {
    // Contains start or end line assertions.
    pub has_start_or_end_line: bool,

    // Contains repetitions.
    pub has_repetitions: bool,

    // Contains greedy repetitions.
    pub has_greedy_repetitions: bool,

    // Contains word boundaries.
    pub has_word_boundaries: bool,

    // Contains word boundaries.
    pub has_classes: bool,

    // Contains alternations.
    pub has_alternations: bool,

    // Number of alternative literals covering the regex.
    //
    // Only set if the regex can be entirely expressed as this literals alternation.
    pub nb_alt_literals: Option<usize>,
}

pub fn analyze_hir(hir: &Hir, dot_all: bool) -> HirAnalysis {
    visit(
        hir,
        HirAnalyser {
            dot_all,

            has_start_or_end_line: false,
            has_repetitions: false,
            has_greedy_repetitions: false,
            has_word_boundaries: false,
            has_classes: false,
            has_alternations: false,

            nb_alt_literals: Some(1),
            alt_stack: Vec::new(),
        },
    )
}

struct HirAnalyser {
    /// Is the `dot_all` flag set.
    ///
    /// This is an input of the visitor, and not an output as other fields are.
    dot_all: bool,

    has_start_or_end_line: bool,
    has_repetitions: bool,
    has_greedy_repetitions: bool,
    has_word_boundaries: bool,
    has_classes: bool,
    has_alternations: bool,

    /// Current count of the number of literals needed to cover the HIR.
    ///
    /// Unset if the HIR cannot be covered with simple literals.
    nb_alt_literals: Option<usize>,

    /// Stack used to store counts of alternation branches.
    alt_stack: Vec<AltStack>,
}

/// Data related to an alternation
struct AltStack {
    /// The count of alt literals before entering the alternation.
    prev_nb_alt_literals: Option<usize>,

    /// The current count of alt literals in visited branches.
    branches_nb_alt_literals: Option<usize>,
}

impl Visitor for HirAnalyser {
    type Output = HirAnalysis;

    fn visit_pre(&mut self, hir: &Hir) -> VisitAction {
        match hir {
            Hir::Mask { negated, .. } => {
                if let Some(count) = &mut self.nb_alt_literals {
                    self.nb_alt_literals = count.checked_mul(if *negated { 256 - 16 } else { 16 });
                }
            }
            Hir::Assertion(kind) => {
                match kind {
                    AssertionKind::StartLine | AssertionKind::EndLine => {
                        self.has_start_or_end_line = true;
                    }
                    AssertionKind::WordBoundary | AssertionKind::NonWordBoundary => {
                        self.has_word_boundaries = true;
                    }
                }
                // Assertions means the regex cannot be just an alternation of literals.
                self.nb_alt_literals = None;
            }
            Hir::Repetition { greedy, .. } => {
                self.has_repetitions = true;
                if *greedy {
                    self.has_greedy_repetitions = true;
                }
                // Repetitions means the regex cannot be just an alternation of literals.
                // TODO: some could be handled.
                self.nb_alt_literals = None;
            }
            Hir::Dot => {
                if let Some(count) = &mut self.nb_alt_literals {
                    self.nb_alt_literals = count.checked_mul(if self.dot_all { 256 } else { 255 });
                }
            }
            Hir::Class(Class { bitmap, .. }) => {
                if let Some(count) = &mut self.nb_alt_literals {
                    self.nb_alt_literals = count.checked_mul(bitmap.count_ones());
                }
                self.has_classes = true;
            }
            Hir::Literal(_) | Hir::Empty | Hir::Group(_) | Hir::Concat(_) => (),
            Hir::Alternation(_) => {
                // Alternations are handled by:
                // - pushing the current count into a stack
                // - after each alternate branch, storing that branch count into the stack
                // - once the all alternation is visited, computing the combinatorics of all
                //   branches, and restoring the count.
                self.alt_stack.push(AltStack {
                    prev_nb_alt_literals: self.nb_alt_literals,
                    branches_nb_alt_literals: Some(0),
                });
                self.nb_alt_literals = Some(1);
                self.has_alternations = true;
            }
        }

        VisitAction::Continue
    }

    fn visit_alternation_in(&mut self) {
        let last_pos = self.alt_stack.len() - 1;
        let v = &mut self.alt_stack[last_pos];

        match (v.branches_nb_alt_literals, self.nb_alt_literals) {
            (Some(bc), Some(c)) => v.branches_nb_alt_literals = bc.checked_add(c),
            (Some(_), None) => v.branches_nb_alt_literals = None,
            (None, _) => (),
        }
        self.nb_alt_literals = Some(1);
    }

    fn visit_post(&mut self, hir: &Hir) {
        if let Hir::Alternation(_) = hir {
            // Close the final branch.
            self.visit_alternation_in();
            // Safety: the visit_pre has pushed an element in the stack.
            let stack = self.alt_stack.pop().unwrap();
            match (stack.prev_nb_alt_literals, stack.branches_nb_alt_literals) {
                (None, _) | (Some(_), None) => self.nb_alt_literals = None,
                (Some(c), Some(bc)) => {
                    self.nb_alt_literals = c.checked_mul(bc);
                }
            }
        }
    }

    fn finish(self) -> Self::Output {
        HirAnalysis {
            has_start_or_end_line: self.has_start_or_end_line,
            has_repetitions: self.has_repetitions,
            has_greedy_repetitions: self.has_greedy_repetitions,
            has_word_boundaries: self.has_word_boundaries,
            has_classes: self.has_classes,
            has_alternations: self.has_alternations,
            nb_alt_literals: self.nb_alt_literals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::expr_to_hir;

    fn analyze_expr(expr: &str, dot_all: bool) -> HirAnalysis {
        analyze_hir(&expr_to_hir(expr), dot_all)
    }

    #[test]
    fn test_count_alt_literals() {
        #[track_caller]
        fn test(expr: &str, dot_all: bool, expected: Option<usize>) {
            let res = analyze_expr(expr, dot_all);
            assert_eq!(res.nb_alt_literals, expected);
        }

        // Assertions and repetitions means no literals
        test(r"^a", false, None);
        test(r"a$", false, None);
        test(r"a\b", false, None);
        test(r"a\B", false, None);

        test(r"a?", false, None);
        test(r"a+?", false, None);
        test(r"a*", false, None);
        test(r"a{2}", false, None);
        test(r"a{1,}", false, None);
        test(r"a{2,3}", false, None);

        // Jumps are not allowed
        test("{ AB [1-] 01 }", false, None);
        test("{ AB [-2] 01 }", false, None);
        test("{ AB [1-2] 01 }", false, None);

        test(r"[a-d_%]", false, Some(6));
        test(r"[^ab]", false, Some(254));
        test(r"\w", false, Some(63));

        // Dot value depends on dot_all
        test(r".", false, Some(255));
        test(r".", true, Some(256));

        // Concat, empty, literal, group, all ok
        test(r"a(b)()e", false, Some(1));

        // Alternations
        test(r"a|f(b|c)|((ab)|)c|d", false, Some(6));

        test("{ AB CD 01 }", false, Some(1));
        test("{ AB ?D 01 }", false, Some(16));
        test("{ D? FE }", false, Some(16));
        test("{ AB ( 01 | 23 45) ( 67 | 89 | F0 ) CD }", false, Some(6));

        test(
            "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
            false,
            Some(13),
        );

        test("{ ( AA | BB ) F? }", false, Some(32));

        test("{ AB ?? 01 }", true, Some(256));
        test("{ AB [1] 01 }", false, Some(255));
        test(
            "{ AB (?A | ?B | ?C | ?D | ?E | ?F | ?0) 01 }",
            false,
            Some(112),
        );

        test("{ AA ( CC | ?? | BB ) }", true, Some(258));
        test("{ AA ~?D BB }", false, Some(240));
        test(r"{ AA [1-3] ?A ?B }", false, None);

        test(r"a\b(1|2)c", false, None);
        test(r"a(\b|2)c", false, None);
        test(r"a.b(|)c", false, Some(510));

        test("{ AA ~?D BB }", false, Some(240));
    }

    #[test]
    fn test_flags() {
        let res = analyze_expr("^a32+", false);
        assert!(res.has_start_or_end_line);
        assert!(res.has_repetitions);
        assert!(res.has_greedy_repetitions);
        assert!(!res.has_word_boundaries);
        assert!(!res.has_classes);
        assert!(!res.has_alternations);

        let res = analyze_expr(r"\b[Ww]o(r|R)d\b", false);
        assert!(!res.has_start_or_end_line);
        assert!(!res.has_repetitions);
        assert!(!res.has_greedy_repetitions);
        assert!(res.has_word_boundaries);
        assert!(res.has_classes);
        assert!(res.has_alternations);

        let res = analyze_expr(r"{ 51 [-3] ( ?A ?? AF | FA ) }", false);
        assert!(!res.has_start_or_end_line);
        assert!(res.has_repetitions);
        assert!(!res.has_greedy_repetitions);
        assert!(!res.has_word_boundaries);
        assert!(!res.has_classes);
        assert!(res.has_alternations);

        let res = analyze_expr(r"\Ba{1,3}?$", false);
        assert!(res.has_start_or_end_line);
        assert!(res.has_repetitions);
        assert!(!res.has_greedy_repetitions);
        assert!(res.has_word_boundaries);
        assert!(!res.has_classes);
        assert!(!res.has_alternations);
    }
}
