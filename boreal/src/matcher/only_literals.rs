use crate::bitmaps::Bitmap;
use crate::regex::{visit, Class, Hir, VisitAction, Visitor};

/// Can the hex string be expressed using only literals.
pub(super) fn hir_to_only_literals(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    visit(hir, Extractor::new())
}

struct Extractor {
    // Combination of all possible literals.
    all: Option<Vec<Vec<u8>>>,
    // Buffer of a string of bytes to be added to all the literals.
    buffer: Vec<u8>,

    // Stack used when building alternations of literals
    alt_stack: Vec<AltLiterals>,
}

struct AltLiterals {
    prev_lits: Option<Vec<Vec<u8>>>,

    branch_lits: Vec<Vec<u8>>,
}

impl Extractor {
    fn new() -> Self {
        Self {
            all: Some(Vec::new()),
            buffer: Vec::new(),
            alt_stack: Vec::new(),
        }
    }

    fn add_byte(&mut self, b: u8) {
        self.buffer.push(b);
    }

    fn add_masked_byte(&mut self, b: u8, mask: u8) {
        // First, commit the local buffer, to have a proper list of all possible literals
        self.commit_buffer();

        // Then, build the suffixes corresponding to the mask.
        let suffixes: Vec<Vec<u8>> = match mask {
            0x0F => (0..=0xF).map(|i| vec![(i << 4) + b]).collect(),
            _ => (b..=(b + 0xF)).map(|i| vec![i]).collect(),
        };
        self.cartesian_product(&suffixes);
    }

    fn add_class(&mut self, bitmap: &Bitmap) {
        // First, commit the local buffer, to have a proper list of all possible literals
        self.commit_buffer();

        if let Some(all) = self.all.as_mut() {
            *all = all
                .iter()
                .flat_map(|prefix| {
                    bitmap.iter().map(move |byte| {
                        let mut v = Vec::with_capacity(prefix.len() + 1);
                        v.extend(prefix);
                        v.push(byte);
                        v
                    })
                })
                .collect();
        }
    }

    fn cartesian_product(&mut self, suffixes: &[Vec<u8>]) {
        if let Some(all) = self.all.as_mut() {
            *all = all
                .iter()
                .flat_map(|prefix| {
                    suffixes.iter().map(|suffix| {
                        prefix
                            .iter()
                            .copied()
                            .chain(suffix.iter().copied())
                            .collect()
                    })
                })
                .collect();
        }
    }

    fn commit_buffer(&mut self) {
        let buffer = std::mem::take(&mut self.buffer);
        if let Some(all) = self.all.as_mut() {
            if all.is_empty() {
                all.push(buffer);
            } else {
                for t in all {
                    t.extend(&buffer);
                }
            }
        }
    }
}

impl Visitor for Extractor {
    type Output = Option<Vec<Vec<u8>>>;

    fn visit_pre(&mut self, hir: &Hir) -> VisitAction {
        if self.all.is_none() {
            return VisitAction::Skip;
        }

        match hir {
            Hir::Mask {
                value,
                mask,
                negated,
            } => {
                if *negated {
                    self.all = None;
                    VisitAction::Skip
                } else {
                    self.add_masked_byte(*value, *mask);
                    VisitAction::Continue
                }
            }
            Hir::Dot => {
                // Should not happen for the moment, the limit is 100 literals, a dot bring that
                // total over the limit.
                self.all = None;
                VisitAction::Skip
            }
            Hir::Literal(b) => {
                self.add_byte(*b);
                VisitAction::Continue
            }

            Hir::Concat(_) | Hir::Empty | Hir::Group(_) => VisitAction::Continue,
            Hir::Alternation(_) => {
                // First, commit the local buffer, to have a proper list of all
                // possible literals.
                self.commit_buffer();
                // Then, store the current lits and push a new stack.
                let prev_lits = std::mem::take(&mut self.all);
                self.alt_stack.push(AltLiterals {
                    prev_lits,
                    branch_lits: Vec::new(),
                });
                self.all = Some(Vec::new());
                VisitAction::Continue
            }
            Hir::Class(Class { bitmap, .. }) => {
                self.add_class(bitmap);
                VisitAction::Continue
            }
            Hir::Assertion(_) | Hir::Repetition { .. } => {
                self.all = None;
                VisitAction::Skip
            }
        }
    }

    fn visit_alternation_in(&mut self) {
        self.commit_buffer();

        let last_pos = self.alt_stack.len() - 1;
        let v = &mut self.alt_stack[last_pos];

        match std::mem::take(&mut self.all) {
            Some(mut al) => v.branch_lits.append(&mut al),
            None => {
                v.prev_lits = None;
            }
        }
        self.all = Some(Vec::new());
    }

    fn visit_post(&mut self, hir: &Hir) {
        if let Hir::Alternation(_) = hir {
            // Close the final branch.
            self.visit_alternation_in();
            // Safety: the visit_pre has pushed an element in the stack.
            let stack = self.alt_stack.pop().unwrap();
            self.all = stack.prev_lits;
            self.cartesian_product(&stack.branch_lits);
        }
    }

    fn finish(mut self) -> Self::Output {
        self.commit_buffer();
        self.all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::expr_to_hir;

    #[test]
    fn test_regex_extract_literals() {
        #[track_caller]
        fn test(expr: &str, expected: Option<Vec<Vec<u8>>>) {
            let hir = expr_to_hir(expr);

            let res = hir_to_only_literals(&hir);
            match res {
                Some(v) => assert_eq!(v, expected.unwrap()),
                None => assert!(expected.is_none()),
            }
        }

        // Assertions and repetitions means no literals
        test(r"^a", None);
        test(r"a$", None);
        test(r"a\b", None);
        test(r"a\B", None);

        test(r"a?", None);
        test(r"a+?", None);
        test(r"a*", None);
        test(r"a{2}", None);
        test(r"a{1,}", None);
        test(r"a{2,3}", None);

        // Classes are handled
        test(
            r"[a-d_%]",
            Some(vec![
                b"%".to_vec(),
                b"_".to_vec(),
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                b"d".to_vec(),
            ]),
        );
        test(
            r"[^ab]",
            Some(
                (0..=255_u8)
                    .filter(|v| *v != b'a' && *v != b'b')
                    .map(|v| vec![v])
                    .collect(),
            ),
        );
        test(
            r"\w",
            Some(
                (b'0'..=b'9')
                    .chain(b'A'..=b'Z')
                    .chain(b'_'..=b'_')
                    .chain(b'a'..=b'z')
                    .map(|v| vec![v])
                    .collect(),
            ),
        );
        test(
            r"a[bc][d-f]g[hk]",
            Some(vec![
                b"abdgh".to_vec(),
                b"abdgk".to_vec(),
                b"abegh".to_vec(),
                b"abegk".to_vec(),
                b"abfgh".to_vec(),
                b"abfgk".to_vec(),
                b"acdgh".to_vec(),
                b"acdgk".to_vec(),
                b"acegh".to_vec(),
                b"acegk".to_vec(),
                b"acfgh".to_vec(),
                b"acfgk".to_vec(),
            ]),
        );

        // Dot leads to too many literals
        test(r".", None);
        test(r".[aA]", None);

        // Concat, empty, literal, group, all works
        test(r"a(b)()e", Some(vec![b"abe".to_vec()]));

        // Alternations works
        test(
            r"a|f(b|c)|((ab)|)c|d",
            Some(vec![
                b"a".to_vec(),
                b"fb".to_vec(),
                b"fc".to_vec(),
                b"abc".to_vec(),
                b"c".to_vec(),
                b"d".to_vec(),
            ]),
        );
    }

    #[test]
    fn test_extract_literals() {
        #[track_caller]
        fn test(expr: &str, expected: Option<&[&[u8]]>) {
            let hir = expr_to_hir(expr);
            let res = hir_to_only_literals(&hir);
            match &res {
                Some(v) => assert_eq!(v, expected.unwrap()),
                None => assert!(expected.is_none()),
            }
        }

        test("{ AB CD 01 }", Some(&[b"\xab\xcd\x01"]));

        // Test masks
        test(
            "{ AB ?D 01 }",
            Some(&[
                b"\xab\x0d\x01",
                b"\xab\x1d\x01",
                b"\xab\x2d\x01",
                b"\xab\x3d\x01",
                b"\xab\x4d\x01",
                b"\xab\x5d\x01",
                b"\xab\x6d\x01",
                b"\xab\x7d\x01",
                b"\xab\x8d\x01",
                b"\xab\x9d\x01",
                b"\xab\xAd\x01",
                b"\xab\xBd\x01",
                b"\xab\xCd\x01",
                b"\xab\xDd\x01",
                b"\xab\xEd\x01",
                b"\xab\xFd\x01",
            ]),
        );
        test(
            "{ D? FE }",
            Some(&[
                b"\xD0\xFE",
                b"\xD1\xFE",
                b"\xD2\xFE",
                b"\xD3\xFE",
                b"\xD4\xFE",
                b"\xD5\xFE",
                b"\xD6\xFE",
                b"\xD7\xFE",
                b"\xD8\xFE",
                b"\xD9\xFE",
                b"\xDA\xFE",
                b"\xDB\xFE",
                b"\xDC\xFE",
                b"\xDD\xFE",
                b"\xDE\xFE",
                b"\xDF\xFE",
            ]),
        );

        // Test alternation
        test(
            "{ AB ( 01 | 23 45) ( 67 | 89 | F0 ) CD }",
            Some(&[
                b"\xAB\x01\x67\xCD",
                b"\xAB\x01\x89\xCD",
                b"\xAB\x01\xF0\xCD",
                b"\xAB\x23\x45\x67\xCD",
                b"\xAB\x23\x45\x89\xCD",
                b"\xAB\x23\x45\xF0\xCD",
            ]),
        );

        // Test imbrication of alternations
        test(
            "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
            Some(&[
                b"\x01",
                b"\x23\x45",
                b"\x23\x67",
                b"\x23\x58\xAA",
                b"\x23\x58\xBB",
                b"\x23\x58\xCC",
                b"\x23\xDD",
                b"\xFF\x45",
                b"\xFF\x67",
                b"\xFF\x58\xAA",
                b"\xFF\x58\xBB",
                b"\xFF\x58\xCC",
                b"\xFF\xDD",
            ]),
        );

        // Test masks + alternation
        test(
            "{ ( AA | BB ) F? }",
            Some(&[
                b"\xAA\xF0",
                b"\xAA\xF1",
                b"\xAA\xF2",
                b"\xAA\xF3",
                b"\xAA\xF4",
                b"\xAA\xF5",
                b"\xAA\xF6",
                b"\xAA\xF7",
                b"\xAA\xF8",
                b"\xAA\xF9",
                b"\xAA\xFA",
                b"\xAA\xFB",
                b"\xAA\xFC",
                b"\xAA\xFD",
                b"\xAA\xFE",
                b"\xAA\xFF",
                b"\xBB\xF0",
                b"\xBB\xF1",
                b"\xBB\xF2",
                b"\xBB\xF3",
                b"\xBB\xF4",
                b"\xBB\xF5",
                b"\xBB\xF6",
                b"\xBB\xF7",
                b"\xBB\xF8",
                b"\xBB\xF9",
                b"\xBB\xFA",
                b"\xBB\xFB",
                b"\xBB\xFC",
                b"\xBB\xFD",
                b"\xBB\xFE",
                b"\xBB\xFF",
            ]),
        );

        // Jumps are not allowed
        test("{ AB [1] 01 }", None);
        test("{ AB [1-] 01 }", None);
        test("{ AB [-2] 01 }", None);
        test("{ AB [1-2] 01 }", None);

        test("{ AB ?? 01 }", None);
        test("{ AA ~?D BB }", None);

        test("{ (AA | ~?D ) BB }", None);
    }
}
