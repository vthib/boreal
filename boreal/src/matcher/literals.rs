//! Literal extraction and computation from variable expressions.
use crate::atoms::{atoms_rank, byte_rank};
use crate::regex::{visit, Class, Hir, VisitAction, Visitor};
use bitmaps::Bitmap;

pub fn get_literals_details(hir: &Hir, dot_all: bool) -> LiteralsDetails {
    let splitter = Splitter::new(dot_all);
    let splitter = visit(hir, splitter);

    let last_position = splitter.current_position;
    let atoms = splitter.best_atoms;

    match atoms {
        None => LiteralsDetails {
            literals: Vec::new(),
            pre_hir: None,
            post_hir: None,
        },
        Some(atoms) => {
            let (pre_hir, post_hir) = atoms.build_pre_post_hir(hir, last_position);
            LiteralsDetails {
                literals: atoms.literals,
                pre_hir,
                post_hir,
            }
        }
    }
}

#[derive(Debug)]
pub struct LiteralsDetails {
    /// Literals extracted from the regex.
    pub literals: Vec<Vec<u8>>,

    /// HIR for validators of matches on literals.
    ///
    /// The `pre` is the HIR of the regex that must match before (and including) the literal.
    /// The `post` is the HIR of the regex that must match after (and including) the literal.
    pub pre_hir: Option<Hir>,
    pub post_hir: Option<Hir>,
}

/// Visitor on a regex AST to search for literals
#[derive(Debug)]
struct Splitter {
    best_atoms: Option<Atoms>,

    current_run: Vec<HirPart>,

    /// Current position of the visitor.
    ///
    /// This position is a simple counter of visited nodes.
    current_position: usize,

    /// True if the dot all modifier is set for this regex.
    dot_all: bool,
}

#[derive(Debug)]
enum HirPartKind {
    Literal(u8),
    Class { bitmap: Bitmap<256> },
}

impl HirPartKind {
    fn combinations(&self) -> usize {
        match self {
            Self::Literal(_) => 1,
            Self::Class { bitmap } => bitmap.len(),
        }
    }
}

impl Splitter {
    fn new(dot_all: bool) -> Self {
        Self {
            best_atoms: None,

            current_run: Vec::new(),

            current_position: 0,
            dot_all,
        }
    }

    fn add_part(&mut self, kind: HirPartKind) {
        self.current_run.push(HirPart {
            start_position: self.current_position,
            kind,
        });
    }

    /// Visit an alternation to add it to the currently being build literals.
    ///
    /// Only allow alternations if each one is a literal or a concat of literals.
    fn visit_alternation(&mut self, alts: &[Hir]) {
        let mut literals = Vec::new();

        for node in alts {
            match node {
                Hir::Literal(b) => literals.push(vec![*b]),
                Hir::Concat(nodes) => {
                    let mut lit = Vec::with_capacity(nodes.len());

                    for subnode in nodes {
                        match subnode {
                            Hir::Literal(b) => lit.push(*b),
                            _ => return,
                        }
                    }
                    literals.push(lit);
                }
                _ => return,
            }
        }

        let rank = atoms_rank(&literals);
        self.try_atoms(Atoms {
            start_position: self.current_position,
            end_position: self.current_position + 1,
            literals,
            rank,
        });
    }

    fn try_atoms(&mut self, atoms: Atoms) {
        match &mut self.best_atoms {
            Some(v) if v.rank < atoms.rank => *v = atoms,
            Some(_) => (),
            None => self.best_atoms = Some(atoms),
        }
    }

    fn close_run(&mut self) {
        if !self.current_run.is_empty() {
            if let Some(atoms) = run_into_atoms(&self.current_run) {
                self.try_atoms(atoms);
            }
            self.current_run = Vec::new();
        }
    }
}

#[derive(Debug)]
struct Atoms {
    start_position: usize,
    end_position: usize,
    literals: Vec<Vec<u8>>,
    rank: u32,
}

impl Atoms {
    fn build_pre_post_hir(
        &self,
        original_hir: &Hir,
        last_position: usize,
    ) -> (Option<Hir>, Option<Hir>) {
        if self.literals.is_empty() {
            return (None, None);
        }

        let visitor = PrePostExtractor::new(self.start_position, self.end_position, last_position);
        visit(original_hir, visitor)
    }
}

fn generate_literals(parts: &[HirPart]) -> Vec<Vec<u8>> {
    let mut literals = vec![Vec::new()];

    for part in parts {
        match &part.kind {
            HirPartKind::Literal(byte) => {
                for lit in &mut literals {
                    lit.push(*byte);
                }
            }
            HirPartKind::Class { bitmap } => {
                // Compute the cardinal product between the prefixes and the literals of the
                // alternation.
                #[allow(clippy::cast_possible_truncation)]
                if literals.is_empty() {
                    literals = bitmap
                        .into_iter()
                        .map(|b| b as u8)
                        .map(|b| vec![b])
                        .collect();
                } else {
                    literals = literals
                        .iter()
                        .flat_map(|prefix| {
                            bitmap.into_iter().map(|b| {
                                prefix
                                    .iter()
                                    .copied()
                                    .chain(std::iter::once(b as u8))
                                    .collect()
                            })
                        })
                        .collect();
                }
            }
        }
    }

    literals
}

#[derive(Debug)]
struct HirPart {
    start_position: usize,
    kind: HirPartKind,
}

fn run_into_atoms(parts: &[HirPart]) -> Option<Atoms> {
    let mut best_slice = None;
    let mut best_rank = 0;

    // Compute the rank of every subslice, and track the best one
    for i in 0..parts.len() {
        for j in (i + 1)..=std::cmp::min(parts.len(), i + 4) {
            if let Some(rank) = get_parts_rank(&parts[i..j]) {
                if best_slice.is_none() || rank > best_rank {
                    best_slice = Some(i..j);
                    best_rank = rank;
                }
            }
        }
    }

    // Generate the literals for this slice, and return it
    let best_slice = best_slice?;
    let parts = &parts[best_slice];
    let literals = generate_literals(parts);
    Some(Atoms {
        start_position: parts.first().unwrap().start_position,
        end_position: parts.last().unwrap().start_position + 1,
        literals,
        rank: best_rank,
    })
}

fn get_parts_rank(parts: &[HirPart]) -> Option<u32> {
    let mut quality = 0_u32;
    let mut bitmap = Bitmap::new();
    let mut nb_uniq = 0;

    // First, check the validity of the parts
    if parts
        .first()
        .map_or(true, |part| part.kind.combinations() >= 100)
        || parts
            .last()
            .map_or(true, |part| part.kind.combinations() >= 100)
    {
        return None;
    }

    let combinations = parts
        .iter()
        .map(|part| part.kind.combinations())
        .product::<usize>();
    if combinations > 256 {
        return None;
    }

    for part in parts {
        match &part.kind {
            HirPartKind::Literal(b) => {
                quality += byte_rank(*b);

                if !bitmap.get(*b as usize) {
                    let _r = bitmap.set(*b as usize, true);
                    nb_uniq += 1;
                }
            }
            #[allow(clippy::cast_possible_truncation)]
            HirPartKind::Class { bitmap: class } => {
                quality += class
                    .into_iter()
                    .map(|v| byte_rank(v as u8))
                    .min()
                    .unwrap_or(0);
                if class.into_iter().any(|b| !bitmap.get(b)) {
                    nb_uniq += 1;
                }
                bitmap |= *class;
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    let len = parts.len() as u32;

    // If all the bytes in the atom are equal and very common, let's penalize
    // it heavily.
    if nb_uniq == 1 && (bitmap.get(0) || bitmap.get(0x20) || bitmap.get(0xCC) || bitmap.get(0xFF)) {
        quality -= 10 * len;
    }
    // In general atoms with more unique bytes have a better quality, so let's
    // boost the quality in the amount of unique bytes.
    else {
        quality += 2 * nb_uniq;
    }

    Some(if combinations >= 100 {
        quality.saturating_sub(10 * len)
    } else if combinations > 1 {
        quality.saturating_sub(4 * len)
    } else {
        quality
    })
}

impl Visitor for Splitter {
    type Output = Self;

    fn visit_pre(&mut self, hir: &Hir) -> VisitAction {
        match hir {
            Hir::Literal(b) => {
                self.add_part(HirPartKind::Literal(*b));
                VisitAction::Skip
            }
            Hir::Empty => VisitAction::Skip,
            Hir::Dot => {
                let mut bitmap = Bitmap::new();
                if !self.dot_all {
                    let _r = bitmap.set(usize::from(b'\n'), true);
                }
                bitmap.invert();
                self.add_part(HirPartKind::Class { bitmap });
                VisitAction::Skip
            }
            Hir::Class(Class { bitmap, .. }) => {
                self.add_part(HirPartKind::Class { bitmap: *bitmap });
                VisitAction::Skip
            }
            Hir::Mask {
                mask,
                value,
                negated,
            } => {
                let mut bitmap = Bitmap::new();
                if *mask == 0x0F {
                    for c in 0..=15 {
                        let _ = bitmap.set(usize::from((c << 4) | *value), true);
                    }
                } else {
                    for c in 0..=15 {
                        let _ = bitmap.set(usize::from(c | *value), true);
                    }
                }
                if *negated {
                    bitmap.invert();
                }
                self.add_part(HirPartKind::Class { bitmap });
                VisitAction::Skip
            }
            Hir::Assertion(_) | Hir::Repetition { .. } => {
                self.close_run();
                VisitAction::Skip
            }
            Hir::Alternation(alts) => {
                self.close_run();
                self.visit_alternation(alts);
                VisitAction::Skip
            }
            Hir::Group(_) | Hir::Concat(_) => VisitAction::Continue,
        }
    }

    fn visit_post(&mut self, node: &Hir) {
        if !matches!(node, Hir::Group(_) | Hir::Concat(_)) {
            self.current_position += 1;
        }
    }

    fn finish(mut self) -> Self::Output {
        self.close_run();
        self
    }
}

/// Visitor used to extract the AST nodes that are before and after extracted literals.
///
/// The goal is to be able to generate regex expressions to validate the regex, knowing the
/// position of literals found by the AC pass.
#[derive(Debug)]
struct PrePostExtractor {
    /// Stacks used during the visit to reconstruct compound nodes.
    pre_stack: Vec<Vec<Hir>>,
    post_stack: Vec<Vec<Hir>>,

    /// Top level pre node.
    ///
    /// May end up None if the extracted literals are from the start of the regex.
    pre_node: Option<Hir>,

    /// Top level post node.
    ///
    /// May end up None if the extracted literals are from the end of the regex.
    post_node: Option<Hir>,

    /// Start position of the extracted literals.
    start_position: usize,
    /// End position of the extracted literals.
    end_position: usize,
    /// Last position of the regex.
    last_position: usize,

    /// Current position during the visit of the original AST.
    current_position: usize,
}

impl PrePostExtractor {
    fn new(start_position: usize, end_position: usize, last_position: usize) -> Self {
        Self {
            pre_stack: Vec::new(),
            post_stack: Vec::new(),

            pre_node: None,
            post_node: None,

            current_position: 0,
            start_position,
            end_position,
            last_position,
        }
    }

    fn push_stack(&mut self) {
        self.pre_stack.push(Vec::new());
        self.post_stack.push(Vec::new());
    }

    fn add_pre_post_hir(&mut self, node: &Hir) {
        if self.current_position < self.end_position && self.start_position > 0 {
            self.add_node(node.clone(), false);
        }
        if self.current_position >= self.start_position && self.end_position != self.last_position {
            self.add_node(node.clone(), true);
        }
    }

    fn add_node(&mut self, node: Hir, post: bool) {
        let (stack, final_node) = if post {
            (&mut self.post_stack, &mut self.post_node)
        } else {
            (&mut self.pre_stack, &mut self.pre_node)
        };

        if stack.is_empty() {
            // Empty stack: we should only have a single HIR to set at top-level.
            let res = final_node.replace(node);
            assert!(res.is_none(), "top level HIR node already set");
        } else {
            let pos = stack.len() - 1;
            stack[pos].push(node);
        }
    }
}

impl Visitor for PrePostExtractor {
    type Output = (Option<Hir>, Option<Hir>);

    fn visit_pre(&mut self, hir: &Hir) -> VisitAction {
        // XXX: be careful here, the visit *must* have the exact same behavior as for the
        // `LiteralsExtractor` visitor, to ensure the pre post expressions are correct.
        match hir {
            Hir::Literal(_)
            | Hir::Repetition { .. }
            | Hir::Dot
            | Hir::Mask { .. }
            | Hir::Class(_)
            | Hir::Empty
            | Hir::Assertion(_)
            | Hir::Alternation(_) => {
                self.add_pre_post_hir(hir);
                VisitAction::Skip
            }
            Hir::Group(_) | Hir::Concat(_) => {
                self.push_stack();
                VisitAction::Continue
            }
        }
    }

    fn visit_post(&mut self, node: &Hir) {
        match node {
            Hir::Literal(_)
            | Hir::Repetition { .. }
            | Hir::Dot
            | Hir::Mask { .. }
            | Hir::Class(_)
            | Hir::Empty
            | Hir::Assertion(_)
            | Hir::Alternation(_) => self.current_position += 1,
            Hir::Group(_) => {
                // Safety: this is a post visit, the pre visit pushed an element on the stack.
                let mut pre = self.pre_stack.pop().unwrap();
                let mut post = self.post_stack.pop().unwrap();

                if let Some(node) = pre.pop() {
                    self.add_node(Hir::Group(Box::new(node)), false);
                }
                if let Some(node) = post.pop() {
                    self.add_node(Hir::Group(Box::new(node)), true);
                }
            }

            Hir::Concat(_) => {
                // Safety: this is a post visit, the pre visit pushed an element on the stack.
                let pre = self.pre_stack.pop().unwrap();
                let post = self.post_stack.pop().unwrap();
                if !pre.is_empty() {
                    self.add_node(Hir::Concat(pre), false);
                }
                if !post.is_empty() {
                    self.add_node(Hir::Concat(post), true);
                }
            }
        }
    }

    fn finish(self) -> Self::Output {
        (self.pre_node, self.post_node)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        regex::regex_hir_to_string,
        test_helpers::{expr_to_hir, test_type_traits_non_clonable},
    };

    use super::*;

    #[test]
    fn test_hex_string_literals() {
        #[track_caller]
        fn test(expr: &str, expected_lits: &[&[u8]], expected_pre: &str, expected_post: &str) {
            let hir = expr_to_hir(expr);
            let exprs = get_literals_details(&hir, false);
            assert_eq!(exprs.literals, expected_lits);
            assert_eq!(
                exprs
                    .pre_hir
                    .as_ref()
                    .map(regex_hir_to_string)
                    .unwrap_or_default(),
                expected_pre
            );
            assert_eq!(
                exprs
                    .post_hir
                    .as_ref()
                    .map(regex_hir_to_string)
                    .unwrap_or_default(),
                expected_post
            );
        }

        test("{ AB CD 01 }", &[b"\xab\xcd\x01"], "", "");

        test(
            "{ AB ?D 01 }",
            &[
                b"\xab\x0D\x01",
                b"\xab\x1D\x01",
                b"\xab\x2D\x01",
                b"\xab\x3D\x01",
                b"\xab\x4D\x01",
                b"\xab\x5D\x01",
                b"\xab\x6D\x01",
                b"\xab\x7D\x01",
                b"\xab\x8D\x01",
                b"\xab\x9D\x01",
                b"\xab\xAD\x01",
                b"\xab\xBD\x01",
                b"\xab\xCD\x01",
                b"\xab\xDD\x01",
                b"\xab\xED\x01",
                b"\xab\xFD\x01",
            ],
            "",
            "",
        );

        test(
            "{ D? FE }",
            &[
                b"\xD0\xfe",
                b"\xD1\xfe",
                b"\xD2\xfe",
                b"\xD3\xfe",
                b"\xD4\xfe",
                b"\xD5\xfe",
                b"\xD6\xfe",
                b"\xD7\xfe",
                b"\xD8\xfe",
                b"\xD9\xfe",
                b"\xDA\xfe",
                b"\xDB\xfe",
                b"\xDC\xfe",
                b"\xDD\xfe",
                b"\xDE\xfe",
                b"\xDF\xfe",
            ],
            "",
            "",
        );

        // test("{ ( AA | BB ) F? }", &[b"\xAA", b"\xBB"], "", "");

        // test(
        //     "{ AB ( 01 | 23 45) ( 67 | 89 | F0 ) CD }",
        //     &[
        //         b"\xAB\x01\x67\xCD",
        //         b"\xAB\x01\x89\xCD",
        //         b"\xAB\x01\xF0\xCD",
        //         b"\xAB\x23\x45\x67\xCD",
        //         b"\xAB\x23\x45\x89\xCD",
        //         b"\xAB\x23\x45\xF0\xCD",
        //     ],
        //     "",
        //     "",
        // );

        // // Do not handle alternations that contains anything other than literals
        // test("{ AB ( ?? | FF ) CC }", &[b"\xAB"], "", r"\xab(.|\xff)\xcc");
        // test(
        //     "{ AB ( ?? DD | FF ) CC }",
        //     &[b"\xAB"],
        //     "",
        //     r"\xab(.\xdd|\xff)\xcc",
        // );
        // test(
        //     "{ AB ( 11 ?? DD | FF ) CC }",
        //     &[b"\xAB"],
        //     "",
        //     r"\xab(\x11.\xdd|\xff)\xcc",
        // );
        // test(
        //     "{ AB ( 11 ?? | FF ) CC }",
        //     &[b"\xAB"],
        //     "",
        //     r"\xab(\x11.|\xff)\xcc",
        // );
        // test("{ ( 11 ?? | FF ) CC }", &[b"\xCC"], r"(\x11.|\xff)\xcc", "");
        // test(
        //     "{ AB ( 11 | 12 ) 13 ( 1? | 14 ) }",
        //     &[b"\xAB\x11\x13", b"\xAB\x12\x13"],
        //     "",
        //     r"\xab(\x11|\x12)\x13([\x10-\x1f]|\x14)",
        // );

        // // Test imbrication of alternations
        // test(
        //     "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
        //     &[],
        //     "",
        //     "",
        // );

        // // Do not grow alternations too much, 32 max
        // test(
        //     "{ ( 11 | 12 ) ( 21 | 22 ) ( 31 | 32 ) ( 41 | 42 ) ( 51 | 52 ) ( 61 | 62 ) ( 71 | 72 ) 88 }",
        //     &[
        //         b"\x11\x21\x31\x41",
        //         b"\x11\x21\x31\x42",
        //         b"\x11\x21\x32\x41",
        //         b"\x11\x21\x32\x42",
        //         b"\x11\x22\x31\x41",
        //         b"\x11\x22\x31\x42",
        //         b"\x11\x22\x32\x41",
        //         b"\x11\x22\x32\x42",
        //         b"\x12\x21\x31\x41",
        //         b"\x12\x21\x31\x42",
        //         b"\x12\x21\x32\x41",
        //         b"\x12\x21\x32\x42",
        //         b"\x12\x22\x31\x41",
        //         b"\x12\x22\x31\x42",
        //         b"\x12\x22\x32\x41",
        //         b"\x12\x22\x32\x42",
        //     ],
        //     "",
        //     "(\\x11|\\x12)(!|\")(1|2)(A|B)(Q|R)(a|b)(q|r)\\x88",
        // );
        // test(
        //     "{ ( 11 | 12 ) ( 21 | 22 ) 33 ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10  ) }",
        //     &[
        //         b"\x11\x21\x33\x01",
        //         b"\x11\x21\x33\x02",
        //         b"\x11\x21\x33\x03",
        //         b"\x11\x21\x33\x04",
        //         b"\x11\x21\x33\x05",
        //         b"\x11\x21\x33\x06",
        //         b"\x11\x21\x33\x07",
        //         b"\x11\x21\x33\x08",
        //         b"\x11\x21\x33\x09",
        //         b"\x11\x21\x33\x10",
        //         b"\x11\x22\x33\x01",
        //         b"\x11\x22\x33\x02",
        //         b"\x11\x22\x33\x03",
        //         b"\x11\x22\x33\x04",
        //         b"\x11\x22\x33\x05",
        //         b"\x11\x22\x33\x06",
        //         b"\x11\x22\x33\x07",
        //         b"\x11\x22\x33\x08",
        //         b"\x11\x22\x33\x09",
        //         b"\x11\x22\x33\x10",
        //         b"\x12\x21\x33\x01",
        //         b"\x12\x21\x33\x02",
        //         b"\x12\x21\x33\x03",
        //         b"\x12\x21\x33\x04",
        //         b"\x12\x21\x33\x05",
        //         b"\x12\x21\x33\x06",
        //         b"\x12\x21\x33\x07",
        //         b"\x12\x21\x33\x08",
        //         b"\x12\x21\x33\x09",
        //         b"\x12\x21\x33\x10",
        //         b"\x12\x22\x33\x01",
        //         b"\x12\x22\x33\x02",
        //         b"\x12\x22\x33\x03",
        //         b"\x12\x22\x33\x04",
        //         b"\x12\x22\x33\x05",
        //         b"\x12\x22\x33\x06",
        //         b"\x12\x22\x33\x07",
        //         b"\x12\x22\x33\x08",
        //         b"\x12\x22\x33\x09",
        //         b"\x12\x22\x33\x10",
        //     ],
        //     "",
        //     "",
        // );

        test(
            "{ 11 22 33 44 55 66 77 ( 88 | 99 | AA | BB ) }",
            &[b"\x11\x22\x33\x44"],
            "",
            r#"\x11"3DUfw(\x88|\x99|\xaa|\xbb)"#,
        );

        test(
            "{ 11 ?A 22 33 [1] 44 55 66 A? 77 88 }",
            &[
                b"\x11\x0A\x22\x33",
                b"\x11\x1A\x22\x33",
                b"\x11\x2A\x22\x33",
                b"\x11\x3A\x22\x33",
                b"\x11\x4A\x22\x33",
                b"\x11\x5A\x22\x33",
                b"\x11\x6A\x22\x33",
                b"\x11\x7A\x22\x33",
                b"\x11\x8A\x22\x33",
                b"\x11\x9A\x22\x33",
                b"\x11\xAA\x22\x33",
                b"\x11\xBA\x22\x33",
                b"\x11\xCA\x22\x33",
                b"\x11\xDA\x22\x33",
                b"\x11\xEA\x22\x33",
                b"\x11\xFA\x22\x33",
            ],
            "",
            r#"\x11[\x0a\x1a\x2a:JZjz\x8a\x9a\xaa\xba\xca\xda\xea\xfa]"3.DUf[\xa0-\xaf]w\x88"#,
        );

        // hex strings found in some real rules
        test(
            "{ 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? \
               00 04 00 02 00 04 ?? ?? }",
            &[b"\x00\x01\x00\x02"],
            r"\x00\x01\x00\x01\x00\x02",
            r"\x00\x01\x00\x02..\x00\x02\x00\x01\x00\x02..\x00\x03\x00\x02\x00\x04....\x00\x04\x00\x02\x00\x04..",
        );

        test(
            "{ c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }",
            &[b"\x00\x00\x01\x00"],
            r"\xc7[\x00-\x0f]\x00\x00\x01\x00",
            r"\x00\x00\x01\x00.{4,14}?\xc7[\x00-\x0f]\x01\x00\x00\x00",
        );
        test(
            "{ 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 }",
            &[b"\x75\x6C\x74\x2E"],
            r"\x00\xcc\x00.....\x00default\x2e",
            r"ult\x2eproperties",
        );
        test(
            "{ FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? \
              89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }",
            &[b"\x83\xC5\x04\x8B"],
            "\\xfc\\xe8.\\x00\\x00\\x00.{0,32}?\\xeb\\x2b.\\x8b.\\x00\\x83\\xc5\\x04\
             \\x8b",
            "\\x83\\xc5\\x04\\x8b.\\x001.\\x83\\xc5\\x04U\\x8b.\\x001.\\x89.\\x001.\
             \\x83\\xc5\\x04\\x83.\\x041.9.t\\x02\\xeb\\xe8.\\xff.\\xe8\\xd0\\xff\\xff\\xff",
        );
        test(
            "{ ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) \
        04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) \
        02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) \
        ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }",
            &[b"\x02\xAA\x02\xC1"],
            "(\\x0f\\x82..\\x00\\x00|r.)(\\x80|A\\x80)([p-\\x7f]|\\x7c\\x24)\\x04\\x02\
             (\\x0f\\x85..\\x00\\x00|u.)(\\x81|A\\x81)([0-\\x3f]|<\\x24|\\x7d\\x00)\
             \\x02\\xaa\\x02\\xc1",
            "\\x02\\xaa\\x02\\xc1(\\x0f\\x85..\\x00\\x00|u.)(\\x8b|A\\x8b|D\\x8b|E\\x8b)\
             ([@-O]|[P-_]|[`-o]|[p-\\x7f]|[\\x04\\x14\\x244DTdt\\x84\\x94\\xa4\\xb4\\xc4\\xd4\
             \\xe4\\xf4]\\x24|[\\x0c\\x1c,<L\\x5cl\\x7c\\x8c\\x9c\\xac\\xbc\\xcc\\xdc\\xec\\xfc]\
             \\x24)\\x06",
        );

        test(
            "{ 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }",
            &[
                b"\xF6\xD0\x1A",
                b"\xF6\xD1\x1A",
                b"\xF6\xD2\x1A",
                b"\xF6\xD3\x1A",
                b"\xF6\xD4\x1A",
                b"\xF6\xD5\x1A",
                b"\xF6\xD6\x1A",
                b"\xF6\xD7\x1A",
                b"\xF6\xD8\x1A",
                b"\xF6\xD9\x1A",
                b"\xF6\xDA\x1A",
                b"\xF6\xDB\x1A",
                b"\xF6\xDC\x1A",
                b"\xF6\xDD\x1A",
                b"\xF6\xDE\x1A",
                b"\xF6\xDF\x1A",
            ],
            r"\x8b[\xc0-\xcf].{2,3}?\xf6[\xd0-\xdf]\x1a",
            r"\xf6[\xd0-\xdf]\x1a[\xc0-\xcf].{2,3}?.{2,3}?0[\x00-\x0f].[@-O]",
        );
        test(
            "{ C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }",
            &[
                b"\x89\x40\x01",
                b"\x89\x41\x01",
                b"\x89\x42\x01",
                b"\x89\x43\x01",
                b"\x89\x44\x01",
                b"\x89\x45\x01",
                b"\x89\x46\x01",
                b"\x89\x47\x01",
                b"\x89\x48\x01",
                b"\x89\x49\x01",
                b"\x89\x4A\x01",
                b"\x89\x4B\x01",
                b"\x89\x4C\x01",
                b"\x89\x4D\x01",
                b"\x89\x4E\x01",
                b"\x89\x4F\x01",
            ],
            r"\xc6[\x00-\x0f]\xe9[@-O][\x80-\x8f][@-O]\x05.{2,2}?\x89[@-O]\x01",
            "",
        );

        // test(
        //     "{ 61 ?? ( 62 63 | 64) 65 }",
        //     &[b"\x62\x63\x65", b"\x64\x65"],
        //     r"a.(bc|d)e",
        //     "",
        // );

        test(
            "{ 81 EB ?? [0-8] E8 ?? 00 00 00 [0-8] 2B C3 }",
            &[b"\x81\xEB"],
            "",
            r"\x81\xeb..{0,8}?\xe8.\x00\x00\x00.{0,8}?\x2b\xc3",
        );
    }

    #[test]
    fn test_regex_literals() {
        #[track_caller]
        fn test<T>(expr: &str, expected_lits: &[T], expected_pre: &str, expected_post: &str)
        where
            T: AsRef<[u8]>,
        {
            let hir = expr_to_hir(expr);
            let exprs = get_literals_details(&hir, false);
            let literals: Vec<_> = exprs.literals.iter().collect();
            let expected: Vec<_> = expected_lits.iter().map(AsRef::as_ref).collect();
            assert_eq!(literals, expected);
            assert_eq!(
                exprs
                    .pre_hir
                    .as_ref()
                    .map(regex_hir_to_string)
                    .unwrap_or_default(),
                expected_pre
            );
            assert_eq!(
                exprs
                    .post_hir
                    .as_ref()
                    .map(regex_hir_to_string)
                    .unwrap_or_default(),
                expected_post
            );
        }

        // Literal on the left side of a group
        test("abc(a+)b", &[b"abc"], "", "abc(a+)b");
        // Literal spanning inside a group
        test("ab(ca+)b", &[b"abc"], "", "ab(ca+)b");
        // Literal spanning up to the end of a group
        test("ab(c)a+b", &[b"abc"], "", "ab(c)a+b");
        // Literal spanning in and out of a group
        test("a(b)ca+b", &[b"abc"], "", "a(b)ca+b");

        // Literal on the right side of a group
        test("b(a+)abc", &[b"abc"], "b(a+)abc", "");
        // Literal spanning inside a group
        test("b(a+a)bc", &[b"abc"], "b(a+a)bc", "");
        // Literal starting in a group
        test("ba+(ab)c", &[b"abc"], "ba+(ab)c", "");
        // Literal spanning in and out of a group
        test("ba+a(bc)", &[b"abc"], "ba+a(bc)", "");

        // A few tests on closing nodes
        test("a.+bcd{2}e", &[b"bc"], "a.+bc", "bcd{2}e");
        test("a.+bc.e", &["bc"], "a.+bc", "bc.e");
        test("a.+bc\\B.e", &[b"bc"], "a.+bc", "bc\\B.e");
        test("a.+bc[aA]e", &[b"bcAe", b"bcae"], "a.+bc[aA]e", "");
        test("a.+bc()de", &[b"bcde"], "a.+bc()de", "");

        test(
            "a+(b.c)(d)(ef)g+",
            &[b"cdef"],
            "a+(b.c)(d)(ef)",
            "(c)(d)(ef)g+",
        );

        test(
            "a((b(c)((d)()(e(g+h)ij)))kl)m",
            &[b"abcd"],
            "",
            "a((b(c)((d)()(e(g+h)ij)))kl)m",
        );

        test(
            " { AB CD 01 }",
            &[b"{ AB"],
            r" \x7b AB",
            r"\x7b AB CD 01 \x7d",
        );

        test(
            r"\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)",
            &[
                b"0 AM", b"0 PM", b"1 AM", b"1 PM", b"2 AM", b"2 PM", b"3 AM", b"3 PM", b"4 AM",
                b"4 PM", b"5 AM", b"5 PM", b"6 AM", b"6 PM", b"7 AM", b"7 PM", b"8 AM", b"8 PM",
                b"9 AM", b"9 PM",
            ],
            r"\x28[0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M",
            r"[0-9] [AP]M\x29",
        );

        test(
            r"b.*a(1234567|7892345).*d",
            &[b"1234567", b"7892345"],
            r"b.*a(1234567|7892345)",
            r"(1234567|7892345).*d",
        );
    }

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(LiteralsDetails {
            literals: Vec::new(),
            pre_hir: None,
            post_hir: None,
        });

        test_type_traits_non_clonable(Splitter::new(false));
        test_type_traits_non_clonable(PrePostExtractor::new(0, 0, 0));
    }
}
