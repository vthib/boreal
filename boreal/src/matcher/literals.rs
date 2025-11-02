//! Literal extraction and computation from variable expressions.
use std::cmp::Ordering;

use crate::atoms::{atom_quality_from_literal, ATOM_SIZE};
use crate::bitmaps::Bitmap;
use crate::regex::{visit, Class, Hir, VisitAction, Visitor};

pub fn get_literals_details(hir: &Hir) -> LiteralsDetails {
    let mut extractor = visit(hir, RunExtractor::new());
    extractor.close_all();

    let atoms = extractor
        .runs
        .iter()
        .filter_map(|run| run_into_atoms(run))
        .reduce(
            |best_atoms, new_atoms| match new_atoms.rank.cmp(&best_atoms.rank) {
                Ordering::Greater => new_atoms,
                Ordering::Equal
                    if new_atoms.literals.iter().map(Vec::len).min()
                        > best_atoms.literals.iter().map(Vec::len).min() =>
                {
                    new_atoms
                }
                _ => best_atoms,
            },
        );

    match atoms {
        None => LiteralsDetails {
            literals: Vec::new(),
            pre_hir: None,
            post_hir: None,
        },
        Some(Atoms {
            start_part,
            end_part,
            literals,
            rank: _rank,
        }) => {
            // The "pre" hir is everything in the hir that is before the
            // parts used for literal extraction, while also including those
            // parts.
            //
            // For example, for `a.bcde.f`, if the part used for literal
            // extraction is `bcde`, then the pre hir is `a.bcde` (and the
            // post hir is `bcde.f`.
            //
            // This pre hir is not needed if the hir starts with the literal
            // (ie start_position is 0).
            let pre_hir = if part_is_start_of_regex(start_part) {
                None
            } else if end_part.end_position.is_none() {
                Some(hir.clone())
            } else {
                Some(visit(hir, PrePostExtractor::new(end_part, true)))
            };
            // the post hir is not needed if the hir ends with the literal
            // (ie end_position is None)
            let post_hir = if part_is_end_of_regex(end_part) {
                None
            } else if start_part.start_position == 0 {
                Some(hir.clone())
            } else {
                Some(visit(hir, PrePostExtractor::new(start_part, false)))
            };

            LiteralsDetails {
                literals,
                pre_hir,
                post_hir,
            }
        }
    }
}

fn part_is_start_of_regex(part: &HirPart) -> bool {
    if part.start_position > 0 {
        return false;
    }
    match &part.kind {
        HirPartKind::Literal(_) | HirPartKind::Class { .. } => true,
        HirPartKind::Alts { alts } => alts
            .iter()
            .all(|alt| alt.first().is_some_and(part_is_start_of_regex)),
    }
}

fn part_is_end_of_regex(part: &HirPart) -> bool {
    if part.end_position.is_some() {
        return false;
    }
    match &part.kind {
        HirPartKind::Literal(_) | HirPartKind::Class { .. } => true,
        HirPartKind::Alts { alts } => alts
            .iter()
            .all(|alt| alt.last().is_some_and(part_is_end_of_regex)),
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

/// Visitor on a regex AST to extract literals that can be used in a
/// Aho-Corasick search.
///
/// The extraction works by finding runs of parts that can be used to
/// generate literals. For the moment, those are either:
///
/// - raw literals
/// - classes (including masked bytes)
/// - dot expression (which are equivalent to classes)
///
/// This run is broken once we either reach a node that cannot be part of it,
/// or if we reach the end of the HIR. Once a run is complete, we then iterate
/// on every possible subslice in the run to find the optimal atoms.
///
/// Alternations are also handled, although with big restrictions: they are
/// considered as their own runs (so for example `a(b|c)` will *not* be a
/// single run that generates `ab` and `ac`), and they must only consists of
/// concatenations of bytes.
#[derive(Debug)]
struct RunExtractor {
    /// Current best atoms extracted.
    runs: Vec<Vec<HirPart>>,

    /// Run open on the left.
    run_open_left: Vec<HirPart>,
    left_closed: bool,

    /// Run open on the right.
    run_open_right: Vec<HirPart>,

    /// Current position of the visitor.
    ///
    /// This position is a simple counter of visited nodes.
    current_position: usize,
}

#[allow(variant_size_differences)]
#[derive(Clone, Debug)]
enum HirPartKind {
    Literal(Vec<u8>),
    Class { bitmap: Bitmap },
    Alts { alts: Vec<Vec<HirPart>> },
}

impl HirPartKind {
    fn len(&self) -> usize {
        match self {
            Self::Literal(lit) => lit.len(),
            Self::Class { .. } => 1,
            Self::Alts { alts } => alts
                .iter()
                .map(|alt| alt.iter().map(|part| part.kind.len()).sum())
                .min()
                .unwrap_or(0),
        }
    }

    fn combinations(&self, max: u32) -> Option<u32> {
        match self {
            Self::Literal(_) => Some(1),
            Self::Class { bitmap } => Some(bitmap.count_ones()),
            Self::Alts { alts } => {
                let mut res = 1;
                for alt in alts {
                    for part in alt {
                        res *= part.kind.combinations(max)?;
                        if res > max {
                            return None;
                        }
                    }
                }
                Some(res)
            }
        }
    }
}

impl RunExtractor {
    fn new() -> Self {
        Self {
            runs: Vec::new(),

            run_open_left: Vec::new(),
            left_closed: false,
            run_open_right: Vec::new(),

            current_position: 0,
        }
    }

    fn add_part(&mut self, kind: HirPartKind) {
        let current_run = if self.left_closed {
            &mut self.run_open_right
        } else {
            &mut self.run_open_left
        };
        if let Some(last_part) = current_run.last_mut() {
            last_part.end_position = Some(self.current_position);
        }
        current_run.push(HirPart {
            start_position: self.current_position,
            end_position: None,
            kind,
        });
    }

    /// Visit an alternation to generate candidate atoms from it
    ///
    /// Only allow alternations if each one is a literal or a concat of literals.
    fn visit_alternation(&mut self, alts: &[Hir]) {
        let mut left_runs = Vec::new();
        let mut right_runs = Vec::new();
        let mut must_close_left = false;

        for alt in alts {
            let extractor = visit(alt, RunExtractor::new());
            if extractor.left_closed {
                must_close_left = true;
                left_runs.push(extractor.run_open_left);
                right_runs.push(extractor.run_open_right);
            } else {
                left_runs.push(extractor.run_open_left.clone());
                right_runs.push(extractor.run_open_left);
            }
        }

        if must_close_left {
            if left_runs.iter().all(|run| !run.is_empty()) {
                // Current run is open left and all alts have stuff on the left: we
                // can prolonged the run.
                self.add_part(HirPartKind::Alts { alts: left_runs });
            }
            self.close_run(false);
            if right_runs.iter().all(|run| !run.is_empty()) {
                // All alts have stuff on the right: we can build a run from it.
                self.add_part(HirPartKind::Alts { alts: right_runs });
            }
        } else {
            self.add_part(HirPartKind::Alts { alts: left_runs });
        }
    }

    fn close_run(&mut self, at_end: bool) {
        if self.left_closed {
            if !at_end {
                if let Some(last_part) = self.run_open_right.last_mut() {
                    last_part.end_position = Some(self.current_position);
                }
            }
            if !self.run_open_right.is_empty() {
                self.runs.push(std::mem::take(&mut self.run_open_right));
            }
        } else {
            if !at_end {
                if let Some(last_part) = self.run_open_left.last_mut() {
                    last_part.end_position = Some(self.current_position);
                }
            }
            self.left_closed = true;
        }
    }

    fn close_all(&mut self) {
        self.close_run(true);
        if !self.run_open_left.is_empty() {
            self.runs.push(std::mem::take(&mut self.run_open_left));
        }
    }

    fn add_byte(&mut self, b: u8) {
        let run = if self.left_closed {
            &mut self.run_open_right
        } else {
            &mut self.run_open_left
        };
        if let Some(HirPart {
            kind: HirPartKind::Literal(lit),
            ..
        }) = run.last_mut()
        {
            lit.push(b);
        } else {
            run.push(HirPart {
                start_position: self.current_position,
                end_position: None,
                kind: HirPartKind::Literal(vec![b]),
            });
        }
    }
}

/// Description of valid atoms extracted from an HIR.
#[derive(Debug)]
struct Atoms<'a> {
    start_part: &'a HirPart,
    end_part: &'a HirPart,
    literals: Vec<Vec<u8>>,
    rank: u32,
}

/// Generate all the possible literals from the given parts.
fn generate_literals(parts: &[HirPart]) -> Vec<Vec<u8>> {
    let mut literals = vec![Vec::new()];

    for part in parts {
        match &part.kind {
            HirPartKind::Literal(v) => {
                for lit in &mut literals {
                    lit.extend(v);
                }
            }
            HirPartKind::Class { bitmap } => {
                // Compute the cardinal product between the prefixes and the literals of the
                // alternation.
                literals = literals
                    .iter()
                    .flat_map(|prefix| {
                        bitmap
                            .iter()
                            .map(|b| prefix.iter().copied().chain(std::iter::once(b)).collect())
                    })
                    .collect();
            }
            HirPartKind::Alts { alts } => {
                let mut new_lits = Vec::new();
                for alt in alts {
                    let alt_lits = generate_literals(alt);
                    for left in &literals {
                        for right in &alt_lits {
                            let mut v = left.clone();
                            v.extend(right);
                            new_lits.push(v);
                        }
                    }
                }
                literals = new_lits;
            }
        }
    }

    literals
}

#[derive(Clone, Debug)]
struct HirPart {
    start_position: usize,
    end_position: Option<usize>,
    kind: HirPartKind,
}

/// Extract the best possible atoms from the given run.
fn run_into_atoms(parts: &[HirPart]) -> Option<Atoms<'_>> {
    // First, attempt to find a run of simple literals:
    // If the parts contain 4 successive bytes of sufficient
    // quality, there is no need for further logic.
    for part in parts {
        let HirPartKind::Literal(lit) = &part.kind else {
            continue;
        };
        let rank = atom_quality_from_literal(lit);
        if rank >= 80 {
            return Some(Atoms {
                start_part: part,
                end_part: part,
                literals: vec![lit.clone()],
                rank,
            });
        }
    }

    let mut best_slice = None;
    let mut best_rank = 0;

    // Compute the rank of every subslice, and track the best one
    for i in 0..parts.len() {
        let mut len = 0;
        for j in (i + 1)..=parts.len() {
            if let Some(rank) = get_parts_rank(&parts[i..j]) {
                if best_slice.is_none() || rank > best_rank {
                    best_slice = Some(i..j);
                    best_rank = rank;
                }
            }
            // Break if the sum of those parts is longer than the
            // atom size, but without counting the first element:
            // this indicates the first element no longer takes
            // part in the atom choice.
            if j != i + 1 {
                len += parts[j - 1].kind.len();
            }
            if len >= ATOM_SIZE {
                break;
            }
        }
    }

    // Generate the literals for this slice, and return it
    let (mut start, mut end) = best_slice.map(|range| (range.start, range.end))?;

    // Upscale the best slice by incorporating literals around it.
    // This is done because it improve performances: those literals will be
    // cheaply compared when confirming an AC match, avoiding going through
    // a full regex DFA if it does not match.
    while start > 0 && matches!(&parts[start - 1].kind, HirPartKind::Literal(_)) {
        start -= 1;
    }
    while end < parts.len() && matches!(&parts[end].kind, HirPartKind::Literal(_)) {
        end += 1;
    }

    // Finally, generate the literals and the atoms object.
    let literals = generate_literals(&parts[start..end]);
    Some(Atoms {
        start_part: &parts[start],
        end_part: &parts[end - 1],
        literals,
        rank: best_rank,
    })
}

fn get_parts_rank(parts: &[HirPart]) -> Option<u32> {
    // Limit ourselves to 256 possibilities max, which
    // is a double expansion of a X? mask in a hex-string.
    let mut combinations = 1_u32;
    for part in parts {
        combinations = combinations.saturating_mul(part.kind.combinations(256)?);
        if combinations > 256 {
            return None;
        }
    }

    let literals = generate_literals(parts);

    let quality = literals
        .iter()
        .map(|v| atom_quality_from_literal(v))
        .min()
        .unwrap_or(0);

    // For atoms of the same quality, we want to favor having as few as possible.
    // So subtract a penalty based on the number of combinations generated.
    // TODO: This is completely arbitrary, and might need some better fine tuning.
    Some(if combinations >= 100 {
        quality.saturating_sub(40)
    } else if combinations > 16 {
        quality.saturating_sub(20)
    } else if combinations > 1 {
        quality.saturating_sub(10)
    } else {
        quality
    })
}

impl Visitor for RunExtractor {
    type Output = Self;

    fn visit_pre(&mut self, hir: &Hir) -> VisitAction {
        match hir {
            Hir::Literal(b) => {
                self.add_byte(*b);
                VisitAction::Skip
            }
            Hir::Empty => VisitAction::Skip,
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
                        bitmap.set((c << 4) | *value);
                    }
                } else {
                    for c in 0..=15 {
                        bitmap.set(c | *value);
                    }
                }
                if *negated {
                    bitmap.invert();
                }
                self.add_part(HirPartKind::Class { bitmap });
                VisitAction::Skip
            }
            Hir::Dot | Hir::Assertion(_) | Hir::Repetition { .. } => {
                self.close_run(false);
                VisitAction::Skip
            }
            Hir::Alternation(alts) => {
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

    fn finish(self) -> Self::Output {
        self
    }
}

/// Visitor used to extract the AST nodes that are before and after extracted literals.
///
/// The goal is to be able to generate regex expressions to validate the regex, knowing the
/// position of literals found by the AC pass.
#[derive(Debug)]
struct PrePostExtractor<'a> {
    /// Stacks used during the visit to reconstruct compound nodes.
    stack: Vec<Vec<Hir>>,

    /// Top level node.
    toplevel_node: Hir,
    /// Is the toplevel node set. Only used for consistency checking.
    toplevel_is_set: bool,

    /// Hir part that is the boundary.
    boundary_part: &'a HirPart,
    /// Current position during the visit of the original AST.
    current_position: usize,

    /// Should the start of the HIR be extracted or the end.
    ///
    /// If true, the hir up to (and excluding) the boundary is included.
    /// If false, the hir from (and including) the boundary is included.
    is_pre: bool,
}

impl<'a> PrePostExtractor<'a> {
    fn new(boundary_part: &'a HirPart, is_pre: bool) -> Self {
        Self {
            stack: Vec::new(),

            toplevel_node: Hir::Empty,
            toplevel_is_set: false,

            boundary_part,
            current_position: 0,

            is_pre,
        }
    }

    fn push_stack(&mut self) {
        self.stack.push(Vec::new());
    }

    fn add_pre_post_hir(&mut self, node: &Hir) {
        if (self.is_pre
            && self
                .boundary_part
                .end_position
                .map_or(true, |end| self.current_position < end))
            || (!self.is_pre && self.current_position >= self.boundary_part.start_position)
        {
            self.add_node(node.clone());
        }
    }

    fn add_node(&mut self, node: Hir) {
        if self.stack.is_empty() {
            // Empty stack: we should only have a single HIR to set at top-level.
            self.toplevel_node = node;
            assert!(!self.toplevel_is_set, "top level HIR node already set");
            self.toplevel_is_set = true;
        } else {
            let pos = self.stack.len() - 1;
            self.stack[pos].push(node);
        }
    }
}

impl Visitor for PrePostExtractor<'_> {
    type Output = Hir;

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
            | Hir::Assertion(_) => {
                self.add_pre_post_hir(hir);
                VisitAction::Skip
            }
            Hir::Alternation(alts) => {
                // The boundary is an alternation. This alternation may have been
                // partially used for literal generation. Notably, the alternation
                // can be seen like this:
                //
                // <pre1><mid1><post1>|<pre2><mid2><post2>|...
                //
                // If only the pre parts were used, we need to only extract those
                // pre parts for the "pre" hir.
                // If only the post parts were used, we need to only extract those
                // post parts for the "post" hir.
                if self.current_position == self.boundary_part.start_position {
                    let HirPartKind::Alts { alts: alt_parts } = &self.boundary_part.kind else {
                        unreachable!();
                    };

                    let mut hirs = Vec::new();
                    for (alt_part, hir) in alt_parts.iter().zip(alts.iter()) {
                        if alt_part.is_empty() {
                            // This cannot really be reached since we avoid
                            // adding parts that contain alternates with one alt
                            // being empty. The reason is that this does not improve
                            // atoms at all since the empty part would not benefit
                            // from adding the alt in the atoms. Still, this could
                            // be reached if the algorithm changes and the right
                            // to do here is to use Hir::Empty, so just do that.
                            hirs.push(Hir::Empty);
                        } else {
                            let visitor = if self.is_pre {
                                PrePostExtractor::new(&alt_part[alt_part.len() - 1], true)
                            } else {
                                PrePostExtractor::new(&alt_part[0], false)
                            };
                            hirs.push(visit(hir, visitor));
                        }
                    }
                    self.add_node(Hir::Alternation(hirs));
                    VisitAction::Skip
                } else {
                    self.add_pre_post_hir(hir);
                    VisitAction::Skip
                }
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
                let mut stack = self.stack.pop().unwrap();

                if let Some(node) = stack.pop() {
                    self.add_node(Hir::Group(Box::new(node)));
                }
            }

            Hir::Concat(_) => {
                // Safety: this is a post visit, the pre visit pushed an element on the stack.
                let stack = self.stack.pop().unwrap();

                if !stack.is_empty() {
                    self.add_node(Hir::Concat(stack));
                }
            }
        }
    }

    fn finish(self) -> Self::Output {
        self.toplevel_node
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        regex::regex_hir_to_string,
        test_helpers::{expr_to_hir, test_type_traits_non_clonable},
    };

    use super::*;

    #[track_caller]
    fn test<T>(expr: &str, expected_lits: &[T], expected_pre: &str, expected_post: &str)
    where
        T: AsRef<[u8]>,
    {
        let hir = expr_to_hir(expr);
        let exprs = get_literals_details(&hir);
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

    #[test]
    fn test_hex_string_literals() {
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

        test(
            "{ ( AA | BB ) F? }",
            &[
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
            ],
            "",
            "",
        );

        test(
            "{ AB ( 01 | 23 45) ( 67 | 89 | F0 ) CD }",
            &[
                b"\xAB\x01\x67\xCD".as_slice(),
                b"\xAB\x23\x45\x67\xCD".as_slice(),
                b"\xAB\x01\x89\xCD".as_slice(),
                b"\xAB\x23\x45\x89\xCD".as_slice(),
                b"\xAB\x01\xF0\xCD".as_slice(),
                b"\xAB\x23\x45\xF0\xCD".as_slice(),
            ],
            "",
            "",
        );

        test(
            "{ CC ?? AB ( 01 | 23 45) ( 67 | 89 | F0 ) CD ?? FF }",
            &[
                b"\xAB\x01\x67\xCD".as_slice(),
                b"\xAB\x23\x45\x67\xCD".as_slice(),
                b"\xAB\x01\x89\xCD".as_slice(),
                b"\xAB\x23\x45\x89\xCD".as_slice(),
                b"\xAB\x01\xF0\xCD".as_slice(),
                b"\xAB\x23\x45\xF0\xCD".as_slice(),
            ],
            "\\xcc.\\xab(\\x01|\\x23E)(g|\\x89|\\xf0)\\xcd",
            "\\xab(\\x01|\\x23E)(g|\\x89|\\xf0)\\xcd.\\xff",
        );

        // Nothing can be extracted here
        test(
            "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
            &[
                b"\x01".as_slice(),
                b"\x23\x45",
                b"\x23\x67",
                b"\xFF\x45",
                b"\xFF\x67",
                b"\x23\x58\xAA",
                b"\x23\x58\xBB",
                b"\x23\x58\xCC",
                b"\xFF\x58\xAA",
                b"\xFF\x58\xBB",
                b"\xFF\x58\xCC",
                b"\x23\xDD",
                b"\xFF\xDD",
            ],
            "",
            "",
        );

        // Do not grow alternations too much, 32 max
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) ( 31 | 32 ) ( 41 | 42 ) ( 51 | 52 ) ( 61 | 62 ) ( 71 | 72 ) }",
            &[
                b"\x11\x21\x31\x41",
                b"\x12\x21\x31\x41",
                b"\x11\x22\x31\x41",
                b"\x12\x22\x31\x41",
                b"\x11\x21\x32\x41",
                b"\x12\x21\x32\x41",
                b"\x11\x22\x32\x41",
                b"\x12\x22\x32\x41",
                b"\x11\x21\x31\x42",
                b"\x12\x21\x31\x42",
                b"\x11\x22\x31\x42",
                b"\x12\x22\x31\x42",
                b"\x11\x21\x32\x42",
                b"\x12\x21\x32\x42",
                b"\x11\x22\x32\x42",
                b"\x12\x22\x32\x42",
            ],
            "",
            "(\\x11|\\x12)(!|\")(1|2)(A|B)(Q|R)(a|b)(q|r)",
        );

        test(
            "{ 11 22 33 44 55 66 77 ( 88 | 99 | AA | BB ) }",
            &[b"\x11\x22\x33\x44\x55\x66\x77"],
            "",
            r#"\x11"3DUfw(\x88|\x99|\xaa|\xbb)"#,
        );

        test(
            "{ 11 ?A 22 33 [1] 44 55 66 A? 77 88 }",
            &[
                b"\x44\x55\x66\xA0\x77\x88",
                b"\x44\x55\x66\xA1\x77\x88",
                b"\x44\x55\x66\xA2\x77\x88",
                b"\x44\x55\x66\xA3\x77\x88",
                b"\x44\x55\x66\xA4\x77\x88",
                b"\x44\x55\x66\xA5\x77\x88",
                b"\x44\x55\x66\xA6\x77\x88",
                b"\x44\x55\x66\xA7\x77\x88",
                b"\x44\x55\x66\xA8\x77\x88",
                b"\x44\x55\x66\xA9\x77\x88",
                b"\x44\x55\x66\xAA\x77\x88",
                b"\x44\x55\x66\xAB\x77\x88",
                b"\x44\x55\x66\xAC\x77\x88",
                b"\x44\x55\x66\xAD\x77\x88",
                b"\x44\x55\x66\xAE\x77\x88",
                b"\x44\x55\x66\xAF\x77\x88",
            ],
            r#"\x11[\x0a\x1a\x2a:JZjz\x8a\x9a\xaa\xba\xca\xda\xea\xfa]"3.DUf[\xa0-\xaf]w\x88"#,
            "",
        );

        // hex strings found in some real rules
        test(
            "{ 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? \
               00 04 00 02 00 04 ?? ?? }",
            &[b"\x00\x02\x00\x01\x00\x02"],
            "\\x00\\x01\\x00\\x01\\x00\\x02..\\x00\\x02\\x00\\x01\\x00\\x02",
            "\\x00\\x02\\x00\\x01\\x00\\x02..\
             \\x00\\x03\\x00\\x02\\x00\\x04....\\x00\\x04\\x00\\x02\\x00\\x04..",
        );

        test(
            "{ c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }",
            &[
                b"\xc7\x00\x01\x00\x00\x00",
                b"\xc7\x01\x01\x00\x00\x00",
                b"\xc7\x02\x01\x00\x00\x00",
                b"\xc7\x03\x01\x00\x00\x00",
                b"\xc7\x04\x01\x00\x00\x00",
                b"\xc7\x05\x01\x00\x00\x00",
                b"\xc7\x06\x01\x00\x00\x00",
                b"\xc7\x07\x01\x00\x00\x00",
                b"\xc7\x08\x01\x00\x00\x00",
                b"\xc7\x09\x01\x00\x00\x00",
                b"\xc7\x0A\x01\x00\x00\x00",
                b"\xc7\x0B\x01\x00\x00\x00",
                b"\xc7\x0C\x01\x00\x00\x00",
                b"\xc7\x0D\x01\x00\x00\x00",
                b"\xc7\x0E\x01\x00\x00\x00",
                b"\xc7\x0F\x01\x00\x00\x00",
            ],
            r"\xc7[\x00-\x0f]\x00\x00\x01\x00.{4,14}?\xc7[\x00-\x0f]\x01\x00\x00\x00",
            "",
        );
        test(
            "{ 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 }",
            &[b"\x00default\x2eproperties"],
            r"\x00\xcc\x00.....\x00default\x2eproperties",
            "",
        );
        test(
            "{ FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? \
              89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }",
            &[b"\x00\x83\xC5\x04\x8B"],
            "\\xfc\\xe8.\\x00\\x00\\x00.{0,32}?\\xeb\\x2b.\\x8b.\\x00\\x83\\xc5\\x04\\x8b",
            "\\x00\\x83\\xc5\\x04\\x8b.\\x001.\\x83\\xc5\\x04U\\x8b.\
             \\x001.\\x89.\\x001.\\x83\\xc5\\x04\\x83.\
             \\x041.9.t\\x02\\xeb\\xe8.\\xff.\\xe8\\xd0\\xff\\xff\\xff",
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

        test(
            "{ 81 EB ?? [0-8] E8 ?? 00 00 00 [0-8] 2B C3 }",
            &[b"\x2B\xC3"],
            r"\x81\xeb..{0,8}?\xe8.\x00\x00\x00.{0,8}?\x2b\xc3",
            "",
        );

        test(
            "{ 01 89 5? 08 8b 5? ?? 25 00 00 00 f0 89 5? }",
            &[
                b"\x01\x89\x50\x08\x8b",
                b"\x01\x89\x51\x08\x8b",
                b"\x01\x89\x52\x08\x8b",
                b"\x01\x89\x53\x08\x8b",
                b"\x01\x89\x54\x08\x8b",
                b"\x01\x89\x55\x08\x8b",
                b"\x01\x89\x56\x08\x8b",
                b"\x01\x89\x57\x08\x8b",
                b"\x01\x89\x58\x08\x8b",
                b"\x01\x89\x59\x08\x8b",
                b"\x01\x89\x5A\x08\x8b",
                b"\x01\x89\x5B\x08\x8b",
                b"\x01\x89\x5C\x08\x8b",
                b"\x01\x89\x5D\x08\x8b",
                b"\x01\x89\x5E\x08\x8b",
                b"\x01\x89\x5F\x08\x8b",
            ],
            r"",
            r"\x01\x89[P-_]\x08\x8b[P-_].%\x00\x00\x00\xf0\x89[P-_]",
        );

        test(
            "{ ( 11 11 11 | 33 33 33 ) AB D? }",
            &[b"\x11\x11\x11\xAB", b"\x33\x33\x33\xAB"],
            r"",
            r"(\x11\x11\x11|333)\xab[\xd0-\xdf]",
        );
    }

    #[test]
    fn test_regex_literals() {
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
        test("a.+bc.e", &[b"bc"], "a.+bc", "bc.e");
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
            &[b"hijklm"],
            "a((b(c)((d)()(e(g+h)ij)))kl)m",
            "",
        );

        test(" { AB CD 01 }", &[b" { AB CD 01 }"], "", "");

        test(
            r"\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)",
            &[b" AM)", b" PM)"],
            r"\x28[0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\x29",
            "",
        );

        test(
            r"b.*a(1234567|7892345).*d",
            &[b"a1234567", b"a7892345"],
            r"b.*a(1234567|7892345)",
            r"a(1234567|7892345).*d",
        );

        test("[ab]d[ef]", &[b"ade", b"adf", b"bde", b"bdf"], "", "");

        test("( () | () )", &[b"  ", b"  "], "", "");

        // Between a list of nul bytes and a single char, the single char is preferred
        test("\x00\x00\x00\x00.*a", &[b"a"], r"\x00\x00\x00\x00.*a", "");
        test(
            "(\x00\x00\x00\x00|abcd)a",
            &[b"\x00\x00\x00\x00a", b"abcda"],
            "",
            "",
        );

        test(
            "{ 12 34 56 78 ?? 00 00 00 00 }",
            &[b"\x12\x34\x56\x78"],
            "",
            r"\x124Vx.\x00\x00\x00\x00",
        );
    }

    #[test]
    fn test_alternates() {
        // Closed on the left, picked as start part
        test(
            "a(bcd|.ef)g.h",
            &["bcdg", "efg"],
            "a(bcd|.ef)g",
            "(bcd|ef)g.h",
        );
        test(
            "(bcd|.ef)g.h",
            &["bcdg", "efg"],
            "(bcd|.ef)g",
            "(bcd|.ef)g.h",
        );
        test("a(bcd|.ef)g", &["bcdg", "efg"], "a(bcd|.ef)g", "");
        test(
            "a(bcd|.ef|1.34)g.h",
            &["bcdg", "efg", "34g"],
            "a(bcd|.ef|1.34)g",
            "(bcd|ef|34)g.h",
        );

        // Break in middle, picked as start part
        test(
            "a(bcd|1.34)g.h",
            &["bcdg", "34g"],
            "a(bcd|1.34)g",
            "(bcd|34)g.h",
        );

        // Break in middle, picked as end part
        test(
            "1.a(bcd|13.4)g.h",
            &["abcd", "a13"],
            "1.a(bcd|13)",
            "a(bcd|13.4)g.h",
        );
        test("a(bcd|13.4)g.h", &["abcd", "a13"], "", "a(bcd|13.4)g.h");
        test("a(bcd|13.4)", &["abcd", "a13"], "", "a(bcd|13.4)");

        // Closed on right, picked as end part
        test("a(bcd|13.)", &["abcd", "a13"], "", "a(bcd|13.)");
        test("a(bcd|13.)g.h", &["abcd", "a13"], "", "a(bcd|13.)g.h");
        test(
            "1.a(bcd|13.)g.h",
            &["abcd", "a13"],
            "1.a(bcd|13)",
            "a(bcd|13.)g.h",
        );

        // Imbricated
        test(
            "1.a(b(c(de.f|gh.|ij)k|l(mn|p.)q)r)",
            &["abcde", "abcgh", "abcij", "ablmn", "ablp"],
            "1.a(b(c(de|gh|ij)|l(mn|p)))",
            "a(b(c(de.f|gh.|ij)k|l(mn|p.)q)r)",
        );

        // Best runs are inside: not possible to handle
        test(
            "1.(a.bcde.f|h.bcde.i).2",
            &["2"],
            "1.(a.bcde.f|h.bcde.i).2",
            "",
        );

        // misc
        test("(c.d|e)f", &["df", "ef"], "(c.d|e)f", "");
        test("a(c.d|e)", &["ac", "ae"], "", "a(c.d|e)");
        test("1.a(c.d|e)", &["ac", "ae"], "1.a(c|e)", "a(c.d|e)");
        test("abcd|ef.g", &["abcd", "ef"], "", "abcd|ef.g");
        test("a.cd|efgh", &["cd", "efgh"], "a.cd|efgh", "");

        test(
            "a.b(c23.d|e).f",
            &["bc23", "be"],
            "a.b(c23|e)",
            "b(c23.d|e).f",
        );
        test(
            "a.(c.23d|e)f.g",
            &["23df", "ef"],
            "a.(c.23d|e)f",
            "(23d|e)f.g",
        );

        test("1.(12.3|67.)xyz.t", &["xyz"], "1.(12.3|67.)xyz", "xyz.t");
    }

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(LiteralsDetails {
            literals: Vec::new(),
            pre_hir: None,
            post_hir: None,
        });

        test_type_traits_non_clonable(RunExtractor::new());
        let part = HirPart {
            start_position: 0,
            end_position: None,
            kind: HirPartKind::Literal(vec![b' ']),
        };
        test_type_traits_non_clonable(part.clone());
        test_type_traits_non_clonable(HirPartKind::Literal(vec![b' ']));
        test_type_traits_non_clonable(PrePostExtractor::new(&part, false));
        test_type_traits_non_clonable(Atoms {
            start_part: &part,
            end_part: &part,
            literals: Vec::new(),
            rank: 0,
        });
    }
}
