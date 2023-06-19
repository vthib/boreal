//! Literal extraction and computation from variable expressions.
use std::borrow::Cow;
use std::ops::Range;

use boreal_parser::regex::{
    AssertionKind, BracketedClass, BracketedClassItem, ClassKind, Node, PerlClass, PerlClassKind,
};

use crate::atoms::{atoms_rank, byte_rank};
use crate::regex::{visit, VisitAction, Visitor};

pub fn get_literals_details(node: &Node) -> LiteralsDetails {
    let splitter = Splitter::new();
    let splitter = visit(node, splitter);

    let last_position = splitter.current_position;
    let set = splitter.find_best_literals_set();

    match set {
        None => LiteralsDetails {
            literals: Vec::new(),
            pre_ast: None,
            post_ast: None,
        },
        Some(set) => {
            let (pre_ast, post_ast) = set.build_pre_post_ast(node, last_position);
            LiteralsDetails {
                literals: set.literals,
                pre_ast,
                post_ast,
            }
        }
    }
}

#[derive(Debug)]
pub struct LiteralsDetails {
    /// Literals extracted from the regex.
    pub literals: Vec<Vec<u8>>,

    /// AST for validators of matches on literals.
    ///
    /// The `pre` is the AST of the regex that must match before (and including) the literal.
    /// The `post` is the AST of the regex that must match after (and including) the literal.
    pub pre_ast: Option<Node>,
    pub post_ast: Option<Node>,
}

/// Visitor on a regex AST to split it into multiple literals.
///
/// This splits the AST into multiple chunks of either literals or regex nodes.
///
/// To extract literals:
/// - only group and concatenations are visited
/// - alternations are visited shallowly, and only taken into account if it is an alternation of
///   literals.
/// - repetitions and classes are not handled.
///
/// This strive to strike a balance between exhaustively finding any possible literal to compute
/// the best one, and a simple algorithm that makes creating the pre and post regex possible.
#[derive(Debug)]
struct Splitter<'a> {
    /// Set of best literals extracted so far.
    parts: Vec<AstPart<'a>>,

    /// Literals currently being built.
    literal_set_builder: Option<LiteralSetBuilder>,

    /// Current position of the visitor.
    ///
    /// This position is a simple counter of visited nodes.
    current_position: usize,
}

#[derive(Debug)]
enum AstPart<'a> {
    Literals(LiteralSet),
    Dot {
        start_position: usize,
    },
    Class {
        start_position: usize,
        kind: &'a ClassKind,
    },
    Other,
}

impl AstPart<'_> {
    fn combinatorics(&self) -> u64 {
        match self {
            AstPart::Literals(set) => set.literals.len() as u64,
            AstPart::Dot { .. } => 256,
            AstPart::Class {
                kind: ClassKind::Perl(p),
                ..
            } => perl_class_combinatorics(p),
            AstPart::Class {
                kind: ClassKind::Bracketed(BracketedClass { items, negated }),
                ..
            } => {
                let mut c = 0;
                for item in items {
                    // FIXME: this is wrong, there might be overlap in the items.
                    match item {
                        BracketedClassItem::Perl(p) => c += perl_class_combinatorics(p),
                        BracketedClassItem::Literal(_) => c += 1,
                        BracketedClassItem::Range(a, b) => c += u64::from(b.saturating_sub(*a) + 1),
                    }
                }
                if *negated {
                    256_u64.saturating_sub(c)
                } else {
                    c
                }
            }
            AstPart::Other => u64::MAX,
        }
    }

    fn rank(&self) -> u32 {
        match self {
            AstPart::Literals(set) => set.rank,
            AstPart::Dot { .. } => byte_rank(0),
            // FIXME: improve this:
            AstPart::Class { .. } => byte_rank(0),
            AstPart::Other => 0,
        }
    }

    fn start_position(&self) -> usize {
        match self {
            AstPart::Literals(set) => set.start_position,
            AstPart::Dot { start_position } => *start_position,
            AstPart::Class { start_position, .. } => *start_position,
            // TODO: avoid this
            AstPart::Other => unreachable!(),
        }
    }

    fn end_position(&self) -> usize {
        match self {
            AstPart::Literals(set) => set.end_position,
            AstPart::Dot { start_position } => start_position + 1,
            AstPart::Class { start_position, .. } => start_position + 1,
            // TODO: avoid this
            AstPart::Other => unreachable!(),
        }
    }
}

fn perl_class_combinatorics(cls: &PerlClass) -> u64 {
    let PerlClass { kind, negated } = cls;
    let c = match kind {
        PerlClassKind::Word => 26 + 26 + 10 + 1, // a-zA-Z0-9_
        PerlClassKind::Space => 6,               // '\t\n\r\v\f '
        PerlClassKind::Digit => 10,              // 0-9
    };
    if *negated {
        256 - c
    } else {
        c
    }
}

impl<'a> Splitter<'a> {
    fn new() -> Self {
        Self {
            parts: Vec::new(),
            literal_set_builder: None,

            current_position: 0,
        }
    }

    /// Add a byte to the literals being built.
    fn add_byte(&mut self, byte: u8) {
        let builder = self
            .literal_set_builder
            .get_or_insert_with(|| LiteralSetBuilder::new(self.current_position));

        builder.add_byte(byte);
    }

    fn add_part(&mut self, part: AstPart<'a>) {
        self.close();
        self.parts.push(part);
    }

    /// Visit an alternation to add it to the currently being build literals.
    ///
    /// Only allow alternations if each one is a literal or a concat of literals.
    fn visit_alternation(&mut self, alts: &[Node]) -> bool {
        let mut lits = Vec::new();

        for node in alts {
            match node {
                Node::Literal(b) => lits.push(vec![*b]),
                Node::Concat(nodes) => {
                    let mut lit = Vec::with_capacity(nodes.len());

                    for subnode in nodes {
                        match subnode {
                            Node::Literal(b) => lit.push(*b),
                            _ => return false,
                        }
                    }
                    lits.push(lit);
                }
                _ => return false,
            }
        }

        let current_len = self
            .literal_set_builder
            .as_ref()
            .map_or(1, |builder| builder.literals.len());
        if current_len.checked_mul(lits.len()).map_or(true, |v| v > 32) {
            return false;
        }

        let builder = self
            .literal_set_builder
            .get_or_insert_with(|| LiteralSetBuilder::new(self.current_position));
        builder.add_alternation(Cow::Owned(lits));
        true
    }

    /// Close currently being built literals.
    fn close(&mut self) {
        if let Some(builder) = self.literal_set_builder.take() {
            self.parts
                .push(AstPart::Literals(builder.build(self.current_position)));
        }
    }

    fn find_best_literals_set(self) -> Option<LiteralSet> {
        // Firstly, try to find explicit literals present in the regex.
        let set = self
            .parts
            .iter()
            .filter_map(|part| match part {
                AstPart::Literals(set) => Some(set),
                _ => None,
            })
            // We use min of -rank to ensure that the first element is returned
            // if multiple elements have the same rank. This is preferable to ease
            // validation of the matching against a literal match.
            .min_by_key(|set| -i64::from(set.rank));

        if let Some(set) = set {
            // If the length of the literals is 3 or more, this is enough for a
            // good quality atom.
            // TODO: should we always do the next step, and keep the best set?
            if !set.literals.is_empty() && set.literals[0].len() > 2 {
                return Some(set.clone());
            }
        }

        // Secondly, try to generate good enough literals by expanding classes
        // or dot expressions.
        //
        // This is useful to generate good literals from some hex strings such as:
        //
        // `{ AA ?? BB }`
        //
        // The first iteration will not find a good enough literals set, as
        // `AA` and `BB` are too small. However, expanding the dot expression
        // will generate a set of 256 literals, all starting with `AA` and
        // ending with `BB`, which is usable in a Aho-Corasick scan.

        // Find runs of AstPart that do not contain "AstPart::Other", which
        // marks anything that cannot be used to expand a literal.
        ExpandableIndexes::new(&self.parts)
            .map(|range| &self.parts[range])
            // On every such run, find the best literals by expanding parts
            .filter_map(find_best_literal_set_in_run)
            // Finally, select the best one
            .min_by_key(|set| -i64::from(set.rank))
    }
}

/// Builder for `LiteralSet`.
#[derive(Debug, Default)]
struct LiteralSetBuilder {
    /// List of literals extracted.
    literals: Vec<Vec<u8>>,

    /// Starting position of the literals (including the first bytes of the literals).
    start_position: usize,
}

impl LiteralSetBuilder {
    fn new(start_position: usize) -> Self {
        Self {
            literals: vec![Vec::new()],
            start_position,
        }
    }

    fn add_byte(&mut self, byte: u8) {
        for lit in &mut self.literals {
            lit.push(byte);
        }
    }

    fn add_alternation(&mut self, alts: Cow<[Vec<u8>]>) {
        // Compute the cardinal product between the prefixes and the literals of the
        // alternation.
        if self.literals.is_empty() {
            self.literals = alts.into_owned();
        } else {
            self.literals = self
                .literals
                .iter()
                .flat_map(|prefix| {
                    alts.iter()
                        .map(|lit| prefix.iter().copied().chain(lit.iter().copied()).collect())
                })
                .collect();
        }
    }

    fn add_class(&mut self, cls: &[u8]) {
        // Compute the cardinal product between the prefixes and the literals of the
        // alternation.
        if self.literals.is_empty() {
            self.literals = cls.iter().map(|b| vec![*b]).collect();
        } else {
            self.literals = self
                .literals
                .iter()
                .flat_map(|prefix| {
                    cls.iter()
                        .map(|b| prefix.iter().copied().chain(std::iter::once(*b)).collect())
                })
                .collect();
        }
    }

    fn build(self, end_position: usize) -> LiteralSet {
        LiteralSet::new(self.literals, self.start_position, end_position)
    }

    fn add_ast_part(&mut self, part: &AstPart) {
        match part {
            AstPart::Literals(set) => {
                if set.literals.len() == 1 {
                    for b in &set.literals[0] {
                        self.add_byte(*b);
                    }
                } else {
                    self.add_alternation(Cow::Borrowed(&set.literals));
                }
            }
            AstPart::Dot { .. } => {
                // TODO: replace with a static vec
                let cls: Vec<_> = (0..=255).collect();
                self.add_class(&cls);
            }
            AstPart::Class { kind, .. } => {
                // TODO: improve data objects used
                let cls = get_class_bytes(kind);
                let cls: Vec<_> = cls
                    .iter()
                    .enumerate()
                    .filter_map(|(i, b)| {
                        if *b {
                            // Safety: there are only 256 elements so casting to u8 is safe.
                            Some(u8::try_from(i).unwrap())
                        } else {
                            None
                        }
                    })
                    .collect();
                self.add_class(&cls);
            }
            // FIXME: avoid this
            AstPart::Other => unreachable!(),
        }
    }
}

// TODO: use something better than a hashset
fn get_class_bytes(kind: &ClassKind) -> [bool; 256] {
    let mut set = [false; 256];

    let negated = match kind {
        ClassKind::Perl(PerlClass { kind, negated }) => {
            add_perl_class_kind_to_set(kind, &mut set);
            *negated
        }
        ClassKind::Bracketed(BracketedClass { items, negated }) => {
            for item in items {
                match item {
                    BracketedClassItem::Perl(PerlClass { kind, negated }) => {
                        if *negated {
                            let mut subset = [false; 256];
                            add_perl_class_kind_to_set(kind, &mut subset);
                            for (i, b) in set.iter_mut().enumerate() {
                                if !subset[i] {
                                    *b = true;
                                }
                            }
                        } else {
                            add_perl_class_kind_to_set(kind, &mut set);
                        }
                    }
                    BracketedClassItem::Literal(b) => set[usize::from(*b)] = true,
                    BracketedClassItem::Range(a, b) => {
                        for i in *a..=*b {
                            set[usize::from(i)] = true;
                        }
                    }
                }
            }
            *negated
        }
    };

    if negated {
        for b in &mut set {
            *b = !*b;
        }
    }
    set
}

fn add_perl_class_kind_to_set(kind: &PerlClassKind, out: &mut [bool; 256]) {
    match kind {
        PerlClassKind::Word => {
            for b in (b'a'..=b'z').chain(b'A'..=b'Z').chain(b'0'..=b'9') {
                out[usize::from(b)] = true;
            }
            out[usize::from(b'_')] = true;
        }
        PerlClassKind::Space => {
            for b in [b'\n', b'\t', b'\r', b'\x0B', b'\x0C', b' '] {
                out[usize::from(b)] = true;
            }
        }
        PerlClassKind::Digit => {
            for b in b'0'..=b'9' {
                out[usize::from(b)] = true;
            }
        }
    }
}

// Max out combinators on expansion of one ?? and one X? or ?X
const MAX_COMBINATORICS: u64 = 256 * 16;

fn find_best_literal_set_in_run(run: &[AstPart<'_>]) -> Option<LiteralSet> {
    // Compute the combinatorics of every part.
    let details: Vec<_> = run
        .iter()
        .map(|part| PartDetails {
            combinatorics: part.combinatorics(),
            rank: part.rank(),
        })
        .collect();

    // For every slice in the run, compute the combinatorics of it, with two rules to simplify it:
    // - ignore slices that reach MAX_COMBINATORICS
    // - grow a valid slice when it can be done without increasing its combinatorics
    let mut valid_slices = Vec::new();
    'outer: for (i, i_details) in details.iter().enumerate() {
        valid_slices.push((i..=i, *i_details));
        let mut current_combinatorics = i_details.combinatorics;
        let mut current_rank = i_details.rank;
        for (j, j_details) in details.iter().enumerate().skip(i + 1) {
            if j_details.combinatorics == 1 {
                // We can append the element to the current valid slices, no need to split it.
                let last_index = valid_slices.len() - 1;
                valid_slices[last_index].0 = i..=j;
                // FIXME: this isn't really what the atoms_rank algorithm does. A better way of
                // computing this would be nice.
                valid_slices[last_index].1.rank += j_details.rank;
                continue;
            }
            current_combinatorics *= j_details.combinatorics;
            current_rank += j_details.rank;
            if current_combinatorics > MAX_COMBINATORICS {
                continue 'outer;
            }
            valid_slices.push((
                i..=j,
                PartDetails {
                    combinatorics: current_combinatorics,
                    rank: current_rank,
                },
            ));
        }
    }

    // Now, select the best slices while trying to limit combinatorics.
    // Try to find a good slice with max 256 combinations: expansion of a single `??`.
    // Otherwise, pick any good slice.
    let best_range = valid_slices
        .iter()
        .filter(|(_, details)| details.combinatorics <= 255)
        .min_by_key(|(_, details)| -i64::from(details.rank))
        .map(|(range, _)| range)
        .or_else(|| {
            valid_slices
                .iter()
                .min_by_key(|(_, details)| -i64::from(details.rank))
                .map(|(range, _)| range)
        })?;

    if best_range.is_empty() {
        return None;
    }

    let parts = &run[best_range.clone()];
    let mut builder = LiteralSetBuilder::new(parts[0].start_position());

    for part in parts {
        builder.add_ast_part(part);
    }
    Some(builder.build(parts[parts.len() - 1].end_position()))
}

#[derive(Debug, Copy, Clone)]
struct PartDetails {
    combinatorics: u64,
    rank: u32,
}

/// Object used as an iterator to return runs of `AstPart` objects that are
/// expandable into literals.
struct ExpandableIndexes<'a, 'b> {
    // Index of the first part that is expandable.
    start_index: usize,
    len: usize,
    // Current iterator over `AstPart` objects.
    parts: std::iter::Enumerate<std::slice::Iter<'a, AstPart<'b>>>,
}

impl<'a, 'b> ExpandableIndexes<'a, 'b> {
    fn new(parts: &'a [AstPart<'b>]) -> Self {
        Self {
            start_index: 0,
            len: parts.len(),
            parts: parts.iter().enumerate(),
        }
    }
}

impl Iterator for ExpandableIndexes<'_, '_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: see if all this can be rewrote, it isn't clean.
        for (index, part) in &mut self.parts {
            if let AstPart::Other = part {
                if self.start_index == index {
                    self.start_index = index + 1;
                } else {
                    let res = self.start_index..index;
                    self.start_index = index + 1;
                    return Some(res);
                }
            }
        }

        if self.start_index == self.len {
            None
        } else {
            let res = self.start_index..self.len;
            self.start_index = self.len;
            Some(res)
        }
    }
}

impl<'a> Visitor<'a> for Splitter<'a> {
    type Output = Self;

    fn visit_pre(&mut self, node: &'a Node) -> VisitAction {
        match node {
            Node::Literal(b) => {
                self.add_byte(*b);
                VisitAction::Skip
            }
            Node::Empty => VisitAction::Skip,
            Node::Dot => {
                self.add_part(AstPart::Dot {
                    start_position: self.current_position,
                });
                VisitAction::Skip
            }
            Node::Class(cls) => {
                self.add_part(AstPart::Class {
                    start_position: self.current_position,
                    kind: cls,
                });
                VisitAction::Skip
            }
            Node::Assertion(_) | Node::Repetition { .. } => {
                self.add_part(AstPart::Other);
                VisitAction::Skip
            }
            Node::Alternation(alts) => {
                if !self.visit_alternation(alts) {
                    self.add_part(AstPart::Other);
                }
                VisitAction::Skip
            }
            Node::Group(_) | Node::Concat(_) => VisitAction::Continue,
        }
    }

    fn visit_post(&mut self, node: &Node) {
        if !matches!(node, Node::Group(_) | Node::Concat(_)) {
            self.current_position += 1;
        }
    }

    fn finish(mut self) -> Self {
        self.close();
        self
    }
}

/// Set of literals extracted from a regex AST.
#[derive(Clone, Debug, Default)]
struct LiteralSet {
    /// List of literals extracted.
    literals: Vec<Vec<u8>>,

    /// Starting position of the literals (including the first bytes of the literals).
    start_position: usize,

    /// Ending position of the literals (excluding the last bytes of the literals).
    ///
    /// Unset if the literals end at the end of the regex.
    end_position: usize,

    /// Rank of the saved literals.
    rank: u32,
}

impl LiteralSet {
    fn new(literals: Vec<Vec<u8>>, start_position: usize, end_position: usize) -> Self {
        let rank = atoms_rank(&literals);

        Self {
            literals,
            start_position,
            end_position,
            rank,
        }
    }

    fn build_pre_post_ast(
        &self,
        original_node: &Node,
        last_position: usize,
    ) -> (Option<Node>, Option<Node>) {
        if self.literals.is_empty() {
            return (None, None);
        }

        let visitor = PrePostExtractor::new(self.start_position, self.end_position, last_position);
        let (pre, post) = visit(original_node, visitor);
        (
            pre.map(|pre| Node::Concat(vec![pre, Node::Assertion(AssertionKind::EndLine)])),
            post.map(|post| Node::Concat(vec![Node::Assertion(AssertionKind::StartLine), post])),
        )
    }
}

/// Visitor used to extract the AST nodes that are before and after extracted literals.
///
/// The goal is to be able to generate regex expressions to validate the regex, knowing the
/// position of literals found by the AC pass.
#[derive(Debug)]
struct PrePostExtractor {
    /// Stacks used during the visit to reconstruct compound nodes.
    pre_stack: Vec<Vec<Node>>,
    post_stack: Vec<Vec<Node>>,

    /// Top level pre node.
    ///
    /// May end up None if the extracted literals are from the start of the regex.
    pre_node: Option<Node>,

    /// Top level post node.
    ///
    /// May end up None if the extracted literals are from the end of the regex.
    post_node: Option<Node>,

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

    fn add_pre_post_node(&mut self, node: &Node) {
        if self.current_position < self.end_position && self.start_position > 0 {
            self.add_node(node.clone(), false);
        }
        if self.current_position >= self.start_position && self.end_position != self.last_position {
            self.add_node(node.clone(), true);
        }
    }

    fn add_node(&mut self, node: Node, post: bool) {
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

impl Visitor<'_> for PrePostExtractor {
    type Output = (Option<Node>, Option<Node>);

    fn visit_pre(&mut self, node: &Node) -> VisitAction {
        // XXX: be careful here, the visit *must* have the exact same behavior as for the
        // `LiteralsExtractor` visitor, to ensure the pre post expressions are correct.
        match node {
            Node::Literal(_)
            | Node::Repetition { .. }
            | Node::Dot
            | Node::Class(_)
            | Node::Empty
            | Node::Assertion(_)
            | Node::Alternation(_) => {
                self.add_pre_post_node(node);
                VisitAction::Skip
            }
            Node::Group(_) | Node::Concat(_) => {
                self.push_stack();
                VisitAction::Continue
            }
        }
    }

    fn visit_post(&mut self, node: &Node) {
        match node {
            Node::Literal(_)
            | Node::Repetition { .. }
            | Node::Dot
            | Node::Class(_)
            | Node::Empty
            | Node::Assertion(_)
            | Node::Alternation(_) => self.current_position += 1,
            Node::Group(_) => {
                // Safety: this is a post visit, the pre visit pushed an element on the stack.
                let mut pre = self.pre_stack.pop().unwrap();
                let mut post = self.post_stack.pop().unwrap();

                if let Some(node) = pre.pop() {
                    self.add_node(Node::Group(Box::new(node)), false);
                }
                if let Some(node) = post.pop() {
                    self.add_node(Node::Group(Box::new(node)), true);
                }
            }

            Node::Concat(_) => {
                // Safety: this is a post visit, the pre visit pushed an element on the stack.
                let pre = self.pre_stack.pop().unwrap();
                let post = self.post_stack.pop().unwrap();
                if !pre.is_empty() {
                    self.add_node(Node::Concat(pre), false);
                }
                if !post.is_empty() {
                    self.add_node(Node::Concat(post), true);
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
        regex::regex_ast_to_string,
        test_helpers::{
            parse_hex_string, parse_regex_string, test_type_traits, test_type_traits_non_clonable,
        },
    };

    use super::*;

    #[test]
    fn test_hex_string_literals() {
        #[track_caller]
        fn test(
            hex_string_expr: &str,
            expected_lits: &[&[u8]],
            expected_pre: &str,
            expected_post: &str,
        ) {
            let hex_string = parse_hex_string(hex_string_expr);
            let ast = super::super::hex_string::hex_string_to_ast(hex_string);

            let exprs = get_literals_details(&ast);
            assert_eq!(exprs.literals, expected_lits);
            assert_eq!(
                exprs
                    .pre_ast
                    .as_ref()
                    .map(regex_ast_to_string)
                    .unwrap_or_default(),
                expected_pre
            );
            assert_eq!(
                exprs
                    .post_ast
                    .as_ref()
                    .map(regex_ast_to_string)
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
                b"\xAB\x01\x67\xCD",
                b"\xAB\x01\x89\xCD",
                b"\xAB\x01\xF0\xCD",
                b"\xAB\x23\x45\x67\xCD",
                b"\xAB\x23\x45\x89\xCD",
                b"\xAB\x23\x45\xF0\xCD",
            ],
            "",
            "",
        );

        // Do not handle alternations that contains anything other than literals
        test(
            "{ AB ( ?? | FF ) CC }",
            &[b"\xAB"],
            "",
            r"^\xab(.|\xff)\xcc",
        );
        test(
            "{ AB ( ?? DD | FF ) CC }",
            &[b"\xAB"],
            "",
            r"^\xab(.\xdd|\xff)\xcc",
        );
        test(
            "{ AB ( 11 ?? DD | FF ) CC }",
            &[b"\xAB"],
            "",
            r"^\xab(\x11.\xdd|\xff)\xcc",
        );
        test(
            "{ AB ( 11 ?? | FF ) CC }",
            &[b"\xAB"],
            "",
            r"^\xab(\x11.|\xff)\xcc",
        );
        test(
            "{ ( 11 ?? | FF ) CC }",
            &[b"\xCC"],
            r"(\x11.|\xff)\xcc$",
            "",
        );
        test(
            "{ AB ( 11 | 12 ) 13 ( 1? | 14 ) }",
            &[b"\xAB\x11\x13", b"\xAB\x12\x13"],
            "",
            r"^\xab(\x11|\x12)\x13([\x10-\x1f]|\x14)",
        );

        // Test imbrication of alternations
        test(
            "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
            &[],
            "",
            "",
        );

        // Do not grow alternations too much, 32 max
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) ( 31 | 32 ) ( 41 | 42 ) ( 51 | 52 ) ( 61 | 62 ) ( 71 | 72 ) 88 }",
            &[
                b"\x11\x21\x31\x41\x51",
                b"\x11\x21\x31\x41\x52",
                b"\x11\x21\x31\x42\x51",
                b"\x11\x21\x31\x42\x52",
                b"\x11\x21\x32\x41\x51",
                b"\x11\x21\x32\x41\x52",
                b"\x11\x21\x32\x42\x51",
                b"\x11\x21\x32\x42\x52",
                b"\x11\x22\x31\x41\x51",
                b"\x11\x22\x31\x41\x52",
                b"\x11\x22\x31\x42\x51",
                b"\x11\x22\x31\x42\x52",
                b"\x11\x22\x32\x41\x51",
                b"\x11\x22\x32\x41\x52",
                b"\x11\x22\x32\x42\x51",
                b"\x11\x22\x32\x42\x52",
                b"\x12\x21\x31\x41\x51",
                b"\x12\x21\x31\x41\x52",
                b"\x12\x21\x31\x42\x51",
                b"\x12\x21\x31\x42\x52",
                b"\x12\x21\x32\x41\x51",
                b"\x12\x21\x32\x41\x52",
                b"\x12\x21\x32\x42\x51",
                b"\x12\x21\x32\x42\x52",
                b"\x12\x22\x31\x41\x51",
                b"\x12\x22\x31\x41\x52",
                b"\x12\x22\x31\x42\x51",
                b"\x12\x22\x31\x42\x52",
                b"\x12\x22\x32\x41\x51",
                b"\x12\x22\x32\x41\x52",
                b"\x12\x22\x32\x42\x51",
                b"\x12\x22\x32\x42\x52",
            ],
            "",
            "^(\\x11|\\x12)(!|\")(1|2)(A|B)(Q|R)(a|b)(q|r)\\x88",
        );
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) 33 ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10  ) }",
            &[
                b"\x11\x21\x33",
                b"\x11\x22\x33",
                b"\x12\x21\x33",
                b"\x12\x22\x33",
            ],
            "",
            r#"^(\x11|\x12)(!|")3(\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x10)"#,
        );

        // TODO: to improve, there are diminishing returns in computing the longest literals.
        test(
            "{ 11 22 33 44 55 66 77 ( 88 | 99 | AA | BB ) }",
            &[
                b"\x11\x22\x33\x44\x55\x66\x77\x88",
                b"\x11\x22\x33\x44\x55\x66\x77\x99",
                b"\x11\x22\x33\x44\x55\x66\x77\xAA",
                b"\x11\x22\x33\x44\x55\x66\x77\xBB",
            ],
            "",
            "",
        );

        test(
            "{ 11 ?A 22 33 [1] 44 55 66 A? 77 88 }",
            &[b"\x44\x55\x66"],
            r#"\x11[\x0a\x1a\x2a:JZjz\x8a\x9a\xaa\xba\xca\xda\xea\xfa]"3.DUf$"#,
            r#"^DUf[\xa0-\xaf]w\x88"#,
        );

        // hex strings found in some real rules
        test(
            "{ 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? \
               00 04 00 02 00 04 ?? ?? }",
            &[b"\x00\x03\x00\x02\x00\x04"],
            r"\x00\x01\x00\x01\x00\x02..\x00\x02\x00\x01\x00\x02..\x00\x03\x00\x02\x00\x04$",
            r"^\x00\x03\x00\x02\x00\x04....\x00\x04\x00\x02\x00\x04..",
        );

        test(
            "{ c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }",
            &[b"\x00\x00\x01\x00"],
            r"\xc7[\x00-\x0f]\x00\x00\x01\x00$",
            r"^\x00\x00\x01\x00.{4,14}?\xc7[\x00-\x0f]\x01\x00\x00\x00",
        );
        test(
            "{ 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 }",
            &[b"\x00\x64\x65\x66\x61\x75\x6C\x74\x2E\x70\x72\x6F\x70\x65\x72\x74\x69\x65\x73"],
            r"\x00\xcc\x00.....\x00default\x2eproperties$",
            "",
        );
        test(
            "{ FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? \
              89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }",
            &[b"\x83\xC5\x04\x55\x8B"],
            "\\xfc\\xe8.\\x00\\x00\\x00.{0,32}?\\xeb\\x2b.\\x8b.\\x00\\x83\\xc5\\x04\
             \\x8b.\\x001.\\x83\\xc5\\x04U\\x8b$",
            "^\\x83\\xc5\\x04U\\x8b.\\x001.\\x89.\\x001.\\x83\\xc5\\x04\\x83.\\x041.9.t\
             \\x02\\xeb\\xe8.\\xff.\\xe8\\xd0\\xff\\xff\\xff",
        );
        test(
            "{ ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) \
        04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) \
        02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) \
        ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }",
            &[b"\x02\xAA\x02\xC1"],
            "(\\x0f\\x82..\\x00\\x00|r.)(\\x80|A\\x80)([p-\\x7f]|\\x7c\\x24)\\x04\\x02\
             (\\x0f\\x85..\\x00\\x00|u.)(\\x81|A\\x81)([0-\\x3f]|<\\x24|\\x7d\\x00)\
             \\x02\\xaa\\x02\\xc1$",
            "^\\x02\\xaa\\x02\\xc1(\\x0f\\x85..\\x00\\x00|u.)(\\x8b|A\\x8b|D\\x8b|E\\x8b)\
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
            r"\x8b[\xc0-\xcf].{2,3}?\xf6[\xd0-\xdf]\x1a$",
            r"^\xf6[\xd0-\xdf]\x1a[\xc0-\xcf].{2,3}?.{2,3}?0[\x00-\x0f].[@-O]",
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
            r"\xc6[\x00-\x0f]\xe9[@-O][\x80-\x8f][@-O]\x05.{2,2}?\x89[@-O]\x01$",
            "",
        );

        test(
            "{ 61 ?? ( 62 63 | 64) 65 }",
            &[b"\x62\x63\x65", b"\x64\x65"],
            r"a.(bc|d)e$",
            "",
        );
    }

    #[test]
    fn test_regex_literals() {
        #[track_caller]
        fn test(expr: &str, expected_lits: &[&[u8]], expected_pre: &str, expected_post: &str) {
            let regex = parse_regex_string(expr);
            let exprs = get_literals_details(&regex.ast);
            assert_eq!(exprs.literals, expected_lits);
            assert_eq!(
                exprs
                    .pre_ast
                    .as_ref()
                    .map(regex_ast_to_string)
                    .unwrap_or_default(),
                expected_pre
            );
            assert_eq!(
                exprs
                    .post_ast
                    .as_ref()
                    .map(regex_ast_to_string)
                    .unwrap_or_default(),
                expected_post
            );
        }

        // Literal on the left side of a group
        test("abc(a+)b", &[b"abc"], "", "^abc(a+)b");
        // Literal spanning inside a group
        test("ab(ca+)b", &[b"abc"], "", "^ab(ca+)b");
        // Literal spanning up to the end of a group
        test("ab(c)a+b", &[b"abc"], "", "^ab(c)a+b");
        // Literal spanning in and out of a group
        test("a(b)ca+b", &[b"abc"], "", "^a(b)ca+b");

        // Literal on the right side of a group
        test("b(a+)abc", &[b"abc"], "b(a+)abc$", "");
        // Literal spanning inside a group
        test("b(a+a)bc", &[b"abc"], "b(a+a)bc$", "");
        // Literal starting in a group
        test("ba+(ab)c", &[b"abc"], "ba+(ab)c$", "");
        // Literal spanning in and out of a group
        test("ba+a(bc)", &[b"abc"], "ba+a(bc)$", "");

        // A few tests on closing nodes
        test("a.+bcd{2}e", &[b"bc"], "a.+bc$", "^bcd{2}e");
        test("a.+bc.e", &[b"bc"], "a.+bc$", "^bc.e");
        test("a.+bc\\B.e", &[b"bc"], "a.+bc$", "^bc\\B.e");
        test("a.+bc[aA]e", &[b"bcAe", b"bcae"], "a.+bc[aA]e$", "");
        test("a.+bc()de", &[b"bcde"], "a.+bc()de$", "");

        test(
            "a+(b.c)(d)(ef)g+",
            &[b"cdef"],
            "a+(b.c)(d)(ef)$",
            "^(c)(d)(ef)g+",
        );

        test(
            "a((b(c)((d)()(e(g+h)ij)))kl)m",
            &[b"hijklm"],
            "a((b(c)((d)()(e(g+h)ij)))kl)m$",
            "",
        );

        test("{ AB CD 01 }", &[b"{ AB CD 01 }"], "", "");
    }

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(LiteralsDetails {
            literals: Vec::new(),
            pre_ast: None,
            post_ast: None,
        });

        test_type_traits_non_clonable(Splitter::new());
        test_type_traits(LiteralSet::default());
        test_type_traits_non_clonable(PrePostExtractor::new(0, 0, 0));
    }
}
