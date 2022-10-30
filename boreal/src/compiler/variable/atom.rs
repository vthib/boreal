//! Atom extraction and computation from variable expressions.
//!
//! An atom is a byte string that is contained in the original variable, which additional
//! constraints:
//!
//! - If an atom is found, then the variable may be present.
//! - If no atoms are found, then the variable cannot be found.
//!
//! That is, for any possible match of a variable, an atom in the set of the variable must be
//! contained in the match.
//!
//! Atoms are selected by computing a rank for each atom: the higher the rank, the preferred the
//! atom. This rank is related to how rare the atom should be found during scanning, and thus
//! the rate of false positive matches.
use std::ops::Range;

use boreal_parser::regex::{AssertionKind, Node};
use regex::bytes::Regex;

use crate::regex::add_ast_to_string;

use super::VariableCompilationError;

// FIXME: add lots of tests here...

pub fn build_atomized_regex(
    node: &Node,
) -> Result<Option<AtomizedRegex>, VariableCompilationError> {
    match build_atomized_expressions(node) {
        Some(v) => Ok(Some(AtomizedRegex::new(v)?)),
        None => Ok(None),
    }
}

fn build_atomized_expressions(node: &Node) -> Option<AtomizedExpressions> {
    let mut visitor = AtomVisitor::new(AstPosition(Vec::new()));
    visitor.visit(node);
    visitor.into_set().into_atomized_expression(node)
}

#[derive(Debug)]
pub struct AtomizedExpressions {
    /// Literals extracted from the regex.
    literals: Vec<Vec<u8>>,

    /// Expression for validators of matches on literals.
    ///
    /// The `pre` is the regex expression that must match before (and including) the literal.
    /// The `post` is the regex expression that must match after (and including) the literal.
    pre: String,
    post: String,
}

#[derive(Debug)]
pub struct AtomizedRegex {
    /// Literals extracted from the regex.
    literals: Vec<Vec<u8>>,

    /// Validators of matches on literals.
    left_validator: Regex,
    right_validator: Regex,
}

impl AtomizedRegex {
    fn new(expr: AtomizedExpressions) -> Result<Self, VariableCompilationError> {
        Ok(Self {
            literals: expr.literals,
            left_validator: super::compile_regex_expr(&expr.pre, false, true)?,
            right_validator: super::compile_regex_expr(&expr.post, false, true)?,
        })
    }

    pub fn literals(&self) -> &[Vec<u8>] {
        &self.literals
    }

    pub fn check_literal_match(&self, mem: &[u8], mat: Range<usize>) -> Option<Range<usize>> {
        if let Some(pre_match) = self.left_validator.find(&mem[..mat.end]) {
            if let Some(post_match) = self.right_validator.find(&mem[mat.start..]) {
                return Some(pre_match.start()..(mat.start + post_match.end()));
            }
        }
        None
    }
}

/// Set of atoms that allows quickly searching for the eventual presence of a variable.
#[derive(Debug, Default)]
pub struct AtomSet {
    atoms: Vec<Atom>,
    literals: Vec<Vec<u8>>,
    rank: u32,
}

impl AtomSet {
    fn new(atoms: Vec<Atom>) -> Self {
        let rank = atoms_rank(&atoms);
        let literals = atoms.iter().map(|v| v.literals.clone()).collect();
        Self {
            atoms,
            literals,
            rank,
        }
    }

    fn add_atoms(&mut self, atoms: Vec<Atom>) {
        self.add_set(Self::new(atoms));
    }

    fn add_set(&mut self, other: Self) {
        // this.atoms is one possible set, and the provided atoms are another one.
        // Keep the one with the best rank.
        if self.atoms.is_empty() || other.rank > self.rank {
            *self = other;
        }
    }

    pub fn into_atomized_expression(self, original_node: &Node) -> Option<AtomizedExpressions> {
        if self.literals.is_empty() {
            None
        } else {
            let mut pre = String::new();
            let mut post = String::new();
            add_ast_to_string(&self.build_pre_ast(original_node), &mut pre);
            add_ast_to_string(&self.build_post_ast(original_node), &mut post);

            Some(AtomizedExpressions {
                literals: self.literals,
                pre,
                post,
            })
        }
    }

    fn build_pre_ast(&self, original_node: &Node) -> Node {
        match &self.atoms[..] {
            [] => Node::Empty,
            [atom] => atom.build_pre_ast(original_node),
            atoms => Node::Alternation(
                atoms
                    .iter()
                    .map(|atom| atom.build_pre_ast(original_node))
                    .collect(),
            ),
        }
    }

    fn build_post_ast(&self, original_node: &Node) -> Node {
        match &self.atoms[..] {
            [] => Node::Empty,
            [atom] => atom.build_post_ast(original_node),
            atoms => Node::Alternation(
                atoms
                    .iter()
                    .map(|atom| atom.build_post_ast(original_node))
                    .collect(),
            ),
        }
    }
}

/// Retrieve the rank of a set of atoms.
fn atoms_rank(atoms: &[Atom]) -> u32 {
    // Get the min rank. This is probably the best solution, it isn't clear if a better one
    // is easy to find.
    atoms
        .iter()
        .map(|atom| literals_rank(&atom.literals))
        .min()
        .unwrap_or(0)
}

pub fn literals_rank(lits: &[u8]) -> u32 {
    // This algorithm is straight copied from libyara.
    // TODO: Probably want to revisit this.
    let mut quality = 0_u32;
    let mut bitmask = [false; 256];
    let mut nb_uniq = 0;

    for lit in lits {
        match *lit {
            0x00 | 0x20 | 0xCC | 0xFF => quality += 12,
            v if (b'a'..=b'z').contains(&v) => quality += 18,
            _ => quality += 20,
        }

        if !bitmask[*lit as usize] {
            bitmask[*lit as usize] = true;
            nb_uniq += 1;
        }
    }

    // If all the bytes in the atom are equal and very common, let's penalize
    // it heavily.
    if nb_uniq == 1 && (bitmask[0] || bitmask[0x20] || bitmask[0xCC] || bitmask[0xFF]) {
        quality -= 10 * u32::try_from(lits.len()).unwrap_or(30);
    }
    // In general atoms with more unique bytes have a better quality, so let's
    // boost the quality in the amount of unique bytes.
    else {
        quality += 2 * nb_uniq;
    }

    quality
}

#[derive(Debug)]
struct AtomVisitor {
    set: AtomSet,

    left: Vec<Atom>,
    right: Vec<Atom>,

    contiguous: bool,

    position: AstPosition,
}

impl AtomVisitor {
    fn new(position: AstPosition) -> Self {
        Self {
            set: AtomSet::default(),
            left: Vec::new(),
            right: Vec::new(),
            contiguous: true,
            position,
        }
    }

    fn visit(&mut self, node: &Node) {
        match node {
            Node::Literal(b) => self.add_byte(*b),
            Node::Repetition { .. } | Node::Dot | Node::Class(_) => self.close(),
            Node::Empty => (),
            Node::Assertion(_) => self.clear(),
            Node::Group(node) => {
                self.position.0.push(0);
                self.visit(node);
                let _ = self.position.0.pop();
            }
            Node::Concat(nodes) => {
                for (i, node) in nodes.iter().enumerate() {
                    self.position.0.push(i);
                    self.visit(node);
                    let _ = self.position.0.pop();
                }
            }
            Node::Alternation(nodes) => self.add_alternatives(nodes),
        }
    }

    fn add_byte(&mut self, byte: u8) {
        let atoms = if self.contiguous {
            &mut self.left
        } else {
            &mut self.right
        };
        if atoms.is_empty() {
            atoms.push(Atom::new(&self.position));
        }
        for atom in atoms {
            atom.literals.push(byte);
        }
    }

    fn clear(&mut self) {
        if self.contiguous {
            self.left.clear();
        } else {
            self.right.clear();
        }
    }

    fn close(&mut self) {
        if self.contiguous {
            for atom in &mut self.left {
                atom.close(&self.position);
            }
            self.contiguous = false;
        } else if !self.right.is_empty() {
            for atom in &mut self.right {
                atom.close(&self.position);
            }
            self.set.add_atoms(std::mem::take(&mut self.right));
        }
    }

    // Merge another possible HexAtoms with the current one (as an alternation).
    fn concat(&mut self, other: Self) {
        self.set.add_set(other.set);
        self.cartesian_product(other.left);
        if !other.contiguous {
            self.close();
            self.right = other.right;
        }
        self.contiguous = self.contiguous && other.contiguous;
    }

    fn add_alternatives(&mut self, alts: &[Node]) {
        // Then, do the cross product between our prefixes literals and the alternatives
        if let Some(suffixes) = alts
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let mut hex_atoms = AtomVisitor::new(self.position.clone());
                hex_atoms.position.0.push(i);
                hex_atoms.visit(node);
                hex_atoms
            })
            .reduce(AtomVisitor::reduce_alternate)
        {
            self.concat(suffixes);
        }
    }

    fn into_set(mut self) -> AtomSet {
        // Close the left & right sets, and keep the best one across the three
        self.set.add_atoms(self.left);
        self.set.add_atoms(self.right);
        self.set
    }

    fn reduce_alternate(mut self, other: Self) -> Self {
        // FIXME: this does not seem right
        self.set.add_set(other.set);

        // If other is non contiguous, and a boundary is empty, it means it contains a non
        // atomicable pattern on the boundary. This makes this boundary non expressable in
        // alternations, which itself is expressed by an empty Vec.
        if other.left.is_empty() {
            self.left = Vec::new();
        }
        if !other.contiguous && other.right.is_empty() {
            self.right = Vec::new();
        }

        let add = |a: &mut Vec<_>, b| {
            if !a.is_empty() {
                a.extend_from_slice(b);
            }
        };
        match (self.contiguous, other.contiguous) {
            (true, true) => add(&mut self.left, &other.left),
            (true, false) => {
                add(&mut self.left, &other.left);
                add(&mut self.left, &other.right);
            }
            (false, true) => {
                add(&mut self.left, &other.left);
                add(&mut self.right, &other.left);
            }
            (false, false) => {
                add(&mut self.left, &other.left);
                add(&mut self.right, &other.right);
            }
        };

        self.contiguous = self.contiguous && other.contiguous;
        self
    }

    fn cartesian_product(&mut self, suffixes: Vec<Atom>) {
        // Suffixes are non expressable with atoms, so we have to close the current ones.
        if suffixes.is_empty() {
            self.close();
            return;
        }

        let prefixes = if self.contiguous {
            &mut self.left
        } else {
            &mut self.right
        };

        if prefixes.is_empty() {
            *prefixes = suffixes;
            return;
        }

        // Don't make the combinatory grow too much
        if prefixes
            .len()
            .checked_mul(suffixes.len())
            .map_or(false, |v| v > 32)
        {
            self.close();
            self.right = suffixes;
            return;
        }

        *prefixes = prefixes
            .iter()
            .flat_map(|prefix| {
                suffixes.iter().map(|suffix| Atom {
                    literals: prefix
                        .literals
                        .iter()
                        .copied()
                        .chain(suffix.literals.iter().copied())
                        .collect(),
                    atom_start: prefix.atom_start.clone(),
                    atom_end: suffix.atom_end.clone(),
                })
            })
            .collect();
    }
}

/// Position inside a Regex AST.
///
/// This position is stored as a set of indexes into the AST subtree.
#[derive(Clone, Debug, Default)]
struct AstPosition(Vec<usize>);

#[derive(Clone, Debug)]
struct Atom {
    literals: Vec<u8>,

    atom_start: AstPosition,
    atom_end: Option<AstPosition>,
}

impl Atom {
    fn new(position: &AstPosition) -> Self {
        Self {
            literals: Vec::new(),
            atom_start: position.clone(),
            atom_end: None,
        }
    }

    fn close(&mut self, position: &AstPosition) {
        self.atom_end = Some(position.clone());
    }

    fn build_pre_ast(&self, original_node: &Node) -> Node {
        let mut nodes = match build_ast_up_to(original_node, &self.atom_start.0) {
            // TODO: avoid building a regex if this is Node::Empty
            Node::Concat(nodes) => nodes,
            node => {
                let mut nodes = Vec::with_capacity(self.literals.len() + 2);
                nodes.push(node);
                nodes
            }
        };
        for b in &self.literals {
            nodes.push(Node::Literal(*b));
        }
        nodes.push(Node::Assertion(AssertionKind::EndLine));
        Node::Concat(nodes)
    }

    fn build_post_ast(&self, original_node: &Node) -> Node {
        match &self.atom_end {
            // TODO: avoid building a regex in this case
            None => {
                let mut nodes = Vec::new();
                nodes.push(Node::Assertion(AssertionKind::StartLine));
                for b in &self.literals {
                    nodes.push(Node::Literal(*b));
                }
                Node::Concat(nodes)
            }
            Some(end_pos) => {
                let mut nodes = Vec::new();
                nodes.push(Node::Assertion(AssertionKind::StartLine));
                for b in &self.literals {
                    nodes.push(Node::Literal(*b));
                }
                match build_ast_from(original_node, &end_pos.0) {
                    Node::Concat(post_nodes) => nodes.extend(post_nodes),
                    node => nodes.push(node),
                }
                Node::Concat(nodes)
            }
        }
    }
}

fn build_ast_up_to(node: &Node, position: &[usize]) -> Node {
    match node {
        Node::Literal(_)
        | Node::Repetition { .. }
        | Node::Dot
        | Node::Class(_)
        | Node::Empty
        | Node::Assertion(_) => Node::Empty,
        Node::Group(subnode) => match position {
            [] => Node::Empty,
            [idx, rest @ ..] => {
                debug_assert!(*idx == 0);
                Node::Group(Box::new(build_ast_up_to(subnode, rest)))
            }
        },
        Node::Concat(nodes) => match position {
            [] => Node::Empty,
            [0, rest @ ..] => build_ast_up_to(&nodes[0], rest),
            [idx, rest @ ..] => {
                let mut new_nodes = Vec::new();
                new_nodes.extend(nodes[..*idx].iter().cloned());
                new_nodes.push(build_ast_up_to(&nodes[*idx], rest));
                Node::Concat(new_nodes)
            }
        },
        Node::Alternation(nodes) => match position {
            [] => Node::Empty,
            [idx, rest @ ..] => {
                debug_assert!(*idx < nodes.len());
                build_ast_up_to(&nodes[*idx], rest)
            }
        },
    }
}

fn build_ast_from(node: &Node, position: &[usize]) -> Node {
    match node {
        Node::Literal(_)
        | Node::Repetition { .. }
        | Node::Dot
        | Node::Class(_)
        | Node::Empty
        | Node::Assertion(_) => node.clone(),
        Node::Group(subnode) => match position {
            [] => node.clone(),
            [idx, rest @ ..] => {
                debug_assert!(*idx == 0);
                Node::Group(Box::new(build_ast_from(subnode, rest)))
            }
        },
        Node::Concat(nodes) => match position {
            [] => node.clone(),
            [idx, rest @ ..] if *idx == nodes.len() - 1 => build_ast_from(&nodes[*idx], rest),
            [idx, rest @ ..] => {
                let mut new_nodes = Vec::new();
                new_nodes.push(build_ast_from(&nodes[*idx], rest));
                new_nodes.extend(nodes[(*idx + 1)..].iter().cloned());
                Node::Concat(new_nodes)
            }
        },
        Node::Alternation(nodes) => match position {
            [] => node.clone(),
            [idx, rest @ ..] => {
                debug_assert!(*idx < nodes.len());
                build_ast_from(&nodes[*idx], rest)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::variable::tests::parse_hex_string;

    use super::*;

    #[test]
    fn test_hex_string_atoms() {
        #[track_caller]
        fn test(
            hex_string_expr: &str,
            expected_lits: &[&[u8]],
            expected_pre: &str,
            expected_post: &str,
        ) {
            let hex_string = parse_hex_string(hex_string_expr);
            let ast = super::super::hex_string::hex_string_to_ast(hex_string);

            let exprs = build_atomized_expressions(&ast);
            if expected_lits.is_empty() {
                assert!(exprs.is_none());
            } else {
                let exprs = exprs.unwrap();
                assert_eq!(exprs.literals, expected_lits);
                assert_eq!(exprs.pre, expected_pre);
                assert_eq!(exprs.post, expected_post);
            }
        }

        test(
            "{ AB CD 01 }",
            &[b"\xab\xcd\x01"],
            r"\xab\xcd\x01$",
            r"^\xab\xcd\x01",
        );

        test(
            "{ AB ?D 01 }",
            &[b"\xab"],
            r"\xab$",
            r"^\xab[\x0d\x1d\x2d=M\x5dm\x7d\x8d\x9d\xad\xbd\xcd\xdd\xed\xfd]\x01",
        );

        test("{ D? FE }", &[b"\xfe"], r"[\xd0-\xdf]\xfe$", r"^\xfe");

        test(
            "{ ( AA | BB ) F? }",
            &[b"\xAA", b"\xBB"],
            // FIXME: this looks weird "(\xaa|\xbb)$" would be cleaner
            r"()\xaa$|()\xbb$",
            // FIXME: this looks weird "^(\xaa|\xbb)[\xf0-\xff]" would be cleaner
            r"^\xaa[\xf0-\xff]|^\xbb[\xf0-\xff]",
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
            "\\xab\\x01g\\xcd$|\\xab\\x01\\x89\\xcd$|\\xab\\x01\\xf0\\xcd$|\\xab\\x23Eg\\xcd$|\
             \\xab\\x23E\\x89\\xcd$|\\xab\\x23E\\xf0\\xcd$",
            "^\\xab\\x01g\\xcd|^\\xab\\x01\\x89\\xcd|^\\xab\\x01\\xf0\\xcd|^\\xab\\x23Eg\\xcd|\
             ^\\xab\\x23E\\x89\\xcd|^\\xab\\x23E\\xf0\\xcd",
        );

        // jump or masked bytes should invalidate alternations if one branch does not have a single
        test(
            "{ AB ( ?? | FF ) CC }",
            &[b"\xAB"],
            r"\xab$",
            r"^\xab(.|\xff)\xcc",
        );
        test(
            "{ AB ( ?? DD | FF ) CC }",
            &[b"\xDD\xCC", b"\xFF\xCC"],
            // FIXME: ugly
            r"\xab(.)\xdd\xcc$|\xab()\xff\xcc$",
            r"^\xdd\xcc|^\xff\xcc",
        );
        test(
            "{ AB ( 11 ?? DD | FF ) CC }",
            &[b"\xAB\x11", b"\xAB\xFF"],
            r"\xab\x11$|\xab\xff$",
            // FIXME: buggy
            r"^\xab\x11(\x11.\xdd|\xff)\xcc|^\xab\xff(\x11.\xdd|\xff)\xcc",
        );
        test(
            "{ AB ( 11 ?? | FF ) CC }",
            &[b"\xAB\x11", b"\xAB\xFF"],
            r"\xab\x11$|\xab\xff$",
            // FIXME: buggy
            r"^\xab\x11(\x11.|\xff)\xcc|^\xab\xff(\x11.|\xff)\xcc",
        );
        // TODO: generating just CC would be better
        test(
            "{ ( 11 ?? | FF ) CC }",
            &[b"\x11", b"\xFF"],
            r"()\x11$|()\xff$",
            // FIXME: buggy
            r"^\x11(\x11.|\xff)\xcc|^\xff(\x11.|\xff)\xcc",
        );
        test(
            "{ AB ( 11 | 12 ) 13 ( 1? | 14 ) }",
            &[b"\xAB\x11\x13", b"\xAB\x12\x13"],
            r"\xab\x11\x13$|\xab\x12\x13$",
            r"^\xab\x11\x13([\x10-\x1f]|\x14)|^\xab\x12\x13([\x10-\x1f]|\x14)",
        );

        // Test imbrication of alternations
        test(
            "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
            &[
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
            ],
            "()\\x01$|(())\\x23E$|(())\\x23g$|(())\\x23X\\xaa$|(())\\x23X\\xbb$|(())\\x23X\\xcc$|\
             (())\\x23\\xdd$|(())\\xffE$|(())\\xffg$|(())\\xffX\\xaa$|(())\\xffX\\xbb$|\
             (())\\xffX\\xcc$|(())\\xff\\xdd$",
            "^\\x01|^\\x23E|^\\x23g|^\\x23X\\xaa|^\\x23X\\xbb|^\\x23X\\xcc|^\\x23\\xdd|^\\xffE|\
             ^\\xffg|^\\xffX\\xaa|^\\xffX\\xbb|^\\xffX\\xcc|^\\xff\\xdd",
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
            "()\\x11!1AQ$|()\\x11!1AR$|()\\x11!1BQ$|()\\x11!1BR$|()\\x11!2AQ$|()\\x11!2AR$|\
             ()\\x11!2BQ$|()\\x11!2BR$|()\\x11\"1AQ$|()\\x11\"1AR$|()\\x11\"1BQ$|()\\x11\"1BR$|\
             ()\\x11\"2AQ$|()\\x11\"2AR$|()\\x11\"2BQ$|()\\x11\"2BR$|()\\x12!1AQ$|()\\x12!1AR$|\
             ()\\x12!1BQ$|()\\x12!1BR$|()\\x12!2AQ$|()\\x12!2AR$|()\\x12!2BQ$|()\\x12!2BR$|\
             ()\\x12\"1AQ$|()\\x12\"1AR$|()\\x12\"1BQ$|()\\x12\"1BR$|()\\x12\"2AQ$|()\\x12\"2AR$|\
             ()\\x12\"2BQ$|()\\x12\"2BR$",
            "^\\x11!1AQ(a|b)(q|r)\\x88|^\\x11!1AR(a|b)(q|r)\\x88|^\\x11!1BQ(a|b)(q|r)\\x88|\
             ^\\x11!1BR(a|b)(q|r)\\x88|^\\x11!2AQ(a|b)(q|r)\\x88|^\\x11!2AR(a|b)(q|r)\\x88|\
             ^\\x11!2BQ(a|b)(q|r)\\x88|^\\x11!2BR(a|b)(q|r)\\x88|^\\x11\"1AQ(a|b)(q|r)\\x88|\
             ^\\x11\"1AR(a|b)(q|r)\\x88|^\\x11\"1BQ(a|b)(q|r)\\x88|^\\x11\"1BR(a|b)(q|r)\\x88|\
             ^\\x11\"2AQ(a|b)(q|r)\\x88|^\\x11\"2AR(a|b)(q|r)\\x88|^\\x11\"2BQ(a|b)(q|r)\\x88|\
             ^\\x11\"2BR(a|b)(q|r)\\x88|^\\x12!1AQ(a|b)(q|r)\\x88|^\\x12!1AR(a|b)(q|r)\\x88|\
             ^\\x12!1BQ(a|b)(q|r)\\x88|^\\x12!1BR(a|b)(q|r)\\x88|^\\x12!2AQ(a|b)(q|r)\\x88|\
             ^\\x12!2AR(a|b)(q|r)\\x88|^\\x12!2BQ(a|b)(q|r)\\x88|^\\x12!2BR(a|b)(q|r)\\x88|\
             ^\\x12\"1AQ(a|b)(q|r)\\x88|^\\x12\"1AR(a|b)(q|r)\\x88|^\\x12\"1BQ(a|b)(q|r)\\x88|\
             ^\\x12\"1BR(a|b)(q|r)\\x88|^\\x12\"2AQ(a|b)(q|r)\\x88|^\\x12\"2AR(a|b)(q|r)\\x88|\
             ^\\x12\"2BQ(a|b)(q|r)\\x88|^\\x12\"2BR(a|b)(q|r)\\x88",
        );
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) 33 ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10  ) }",
            &[
                b"\x11\x21\x33",
                b"\x11\x22\x33",
                b"\x12\x21\x33",
                b"\x12\x22\x33",
            ],
            r#"()\x11!3$|()\x11"3$|()\x12!3$|()\x12"3$"#,
            "^\\x11!3(\\x01|\\x02|\\x03|\\x04|\\x05|\\x06|\\x07|\\x08|\\x09|\\x10)|\
             ^\\x11\"3(\\x01|\\x02|\\x03|\\x04|\\x05|\\x06|\\x07|\\x08|\\x09|\\x10)|\
             ^\\x12!3(\\x01|\\x02|\\x03|\\x04|\\x05|\\x06|\\x07|\\x08|\\x09|\\x10)|\
             ^\\x12\"3(\\x01|\\x02|\\x03|\\x04|\\x05|\\x06|\\x07|\\x08|\\x09|\\x10)",
        );

        // TODO: to improve, there are diminishing returns in computing the longest atoms.
        test(
            "{ 11 22 33 44 55 66 77 ( 88 | 99 | AA | BB ) }",
            &[
                b"\x11\x22\x33\x44\x55\x66\x77\x88",
                b"\x11\x22\x33\x44\x55\x66\x77\x99",
                b"\x11\x22\x33\x44\x55\x66\x77\xAA",
                b"\x11\x22\x33\x44\x55\x66\x77\xBB",
            ],
            r#"\x11"3DUfw\x88$|\x11"3DUfw\x99$|\x11"3DUfw\xaa$|\x11"3DUfw\xbb$"#,
            r#"^\x11"3DUfw\x88|^\x11"3DUfw\x99|^\x11"3DUfw\xaa|^\x11"3DUfw\xbb"#,
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
            r"^\x00default\x2eproperties",
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
            &[b"\x02\xAA\x02\xC1\x0F\x85", b"\x02\xAA\x02\xC1\x75"],
            "(\\x0f\\x82..\\x00\\x00|r.)(\\x80|A\\x80)([p-\\x7f]|\\x7c\\x24)\\x04\\x02\
             (\\x0f\\x85..\\x00\\x00|u.)(\\x81|A\\x81)([0-\\x3f]|<\\x24|\\x7d\\x00)\
             \\x02\\xaa\\x02\\xc1\\x0f\\x85$|(\\x0f\\x82..\\x00\\x00|r.)(\\x80|A\\x80)\
             ([p-\\x7f]|\\x7c\\x24)\\x04\\x02(\\x0f\\x85..\\x00\\x00|u.)(\\x81|A\\x81)\
             ([0-\\x3f]|<\\x24|\\x7d\\x00)\\x02\\xaa\\x02\\xc1u$",
            "^\\x02\\xaa\\x02\\xc1\\x0f\\x85(\\x0f\\x85..\\x00\\x00|u.)(\\x8b|A\\x8b|\
             D\\x8b|E\\x8b)([@-O]|[P-_]|[`-o]|[p-\\x7f]|[\\x04\\x14\\x244DTdt\\x84\\x94\
             \\xa4\\xb4\\xc4\\xd4\\xe4\\xf4]\\x24|[\\x0c\\x1c,<L\\x5cl\\x7c\\x8c\\x9c\\xac\
             \\xbc\\xcc\\xdc\\xec\\xfc]\\x24)\\x06|^\\x02\\xaa\\x02\\xc1u(\\x0f\\x85..\\x00\
             \\x00|u.)(\\x8b|A\\x8b|D\\x8b|E\\x8b)([@-O]|[P-_]|[`-o]|[p-\\x7f]|[\\x04\\x14\\x24\
             4DTdt\\x84\\x94\\xa4\\xb4\\xc4\\xd4\\xe4\\xf4]\\x24|[\\x0c\\x1c,<L\\x5cl\\x7c\\x8c\
             \\x9c\\xac\\xbc\\xcc\\xdc\\xec\\xfc]\\x24)\\x06",
        );

        // TODO: expanding the masked byte would improve the atoms
        test(
            "{ 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }",
            &[b"\xF6"],
            r"\x8b[\xc0-\xcf].{2,3}?\xf6$",
            r"^\xf6[\xd0-\xdf]\x1a[\xc0-\xcf].{2,3}?.{2,3}?0[\x00-\x0f].[@-O]",
        );
        test(
            "{ C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }",
            &[b"\xE9"],
            r"\xc6[\x00-\x0f]\xe9$",
            r"^\xe9[@-O][\x80-\x8f][@-O]\x05.{2,2}?\x89[@-O]\x01",
        );
    }
}
