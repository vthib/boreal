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
use boreal_parser::regex::{AssertionKind, Node};

use crate::regex::add_ast_to_string;

// FIXME: add lots of tests here...

pub fn extract_atoms(node: &Node) -> AtomSet {
    let mut position = AstPosition(Vec::new());
    let mut hex_atoms = HexAtoms::new();
    hex_atoms.add_node(node, &mut position);
    hex_atoms.into_set()
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

    pub fn into_literals(self) -> Vec<Vec<u8>> {
        self.literals
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

    pub fn build_regexes(&self, original_node: &Node) -> (String, String) {
        let mut pre = String::new();
        pre.push_str("(?s)");
        add_ast_to_string(&self.build_pre_ast(original_node), &mut pre);

        let mut post = String::new();
        post.push_str("(?s)");
        add_ast_to_string(&self.build_post_ast(original_node), &mut post);

        (pre, post)
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
struct HexAtoms {
    set: AtomSet,

    left: Vec<Atom>,
    right: Vec<Atom>,

    contiguous: bool,
}

impl HexAtoms {
    fn new() -> Self {
        Self {
            set: AtomSet::default(),
            left: Vec::new(),
            right: Vec::new(),
            contiguous: true,
        }
    }

    fn add_node(&mut self, node: &Node, position: &mut AstPosition) {
        match node {
            Node::Literal(b) => self.add_byte(*b, position),
            Node::Repetition { .. } | Node::Dot | Node::Class(_) => self.close(position),
            Node::Empty => (),
            Node::Assertion(_) => self.clear(),
            Node::Group(node) => {
                position.0.push(0);
                self.add_node(node, position);
                let _ = position.0.pop();
            }
            Node::Concat(nodes) => {
                for (i, node) in nodes.iter().enumerate() {
                    position.0.push(i);
                    self.add_node(node, position);
                    let _ = position.0.pop();
                }
            }
            Node::Alternation(nodes) => self.add_alternatives(nodes, position),
        }
    }

    fn add_byte(&mut self, byte: u8, position: &AstPosition) {
        let atoms = if self.contiguous {
            &mut self.left
        } else {
            &mut self.right
        };
        if atoms.is_empty() {
            atoms.push(Atom::new(position));
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

    fn close(&mut self, position: &AstPosition) {
        if self.contiguous {
            for atom in &mut self.left {
                atom.close(position);
            }
            self.contiguous = false;
        } else if !self.right.is_empty() {
            for atom in &mut self.right {
                atom.close(position);
            }
            self.set.add_atoms(std::mem::take(&mut self.right));
        }
    }

    // Merge another possible HexAtoms with the current one (as an alternation).
    fn concat(&mut self, other: Self, position: &AstPosition) {
        self.set.add_set(other.set);
        self.cartesian_product(other.left, position);
        if !other.contiguous {
            self.close(position);
            self.right = other.right;
        }
        self.contiguous = self.contiguous && other.contiguous;
    }

    fn add_alternatives(&mut self, alts: &[Node], position: &mut AstPosition) {
        // Then, do the cross product between our prefixes literals and the alternatives
        if let Some(suffixes) = alts
            .iter()
            .enumerate()
            .map(|(i, node)| {
                position.0.push(i);
                let mut hex_atoms = HexAtoms::new();
                hex_atoms.add_node(node, position);
                let _ = position.0.pop();
                hex_atoms
            })
            .reduce(HexAtoms::reduce_alternate)
        {
            self.concat(suffixes, position);
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

    fn cartesian_product(&mut self, suffixes: Vec<Atom>, position: &AstPosition) {
        // Suffixes are non expressable with atoms, so we have to close the current ones.
        if suffixes.is_empty() {
            self.close(position);
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
            self.close(position);
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
    fn test_hex_string_extract_atoms() {
        #[track_caller]
        fn test(hex_string_expr: &str, expected_atoms: &[&[u8]]) {
            let hex_string = parse_hex_string(hex_string_expr);
            let ast = super::super::hex_string::hex_string_to_ast(hex_string);

            let atoms = extract_atoms(&ast);
            assert_eq!(atoms.into_literals(), expected_atoms);
        }

        test("{ AB CD 01 }", &[b"\xab\xcd\x01"]);
        test("{ AB ?D 01 }", &[b"\xab"]);
        test("{ D? FE }", &[b"\xFE"]);
        test("{ ( AA | BB ) F? }", &[b"\xAA", b"\xBB"]);
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
        );

        // jump or masked bytes should invalidate alternations if one branch does not have a single
        test("{ AB ( ?? | FF ) CC }", &[b"\xAB"]);
        test("{ AB ( ?? DD | FF ) CC }", &[b"\xDD\xCC", b"\xFF\xCC"]);
        test("{ AB ( 11 ?? DD | FF ) CC }", &[b"\xAB\x11", b"\xAB\xFF"]);
        test("{ AB ( 11 ?? | FF ) CC }", &[b"\xAB\x11", b"\xAB\xFF"]);
        // TODO: generating just CC would be better
        test("{ ( 11 ?? | FF ) CC }", &[b"\x11", b"\xFF"]);
        test(
            "{ AB ( 11 | 22 ) 33 ( ?1 | 44 ) }",
            &[b"\xAB\x11\x33", b"\xAB\x22\x33"],
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
        );
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) 33 ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10  ) }",
            &[
                b"\x11\x21\x33",
                b"\x11\x22\x33",
                b"\x12\x21\x33",
                b"\x12\x22\x33",
            ],
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
        );

        test("{ 11 ?A 22 33 [1] 44 55 66 A? 77 88 }", &[b"\x44\x55\x66"]);

        // hex strings found in some real rules
        test(
            "{ 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? 00 04 00 02 00 04 ?? ?? }",
            &[b"\x00\x03\x00\x02\x00\x04"]);

        test(
            "{ c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }",
            &[b"\x00\x00\x01\x00"],
        );
        test(
            "{ 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 }",
            &[b"\x00\x64\x65\x66\x61\x75\x6C\x74\x2E\x70\x72\x6F\x70\x65\x72\x74\x69\x65\x73"],
        );
        test(
"{ FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? \
83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }",
            &[b"\x83\xC5\x04\x55\x8B"]);
        test(
            "{ ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) \
04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) \
02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) \
( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }",
            &[b"\x02\xAA\x02\xC1\x0F\x85", b"\x02\xAA\x02\xC1\x75"],
        );

        // TODO: expanding the masked byte would improve the atoms
        test(
            "{ 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }",
            &[b"\xF6"],
        );
        test("{ C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }", &[b"\xE9"]);
    }
}
