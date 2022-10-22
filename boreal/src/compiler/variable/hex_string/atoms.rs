use boreal_parser::regex::Node;

use crate::compiler::variable::atom::{Atom, AtomSet};

pub fn extract_atoms(node: &Node) -> AtomSet {
    HexAtoms::from_regex_node(node).into_set()
}

#[derive(Debug, Default)]
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

    fn from_regex_node(node: &Node) -> Self {
        let mut this = Self::new();
        this.add_node(node);
        this
    }

    fn add_node(&mut self, node: &Node) {
        match node {
            Node::Literal(b) => self.add_byte(*b),
            Node::Repetition { .. } | Node::Dot | Node::Class(_) => self.rotate(),
            Node::Empty => (),
            Node::Assertion(_) => self.clear(),
            Node::Group(node) => self.add_node(node),
            Node::Concat(nodes) => {
                for node in nodes {
                    self.add_node(node);
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
            atoms.push(Vec::new());
        }
        for atom in atoms {
            atom.push(byte);
        }
    }

    fn clear(&mut self) {
        if self.contiguous {
            self.left.clear();
        } else {
            self.right.clear();
        }
    }

    fn rotate(&mut self) {
        if self.contiguous {
            self.contiguous = false;
        } else if !self.right.is_empty() {
            self.set.add_atoms(std::mem::take(&mut self.right));
        }
    }

    // Merge another possible HexAtoms with the current one (as an alternation).
    fn concat(&mut self, other: Self) {
        self.set.add_set(other.set);
        self.cartesian_product(other.left);
        if !other.contiguous {
            self.rotate();
            self.right = other.right;
        }
        self.contiguous = self.contiguous && other.contiguous;
    }

    fn add_alternatives(&mut self, alts: &[Node]) {
        // Then, do the cross product between our prefixes literals and the alternatives
        if let Some(suffixes) = alts
            .iter()
            .map(HexAtoms::from_regex_node)
            .reduce(HexAtoms::reduce_alternate)
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

    fn cartesian_product(&mut self, suffixes: Vec<Vec<u8>>) {
        // Suffixes are non expressable with atoms, so we have to rotate.
        if suffixes.is_empty() {
            self.rotate();
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
            self.rotate();
            self.right = suffixes;
            return;
        }

        *prefixes = prefixes
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
#[cfg(test)]
mod tests {
    use super::super::tests::parse_hex_string;
    use super::*;

    #[test]
    fn test_extract_atoms() {
        #[track_caller]
        fn test(hex_string: &str, expected_atoms: &[&[u8]]) {
            let hex_string = parse_hex_string(hex_string);
            let ast = super::super::hex_string_to_ast(hex_string);

            let atoms = extract_atoms(&ast);
            assert_eq!(atoms.get_literals(), expected_atoms);
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
            &[b"\x00\x02\x00\x01\x00\x02"]);

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
            &[b"\x00\x83\xC5\x04\x8B"]);
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
