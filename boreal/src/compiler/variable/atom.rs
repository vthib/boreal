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
    let mut visitor = AtomVisitor::new();
    visitor.visit(node);
    visitor.into_set().into_atomized_expression(node)
}

/// Visitor on a regex AST to extract atoms.
#[derive(Debug)]
struct AtomVisitor {
    set: AtomSet,

    atoms: Vec<Vec<u8>>,
    atoms_start_position: usize,

    current_position: usize,
}

impl AtomVisitor {
    fn new() -> Self {
        Self {
            set: AtomSet::default(),
            atoms: Vec::new(),
            atoms_start_position: 0,

            current_position: 0,
        }
    }
}

impl AtomVisitor {
    fn visit(&mut self, node: &Node) {
        // TODO for repetitions and alternation
        match node {
            Node::Literal(b) => self.add_byte(*b),
            Node::Group(node) => self.visit(node),
            Node::Repetition { .. }
            | Node::Dot
            | Node::Class(_)
            | Node::Empty
            | Node::Assertion(_) => self.close(),
            Node::Concat(nodes) => {
                for node in nodes {
                    self.visit(node);
                }
            }
            Node::Alternation(alts) => {
                if !self.visit_alternation(alts) {
                    self.close();
                }
            }
        }

        self.current_position += 1;
    }

    fn add_byte(&mut self, byte: u8) {
        if self.atoms.is_empty() {
            self.atoms.push(Vec::new());
            self.atoms_start_position = self.current_position;
        }
        for atom in &mut self.atoms {
            atom.push(byte);
        }
    }

    fn visit_alternation(&mut self, alts: &[Node]) -> bool {
        // Only allow alternations if each one is a literal or a concat of literals.
        // This can be revised in the future.
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

        if self
            .atoms
            .len()
            .checked_mul(lits.len())
            .map_or(true, |v| v > 32)
        {
            return false;
        }

        if self.atoms.is_empty() {
            self.atoms = lits;
        } else {
            self.atoms = self
                .atoms
                .iter()
                .flat_map(|prefix| {
                    lits.iter()
                        .map(|lit| prefix.iter().copied().chain(lit.iter().copied()).collect())
                })
                .collect();
        }
        true
    }

    fn close(&mut self) {
        self.set.add_atoms(
            std::mem::take(&mut self.atoms),
            self.atoms_start_position,
            self.current_position,
        );
    }

    fn into_set(mut self) -> AtomSet {
        self.close();
        self.set
    }
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
    atoms: Vec<Vec<u8>>,
    start_position: usize,
    end_position: usize,
    rank: u32,
}

impl AtomSet {
    fn add_atoms(&mut self, atoms: Vec<Vec<u8>>, start_position: usize, end_position: usize) {
        let rank = atoms_rank(&atoms);
        // this.atoms is one possible set, and the provided atoms are another one.
        // Keep the one with the best rank.
        if self.atoms.is_empty() || rank > self.rank {
            self.atoms = atoms;
            self.start_position = start_position;
            self.end_position = end_position;
            self.rank = rank;
        }
    }

    pub fn into_atomized_expression(self, original_node: &Node) -> Option<AtomizedExpressions> {
        if self.atoms.is_empty() {
            None
        } else {
            let mut pre = String::new();
            let mut post = String::new();
            add_ast_to_string(&self.build_pre_ast(original_node), &mut pre);
            add_ast_to_string(&self.build_post_ast(original_node), &mut post);

            Some(AtomizedExpressions {
                literals: self.atoms,
                pre,
                post,
            })
        }
    }

    fn add_literals_ast(&self, nodes: &mut Vec<Node>) {
        match &self.atoms[..] {
            [] => (),
            [atom] => {
                nodes.extend(atom.iter().copied().map(Node::Literal));
            }
            atoms => {
                nodes.push(Node::Group(Box::new(Node::Alternation(
                    atoms
                        .iter()
                        .map(|atom| Node::Concat(atom.iter().copied().map(Node::Literal).collect()))
                        .collect(),
                ))));
            }
        }
    }

    fn build_pre_ast(&self, original_node: &Node) -> Node {
        let mut nodes = Vec::new();

        add_ast_up_to(original_node, self.start_position, &mut nodes);
        self.add_literals_ast(&mut nodes);
        nodes.push(Node::Assertion(AssertionKind::EndLine));

        Node::Concat(nodes)
    }

    fn build_post_ast(&self, original_node: &Node) -> Node {
        let mut nodes = Vec::new();

        nodes.push(Node::Assertion(AssertionKind::StartLine));
        self.add_literals_ast(&mut nodes);
        add_ast_from(original_node, self.end_position, &mut nodes);

        Node::Concat(nodes)
    }
}

/// Retrieve the rank of a set of atoms.
fn atoms_rank(atoms: &[Vec<u8>]) -> u32 {
    // Get the min rank. This is probably the best solution, it isn't clear if a better one
    // is easy to find.
    atoms
        .iter()
        .map(|atom| literals_rank(atom))
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

fn add_ast_up_to(node: &Node, position: usize, out: &mut Vec<Node>) {
    let mut pos = 0;
    let _ = add_ast_up_to_inner(node, position, &mut pos, out);
}

fn add_ast_up_to_inner(
    node: &Node,
    position: usize,
    cur_pos: &mut usize,
    out: &mut Vec<Node>,
) -> bool {
    if *cur_pos >= position {
        return false;
    }

    match node {
        Node::Literal(_)
        | Node::Repetition { .. }
        | Node::Dot
        | Node::Class(_)
        | Node::Empty
        | Node::Assertion(_)
        | Node::Alternation(_) => out.push(node.clone()),
        Node::Group(subnode) => {
            let mut new_nodes = Vec::with_capacity(1);
            if add_ast_up_to_inner(subnode, position, cur_pos, &mut new_nodes) {
                debug_assert!(new_nodes.len() == 1);
                if let Some(node) = new_nodes.pop() {
                    out.push(Node::Group(Box::new(node)));
                }
            } else {
                return false;
            }
        }

        Node::Concat(nodes) => {
            let mut new_nodes = Vec::with_capacity(nodes.len());

            for node in nodes {
                if !add_ast_up_to_inner(node, position, cur_pos, &mut new_nodes) {
                    break;
                }
            }
            if !new_nodes.is_empty() {
                out.push(Node::Concat(new_nodes));
            }
        }
    }

    *cur_pos += 1;
    true
}

fn add_ast_from(node: &Node, position: usize, out: &mut Vec<Node>) {
    let mut pos = 0;
    add_ast_from_inner(node, position, &mut pos, out);
}

fn add_ast_from_inner(node: &Node, position: usize, cur_pos: &mut usize, out: &mut Vec<Node>) {
    match node {
        Node::Literal(_)
        | Node::Repetition { .. }
        | Node::Dot
        | Node::Class(_)
        | Node::Empty
        | Node::Assertion(_)
        | Node::Alternation(_) => {
            if *cur_pos >= position {
                out.push(node.clone());
            }
        }
        Node::Group(subnode) => {
            let mut new_nodes = Vec::with_capacity(1);
            add_ast_from_inner(subnode, position, cur_pos, &mut new_nodes);
            if let Some(node) = new_nodes.pop() {
                out.push(Node::Group(Box::new(node)));
            }
        }

        Node::Concat(nodes) => {
            let mut new_nodes = Vec::with_capacity(nodes.len());

            for node in nodes {
                add_ast_from_inner(node, position, cur_pos, &mut new_nodes);
            }
            if !new_nodes.is_empty() {
                out.push(Node::Concat(new_nodes));
            }
        }
    }

    *cur_pos += 1;
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
            r"(\xaa|\xbb)$",
            r"^(\xaa|\xbb)[\xf0-\xff]",
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
            "(\\xab\\x01g\\xcd|\\xab\\x01\\x89\\xcd|\\xab\\x01\\xf0\\xcd|\\xab\\x23Eg\\xcd|\
              \\xab\\x23E\\x89\\xcd|\\xab\\x23E\\xf0\\xcd)$",
            "^(\\xab\\x01g\\xcd|\\xab\\x01\\x89\\xcd|\\xab\\x01\\xf0\\xcd|\\xab\\x23Eg\\xcd|\
               \\xab\\x23E\\x89\\xcd|\\xab\\x23E\\xf0\\xcd)",
        );

        // Do not handle alternations that contains anything other than literals
        test(
            "{ AB ( ?? | FF ) CC }",
            &[b"\xAB"],
            r"\xab$",
            r"^\xab(.|\xff)\xcc",
        );
        test(
            "{ AB ( ?? DD | FF ) CC }",
            &[b"\xAB"],
            r"\xab$",
            r"^\xab(.\xdd|\xff)\xcc",
        );
        test(
            "{ AB ( 11 ?? DD | FF ) CC }",
            &[b"\xAB"],
            r"\xab$",
            r"^\xab(\x11.\xdd|\xff)\xcc",
        );
        test(
            "{ AB ( 11 ?? | FF ) CC }",
            &[b"\xAB"],
            r"\xab$",
            r"^\xab(\x11.|\xff)\xcc",
        );
        test(
            "{ ( 11 ?? | FF ) CC }",
            &[b"\xCC"],
            r"(\x11.|\xff)\xcc$",
            r"^\xcc",
        );
        test(
            "{ AB ( 11 | 12 ) 13 ( 1? | 14 ) }",
            &[b"\xAB\x11\x13", b"\xAB\x12\x13"],
            r"(\xab\x11\x13|\xab\x12\x13)$",
            r"^(\xab\x11\x13|\xab\x12\x13)([\x10-\x1f]|\x14)",
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
            "(\\x11!1AQ|\\x11!1AR|\\x11!1BQ|\\x11!1BR|\\x11!2AQ|\\x11!2AR|\\x11!2BQ|\\x11!2BR|\
              \\x11\"1AQ|\\x11\"1AR|\\x11\"1BQ|\\x11\"1BR|\\x11\"2AQ|\\x11\"2AR|\\x11\"2BQ|\
              \\x11\"2BR|\\x12!1AQ|\\x12!1AR|\\x12!1BQ|\\x12!1BR|\\x12!2AQ|\\x12!2AR|\\x12!2BQ|\
              \\x12!2BR|\\x12\"1AQ|\\x12\"1AR|\\x12\"1BQ|\\x12\"1BR|\\x12\"2AQ|\\x12\"2AR|\
              \\x12\"2BQ|\\x12\"2BR)$",
            "^(\\x11!1AQ|\\x11!1AR|\\x11!1BQ|\\x11!1BR|\\x11!2AQ|\\x11!2AR|\\x11!2BQ|\\x11!2BR|\
               \\x11\"1AQ|\\x11\"1AR|\\x11\"1BQ|\\x11\"1BR|\\x11\"2AQ|\\x11\"2AR|\\x11\"2BQ|\
               \\x11\"2BR|\\x12!1AQ|\\x12!1AR|\\x12!1BQ|\\x12!1BR|\\x12!2AQ|\\x12!2AR|\\x12!2BQ|\
               \\x12!2BR|\\x12\"1AQ|\\x12\"1AR|\\x12\"1BQ|\\x12\"1BR|\\x12\"2AQ|\\x12\"2AR|\
               \\x12\"2BQ|\\x12\"2BR)(a|b)(q|r)\\x88",
        );
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) 33 ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10  ) }",
            &[
                b"\x11\x21\x33",
                b"\x11\x22\x33",
                b"\x12\x21\x33",
                b"\x12\x22\x33",
            ],
            r#"(\x11!3|\x11"3|\x12!3|\x12"3)$"#,
            r#"^(\x11!3|\x11"3|\x12!3|\x12"3)(\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x10)"#,
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
            r#"(\x11"3DUfw\x88|\x11"3DUfw\x99|\x11"3DUfw\xaa|\x11"3DUfw\xbb)$"#,
            r#"^(\x11"3DUfw\x88|\x11"3DUfw\x99|\x11"3DUfw\xaa|\x11"3DUfw\xbb)"#,
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
            &[b"\x02\xAA\x02\xC1"],
            "(\\x0f\\x82..\\x00\\x00|r.)(\\x80|A\\x80)([p-\\x7f]|\\x7c\\x24)\\x04\\x02\
             (\\x0f\\x85..\\x00\\x00|u.)(\\x81|A\\x81)([0-\\x3f]|<\\x24|\\x7d\\x00)\
             \\x02\\xaa\\x02\\xc1$",
            "^\\x02\\xaa\\x02\\xc1(\\x0f\\x85..\\x00\\x00|u.)(\\x8b|A\\x8b|D\\x8b|E\\x8b)\
             ([@-O]|[P-_]|[`-o]|[p-\\x7f]|[\\x04\\x14\\x244DTdt\\x84\\x94\\xa4\\xb4\\xc4\\xd4\
             \\xe4\\xf4]\\x24|[\\x0c\\x1c,<L\\x5cl\\x7c\\x8c\\x9c\\xac\\xbc\\xcc\\xdc\\xec\\xfc]\
             \\x24)\\x06",
        );

        // TODO: expanding the masked byte would improve the atoms
        test(
            "{ 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }",
            &[b"\x8B"],
            r"\x8b$",
            r"^\x8b[\xc0-\xcf].{2,3}?\xf6[\xd0-\xdf]\x1a[\xc0-\xcf].{2,3}?.{2,3}?0[\x00-\x0f].[@-O]",
        );
        test(
            "{ C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }",
            &[b"\xC6"],
            r"\xc6$",
            r"^\xc6[\x00-\x0f]\xe9[@-O][\x80-\x8f][@-O]\x05.{2,2}?\x89[@-O]\x01",
        );
    }
}
