//! Literal extraction and computation from variable expressions.
use boreal_parser::regex::{AssertionKind, Node};

use crate::atoms::atom_rank;
use crate::regex::{visit, VisitAction, Visitor};

pub fn get_literals_details(node: &Node) -> LiteralsDetails {
    let visitor = LiteralsExtractor::new();
    let visitor = visit(node, visitor);
    visitor.into_literals_details(node)
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

/// Visitor on a regex AST to extract literals.
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
struct LiteralsExtractor {
    /// Set of best literals extracted so far.
    set: LiteralSet,

    /// Literals currently being built.
    literals: Vec<Vec<u8>>,
    /// Starting position of the currently built literals.
    literals_start_position: usize,

    /// Current position of the visitor.
    ///
    /// This position is a simple counter of visited nodes.
    current_position: usize,
}

impl LiteralsExtractor {
    fn new() -> Self {
        Self {
            set: LiteralSet::default(),
            literals: Vec::new(),
            literals_start_position: 0,

            current_position: 0,
        }
    }
}

impl Visitor for LiteralsExtractor {
    type Output = Self;

    fn visit_pre(&mut self, node: &Node) -> VisitAction {
        match node {
            Node::Literal(b) => {
                self.add_byte(*b);
                VisitAction::Skip
            }
            Node::Empty => VisitAction::Skip,
            Node::Dot | Node::Class(_) | Node::Assertion(_) | Node::Repetition { .. } => {
                self.close();
                VisitAction::Skip
            }
            Node::Alternation(alts) => {
                if !self.visit_alternation(alts) {
                    self.close();
                }
                VisitAction::Skip
            }
            Node::Group(_) | Node::Concat(_) => VisitAction::Continue,
        }
    }

    fn visit_post(&mut self, _node: &Node) {
        self.current_position += 1;
    }

    fn finish(self) -> Self {
        self
    }
}

impl LiteralsExtractor {
    /// Add a byte to the literals being built.
    fn add_byte(&mut self, byte: u8) {
        if self.literals.is_empty() {
            self.literals.push(Vec::new());
            self.literals_start_position = self.current_position;
        }

        for lit in &mut self.literals {
            lit.push(byte);
        }
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

        // Limit the amount of literals being built to avoid exponential buildup.
        if self
            .literals
            .len()
            .checked_mul(lits.len())
            .map_or(true, |v| v > 32)
        {
            return false;
        }

        if self.literals.is_empty() {
            self.literals = lits;
            self.literals_start_position = self.current_position;
        } else {
            // Compute the cardinal product between the prefixes and the literals of the
            // alternation.
            self.literals = self
                .literals
                .iter()
                .flat_map(|prefix| {
                    lits.iter()
                        .map(|lit| prefix.iter().copied().chain(lit.iter().copied()).collect())
                })
                .collect();
        }
        true
    }

    /// Close currently being built literals.
    fn close(&mut self) {
        if !self.literals.is_empty() {
            self.set.add_literals(
                std::mem::take(&mut self.literals),
                self.literals_start_position,
                self.current_position,
            );
        }
    }

    pub fn into_literals_details(mut self, original_node: &Node) -> LiteralsDetails {
        self.close();

        let (pre_ast, post_ast) = self.set.build_pre_post_ast(original_node);

        LiteralsDetails {
            literals: self.set.literals,
            pre_ast,
            post_ast,
        }
    }
}

/// Set of literals extracted from a regex AST.
#[derive(Debug, Default)]
struct LiteralSet {
    /// List of literals extracted.
    literals: Vec<Vec<u8>>,

    /// Starting position of the literals (including the first bytes of the literals).
    start_position: usize,
    /// Ending position of the literals (excluding the last bytes of the literals).
    end_position: usize,

    /// Rank of the saved literals.
    rank: u32,
}

impl LiteralSet {
    fn add_literals(&mut self, literals: Vec<Vec<u8>>, start_position: usize, end_position: usize) {
        // Get the min rank. This is probably the best solution, it isn't clear if a better one
        // is easy to find.
        let rank = literals
            .iter()
            .map(|lit| atom_rank(lit))
            .min()
            .unwrap_or(0);

        // this.literals is one possible set, and the provided literals are another one.
        // Keep the one with the best rank.
        if self.literals.is_empty() || rank > self.rank {
            self.literals = literals;
            self.start_position = start_position;
            self.end_position = end_position;
            self.rank = rank;
        }
    }

    fn add_literals_ast(&self, nodes: &mut Vec<Node>) {
        match &self.literals[..] {
            [] => (),
            [literal] => {
                nodes.extend(literal.iter().copied().map(Node::Literal));
            }
            literals => {
                nodes.push(Node::Group(Box::new(Node::Alternation(
                    literals
                        .iter()
                        .map(|literal| Node::Concat(literal.iter().copied().map(Node::Literal).collect()))
                        .collect(),
                ))));
            }
        }
    }

    fn build_pre_post_ast(&self, original_node: &Node) -> (Option<Node>, Option<Node>) {
        if self.literals.is_empty() {
            return (None, None);
        }

        let visitor = PrePostExtractor::new(self.start_position, self.end_position);
        let (pre_node, post_node) = visit(original_node, visitor);

        let pre_node = pre_node.map(|pre| {
            let mut pre_nodes = Vec::new();
            pre_nodes.push(pre);
            self.add_literals_ast(&mut pre_nodes);
            pre_nodes.push(Node::Assertion(AssertionKind::EndLine));
            Node::Concat(pre_nodes)
        });
        let post_node = post_node.map(|post| {
            let mut post_nodes = Vec::new();
            post_nodes.push(Node::Assertion(AssertionKind::StartLine));
            self.add_literals_ast(&mut post_nodes);
            post_nodes.push(post);
            Node::Concat(post_nodes)
        });

        (pre_node, post_node)
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

    /// Current position during the visit of the original AST.
    current_position: usize,
}

impl PrePostExtractor {
    fn new(start_position: usize, end_position: usize) -> Self {
        Self {
            pre_stack: Vec::new(),
            post_stack: Vec::new(),

            pre_node: None,
            post_node: None,

            current_position: 0,
            start_position,
            end_position,
        }
    }

    fn push_stack(&mut self) {
        self.pre_stack.push(Vec::new());
        self.post_stack.push(Vec::new());
    }

    fn add_pre_post_node(&mut self, node: &Node) {
        if self.current_position < self.start_position {
            self.add_node(node.clone(), false);
        } else if self.current_position >= self.end_position {
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

impl Visitor for PrePostExtractor {
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
            | Node::Alternation(_) => (),
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

        self.current_position += 1;
    }

    fn finish(self) -> Self::Output {
        (self.pre_node, self.post_node)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        regex::regex_ast_to_string,
        test_helpers::{parse_hex_string, parse_regex_string, test_type_traits_non_clonable},
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
            &[b"\xab"],
            "",
            r"^\xab[\x0d\x1d\x2d=M\x5dm\x7d\x8d\x9d\xad\xbd\xcd\xdd\xed\xfd]\x01",
        );

        test("{ D? FE }", &[b"\xfe"], r"[\xd0-\xdf]\xfe$", "");

        test(
            "{ ( AA | BB ) F? }",
            &[b"\xAA", b"\xBB"],
            "",
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
            "",
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
            "",
            r#"^(\x11!3|\x11"3|\x12!3|\x12"3)(\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x10)"#,
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

        // TODO: expanding the masked byte would improve the literals
        test(
            "{ 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }",
            &[b"\x8B"],
            "",
            r"^\x8b[\xc0-\xcf].{2,3}?\xf6[\xd0-\xdf]\x1a[\xc0-\xcf].{2,3}?.{2,3}?0[\x00-\x0f].[@-O]",
        );
        test(
            "{ C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }",
            &[b"\xC6"],
            "",
            r"^\xc6[\x00-\x0f]\xe9[@-O][\x80-\x8f][@-O]\x05.{2,2}?\x89[@-O]\x01",
        );

        test(
            "{ 61 ?? ( 62 63 | 64) 65 }",
            &[b"\x62\x63\x65", b"\x64\x65"],
            r"a.(bce|de)$",
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
        test("ab(ca+)b", &[b"abc"], "", "^abc(a+)b");
        // Literal spanning up to the end of a group
        test("ab(c)a+b", &[b"abc"], "", "^abca+b");
        // Literal spanning in and out of a group
        test("a(b)ca+b", &[b"abc"], "", "^abca+b");

        // Literal on the right side of a group
        test("b(a+)abc", &[b"abc"], "b(a+)abc$", "");
        // Literal spanning inside a group
        test("b(a+a)bc", &[b"abc"], "b(a+)abc$", "");
        // Literal starting in a group
        test("ba+(ab)c", &[b"abc"], "ba+abc$", "");
        // Literal spanning in and out of a group
        test("ba+a(bc)", &[b"abc"], "ba+abc$", "");

        // A few tests on closing nodes
        test("a.+bcd{2}e", &[b"bc"], "a.+bc$", "^bcd{2}e");
        test("a.+bc.e", &[b"bc"], "a.+bc$", "^bc.e");
        test("a.+bc\\B.e", &[b"bc"], "a.+bc$", "^bc\\B.e");
        test("a.+bc[aA]e", &[b"bc"], "a.+bc$", "^bc[aA]e");
        test("a.+bc()de", &[b"bcde"], "a.+bcde$", "");

        test("a+(b.c)(d)(ef)g+", &[b"cdef"], "a+(b.)cdef$", "^cdefg+");

        test(
            "a((b(c)((d)()(e(g+h)ij)))kl)m",
            &[b"hijklm"],
            "a((b(c)((d)()(e(g+)))))hijklm$",
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

        test_type_traits_non_clonable(LiteralsExtractor::new());
        test_type_traits_non_clonable(LiteralSet::default());
        test_type_traits_non_clonable(PrePostExtractor::new(0, 0));
    }
}
