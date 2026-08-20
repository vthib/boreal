//! Validator able to handle "simple" expressions.
//!
//! This is a hand-rolled validator on a subset of the regex HIR,
//! which for those simpler expressions, allows avoiding building a full
//! DFA matcher. This results in smaller memory usage and faster matching.
use boreal_parser::regex::{RepetitionKind, RepetitionRange};

use crate::matcher::Modifiers;
use crate::matcher::analysis::HirAnalysis;
use crate::regex::Hir;

#[derive(Debug, PartialEq)]
pub(crate) struct SimpleValidator {
    /// List of nodes to match
    nodes: Box<[SimpleNode]>,
}

#[derive(Debug, PartialEq, Eq)]
enum SimpleNode {
    // Byte to match
    Byte(u8),
    // Masked byte
    Mask { value: u8, mask: u8 },
    // Negated Masked byte
    NegatedMask { value: u8, mask: u8 },
    // Jump over a number of bytes
    Jump(u8),
    // Jump over a range of bytes, non-greedy
    JumpRange(u8, u8),
    // Dot, any byte but '\n'
    Dot,
    // Start of an alternation.
    //
    // The value is the total length of the alternation.
    //
    // `[Alternation(N), <N nodes>, ...rest...]`
    //
    // Instead those N nodes, each branch is indicated by an `AltBranch` node.
    Alternation(u16),
    // Start of an alternation branch.
    //
    // The value is the length of the branch.
    //
    // `[AltBranch(N), <N nodes>, ...rest...]`
    AltBranch(u8),
}

impl SimpleValidator {
    pub(crate) fn new(
        hir: &Hir,
        analysis: &HirAnalysis,
        modifiers: Modifiers,
        reverse: bool,
    ) -> Option<Self> {
        if analysis.has_start_or_end_line
            || analysis.has_word_boundaries
            // Classes are not handled because the naive solution would be to use the class bitmap
            // as a new SimpleNode, which would make its size grow to more than 32 bytes, compared
            // to the min 16 bytes currently. This makes performances much worse for use-cases
            // very reliant on simple validators.
            // Some classes could be handled if there is a way to encode how to check them in as
            // few bytes as possible. But for the moment, this isn't really needed.
            || analysis.has_classes
        {
            // TODO: handle fixed size repetitions.
            return None;
        }

        if modifiers.nocase || modifiers.wide {
            // TODO: all those modifiers could be handled.
            return None;
        }

        let mut builder = SimpleValidatorBuilder {
            nodes: Vec::new(),
            dot_all: modifiers.dot_all,
            reverse,
            combinations: 1,
            in_alternation: false,
        };
        if !builder.add_hir(hir) {
            return None;
        }

        Some(Self {
            nodes: builder.nodes.into_boxed_slice(),
        })
    }

    pub(crate) fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let mem = &haystack[start..end];

        let after_match = check_nodes(&self.nodes, mem)?;

        // For example:
        // - mem: "abcdef"
        // - after_match: "ef"
        // Hence index of match end is mem.len() - after_match.len()
        Some(start + mem.len() - after_match.len())
    }

    pub(crate) fn find_anchored_rev(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let mem = &haystack[start..end];

        let before_match = check_nodes_reverse(&self.nodes, mem)?;

        // For example:
        // - mem: "abcdef"
        // - before_match: "ab"
        // Hence index of match start is simply before_match.len()
        Some(start + before_match.len())
    }
}

fn check_nodes<'a>(mut nodes: &[SimpleNode], mut mem: &'a [u8]) -> Option<&'a [u8]> {
    loop {
        let Some(first) = split_off_first(&mut nodes) else {
            return Some(mem);
        };

        match first {
            SimpleNode::Jump(v) => {
                let len = usize::from(*v);

                mem = mem.get(len..)?;
            }
            SimpleNode::Dot => {
                let c = split_off_first(&mut mem)?;
                if *c == b'\n' {
                    return None;
                }
            }
            SimpleNode::Byte(a) => {
                let c = split_off_first(&mut mem)?;
                if *c != *a {
                    return None;
                }
            }
            SimpleNode::Mask { value, mask } => {
                let c = split_off_first(&mut mem)?;
                if (*c & *mask) != *value {
                    return None;
                }
            }
            SimpleNode::NegatedMask { value, mask } => {
                let c = split_off_first(&mut mem)?;
                if (*c & *mask) == *value {
                    return None;
                }
            }
            SimpleNode::JumpRange(min, max) => {
                // Non-greedy repetition: search from min to max
                for jump_length in *min..=*max {
                    let jump_length = usize::from(jump_length);

                    // Can rethrow here: since jump_length increases on
                    // each iteration, all future iterations will also
                    // return None here.
                    let mem2 = mem.get(jump_length..)?;

                    if let Some(res) = check_nodes(nodes, mem2) {
                        return Some(res);
                    }
                }
                return None;
            }
            SimpleNode::Alternation(length) => {
                let nodes_after_alt = &nodes[usize::from(*length)..];

                while let Some(SimpleNode::AltBranch(branch_length)) = split_off_first(&mut nodes) {
                    let branch_length = usize::from(*branch_length);
                    let (branch_nodes, rest_nodes) = nodes.split_at(branch_length);

                    if let Some(rest) = check_nodes(branch_nodes, mem) {
                        // Validate the rest, and try another branch if it
                        // fails. See for example `(a|ab)c`, on input `abc`.
                        if let Some(end) = check_nodes(nodes_after_alt, rest) {
                            return Some(end);
                        }
                    }
                    nodes = rest_nodes;
                }
                return None;
            }
            // Handled in SimpleNode::Alternation, should not appear on its own.
            SimpleNode::AltBranch(_) => return None,
        }
    }
}

fn check_nodes_reverse<'a>(mut nodes: &[SimpleNode], mut mem: &'a [u8]) -> Option<&'a [u8]> {
    loop {
        let Some(first) = split_off_first(&mut nodes) else {
            return Some(mem);
        };

        match first {
            SimpleNode::Jump(v) => {
                let jump_len = usize::from(*v);
                let new_len = mem.len().checked_sub(jump_len)?;

                mem = mem.get(..new_len)?;
            }
            SimpleNode::Dot => {
                let c = split_off_last(&mut mem)?;
                if *c == b'\n' {
                    return None;
                }
            }
            SimpleNode::Byte(a) => {
                let c = split_off_last(&mut mem)?;
                if *c != *a {
                    return None;
                }
            }
            SimpleNode::Mask { value, mask } => {
                let c = split_off_last(&mut mem)?;
                if (*c & *mask) != *value {
                    return None;
                }
            }
            SimpleNode::NegatedMask { value, mask } => {
                let c = split_off_last(&mut mem)?;
                if (*c & *mask) == *value {
                    return None;
                }
            }
            SimpleNode::JumpRange(from, to) => {
                // Reverse search, so look for "smallest" start first,
                // ie biggest reverse jump first, and keep going.
                // This allows finding multiple matches in the right order,
                // and greediness can be handled on how multiple matches are
                // handled.
                for jump_len in (*from..=*to).rev() {
                    let jump_len = usize::from(jump_len);
                    if let Some(new_len) = mem.len().checked_sub(jump_len) {
                        if let Some(res) = check_nodes_reverse(nodes, &mem[..new_len]) {
                            return Some(res);
                        }
                    }
                }
                return None;
            }
            SimpleNode::Alternation(length) => {
                let nodes_after_alt = &nodes[usize::from(*length)..];

                while let Some(SimpleNode::AltBranch(branch_length)) = split_off_first(&mut nodes) {
                    let branch_length = usize::from(*branch_length);
                    let (branch_nodes, rest_nodes) = nodes.split_at(branch_length);

                    if let Some(rest) = check_nodes_reverse(branch_nodes, mem) {
                        if let Some(end) = check_nodes_reverse(nodes_after_alt, rest) {
                            return Some(end);
                        }
                    }
                    nodes = rest_nodes;
                }
                return None;
            }
            // Handled in SimpleNode::Alternation, should not appear on its own.
            SimpleNode::AltBranch(_) => return None,
        }
    }
}

fn split_off_first<'a, T>(slice: &mut &'a [T]) -> Option<&'a T> {
    let (first, rem) = slice.split_first()?;
    *slice = rem;
    Some(first)
}

fn split_off_last<'a, T>(slice: &mut &'a [T]) -> Option<&'a T> {
    let (last, rem) = slice.split_last()?;
    *slice = rem;
    Some(last)
}

struct SimpleValidatorBuilder {
    nodes: Vec<SimpleNode>,
    dot_all: bool,
    reverse: bool,
    combinations: u8,
    in_alternation: bool,
}

impl SimpleValidatorBuilder {
    fn add_hir(&mut self, hir: &Hir) -> bool {
        match hir {
            Hir::Assertion(_) | Hir::Class(_) => false,
            Hir::Mask {
                value,
                mask,
                negated,
            } => {
                self.nodes.push(if *negated {
                    SimpleNode::NegatedMask {
                        value: *value,
                        mask: *mask,
                    }
                } else {
                    SimpleNode::Mask {
                        value: *value,
                        mask: *mask,
                    }
                });
                true
            }
            Hir::Concat(hirs) => {
                if self.reverse {
                    for h in hirs.iter().rev() {
                        if !self.add_hir(h) {
                            return false;
                        }
                    }
                } else {
                    for h in hirs {
                        if !self.add_hir(h) {
                            return false;
                        }
                    }
                }

                true
            }
            Hir::Dot => {
                if self.dot_all {
                    self.add_jump(1);
                } else {
                    self.nodes.push(SimpleNode::Dot);
                }
                true
            }
            Hir::Empty => true,
            Hir::Literal(b) => {
                self.nodes.push(SimpleNode::Byte(*b));
                true
            }
            Hir::Group(hir) => self.add_hir(hir),
            Hir::Repetition { hir, kind, greedy } => {
                // Only handle non-greedy ".{...}" repetitions, with dot_all set. This
                // means the repeated byte can just be ignored, and matches
                // the [X-Y] jumps in hex strings.
                if !matches!(&**hir, Hir::Dot) || !self.dot_all || *greedy {
                    return false;
                }

                match kind {
                    RepetitionKind::ZeroOrOne => {
                        if !self.add_jump_range(0, 1) {
                            return false;
                        }
                    }
                    RepetitionKind::Range(RepetitionRange::Exactly(m)) => {
                        let Ok(m) = u8::try_from(*m) else {
                            return false;
                        };
                        self.add_jump(m);
                    }
                    RepetitionKind::Range(RepetitionRange::Bounded(min, max)) => {
                        let Ok(min) = u8::try_from(*min) else {
                            return false;
                        };
                        let Ok(max) = u8::try_from(*max) else {
                            return false;
                        };

                        if min == max {
                            self.add_jump(min);
                        } else if !self.add_jump_range(min, max) {
                            return false;
                        }
                    }
                    // Unbounded jumps are not handled
                    RepetitionKind::ZeroOrMore
                    | RepetitionKind::OneOrMore
                    | RepetitionKind::Range(RepetitionRange::AtLeast(_)) => return false,
                }
                true
            }
            Hir::Alternation(alts) => {
                // Refuse imbricated alternations
                if self.in_alternation {
                    return false;
                }
                let Ok(nb_alts) = u8::try_from(alts.len()) else {
                    return false;
                };
                if !self.add_combinations(nb_alts) {
                    return false;
                }

                self.in_alternation = true;
                let mut current_stack = std::mem::take(&mut self.nodes);
                let alt_node_index = current_stack.len();
                // Placeholder value 0, will be replaced once
                // all branches are saved.
                current_stack.push(SimpleNode::Alternation(0));

                for alt in alts {
                    if !self.add_hir(alt) {
                        return false;
                    }
                    let branch_nodes = std::mem::take(&mut self.nodes);

                    // Insert the branch nodes in the stack with
                    // an AltBranch node first.
                    let Ok(nb_branch_nodes) = u8::try_from(branch_nodes.len()) else {
                        return false;
                    };
                    current_stack.push(SimpleNode::AltBranch(nb_branch_nodes));
                    current_stack.extend(branch_nodes);
                }

                let Ok(alt_total_length) = u16::try_from(current_stack.len() - alt_node_index - 1)
                else {
                    return false;
                };
                current_stack[alt_node_index] = SimpleNode::Alternation(alt_total_length);
                self.nodes = current_stack;
                self.in_alternation = false;

                true
            }
        }
    }

    fn add_jump(&mut self, jump_length: u8) {
        if self.nodes.is_empty() {
            self.nodes.push(SimpleNode::Jump(jump_length));
        } else {
            let last_index = self.nodes.len() - 1;
            if let SimpleNode::Jump(value) = &mut self.nodes[last_index] {
                match value.checked_add(jump_length) {
                    Some(new_value) => *value = new_value,
                    None => self.nodes.push(SimpleNode::Jump(jump_length)),
                }
            } else {
                self.nodes.push(SimpleNode::Jump(jump_length));
            }
        }
    }

    fn add_combinations(&mut self, nb: u8) -> bool {
        self.combinations = self.combinations.saturating_mul(nb);
        self.combinations <= 64
    }

    fn add_jump_range(&mut self, min: u8, max: u8) -> bool {
        if self.in_alternation {
            // Do not accept jump ranges in alternations. This makes
            // the matching much more difficult.
            //
            // For example, see:
            //
            // { ( AA [0-1] BB | CC ) DD }
            //
            // The input `AA BB BB DD` should match, using the first branch
            // and a jump of 1. However, the jump being non-greedy, the alt
            // branch would actually match with a jum of 0 first, and would
            // fail after validating the next node.
            //
            // Handling this would require backtracking in jump attempts
            // inside the alternation, making this overly complex. So exclude
            // those cases.
            return false;
        }

        // Cap the combinations of jumps. This does not distinguish
        // many small jumps from one bit jump, the goal is simply
        // to have a conservative cap to avoid any complications.
        if !self.add_combinations(max.saturating_sub(min) + 1) {
            return false;
        }

        self.nodes.push(SimpleNode::JumpRange(min, max));
        true
    }
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use super::{SimpleNode, SimpleValidator};

    impl Serialize for SimpleValidator {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.nodes.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for SimpleValidator {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let nodes = <Vec<SimpleNode>>::deserialize_reader(reader)?;

            Ok(Self {
                nodes: nodes.into_boxed_slice(),
            })
        }
    }

    impl Serialize for SimpleNode {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Self::Byte(b) => {
                    0_u8.serialize(writer)?;
                    b.serialize(writer)?;
                }
                Self::Mask { value, mask } => {
                    1_u8.serialize(writer)?;
                    value.serialize(writer)?;
                    mask.serialize(writer)?;
                }
                Self::NegatedMask { value, mask } => {
                    2_u8.serialize(writer)?;
                    value.serialize(writer)?;
                    mask.serialize(writer)?;
                }
                Self::Jump(v) => {
                    3_u8.serialize(writer)?;
                    v.serialize(writer)?;
                }
                Self::Dot => {
                    4_u8.serialize(writer)?;
                }
                Self::JumpRange(m, n) => {
                    5_u8.serialize(writer)?;
                    m.serialize(writer)?;
                    n.serialize(writer)?;
                }
                Self::Alternation(len) => {
                    6_u8.serialize(writer)?;
                    len.serialize(writer)?;
                }
                Self::AltBranch(len) => {
                    7_u8.serialize(writer)?;
                    len.serialize(writer)?;
                }
            }

            Ok(())
        }
    }

    impl Deserialize for SimpleNode {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let discriminant = u8::deserialize_reader(reader)?;
            match discriminant {
                0 => Ok(Self::Byte(u8::deserialize_reader(reader)?)),
                1 => {
                    let value = u8::deserialize_reader(reader)?;
                    let mask = u8::deserialize_reader(reader)?;
                    Ok(Self::Mask { value, mask })
                }
                2 => {
                    let value = u8::deserialize_reader(reader)?;
                    let mask = u8::deserialize_reader(reader)?;
                    Ok(Self::NegatedMask { value, mask })
                }
                3 => Ok(Self::Jump(u8::deserialize_reader(reader)?)),
                4 => Ok(Self::Dot),
                5 => {
                    let m = u8::deserialize_reader(reader)?;
                    let n = u8::deserialize_reader(reader)?;
                    Ok(Self::JumpRange(m, n))
                }
                6 => {
                    let len = u16::deserialize_reader(reader)?;
                    Ok(Self::Alternation(len))
                }
                7 => {
                    let len = u8::deserialize_reader(reader)?;
                    Ok(Self::AltBranch(len))
                }
                v => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid discriminant when deserializing a simple node: {v}"),
                )),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::wire::tests::{test_invalid_deserialization, test_round_trip};

        #[test]
        fn test_wire_simple_validator() {
            test_round_trip(
                &SimpleValidator {
                    nodes: Box::new([SimpleNode::Byte(23), SimpleNode::Dot]),
                },
                &[0, 1, 6],
            );

            test_round_trip(&SimpleNode::Byte(23), &[0, 1]);
            test_round_trip(
                &SimpleNode::Mask {
                    value: 48,
                    mask: 12,
                },
                &[0, 1, 2],
            );
            test_round_trip(
                &SimpleNode::NegatedMask {
                    value: 12,
                    mask: 49,
                },
                &[0, 1, 2],
            );
            test_round_trip(&SimpleNode::Jump(23), &[0, 1]);
            test_round_trip(&SimpleNode::Dot, &[0]);
            test_round_trip(&SimpleNode::JumpRange(12, 23), &[0, 1, 2]);
            test_round_trip(&SimpleNode::Alternation(12), &[0, 1]);
            test_round_trip(&SimpleNode::AltBranch(12), &[0, 1]);

            test_invalid_deserialization::<SimpleNode>(b"\x10");
        }
    }
}

#[cfg(test)]
mod tests {
    use boreal_parser::regex::AssertionKind;

    use super::*;
    use crate::matcher::analysis::analyze_hir;
    use crate::test_helpers::{expr_to_hir, test_type_traits_non_clonable};

    #[test]
    fn test_types_traits() {
        let analysis = analyze_hir(&Hir::Empty, false);
        test_type_traits_non_clonable(
            SimpleValidator::new(
                &Hir::Empty,
                &analysis,
                Modifiers {
                    dot_all: true,
                    ..Default::default()
                },
                false,
            )
            .unwrap(),
        );
        test_type_traits_non_clonable(SimpleNode::Dot);
    }

    fn build_validator(expr: &str, modifiers: Modifiers, reverse: bool) -> Option<SimpleValidator> {
        let hir = expr_to_hir(expr);
        let analysis = analyze_hir(&hir, modifiers.dot_all);
        SimpleValidator::new(&hir, &analysis, modifiers, reverse)
    }

    #[track_caller]
    fn test_build(
        expr: &str,
        modifiers: Modifiers,
        reverse: bool,
        expected_nodes: Option<&[SimpleNode]>,
    ) {
        let v = build_validator(expr, modifiers, reverse);
        assert_eq!(v.as_ref().map(|v| &*v.nodes), expected_nodes);
    }

    #[test]
    fn test_simple_validator_build() {
        // Regex contains nodes that are not handled
        test_build("a?", Modifiers::default(), false, None);
        test_build("^a", Modifiers::default(), false, None);
        test_build("a$", Modifiers::default(), false, None);
        test_build(r"a\b", Modifiers::default(), false, None);
        test_build(r"a\B", Modifiers::default(), false, None);
        test_build(r"[aA]", Modifiers::default(), false, None);

        // Modifiers not handled
        test_build(
            r"a",
            Modifiers {
                nocase: true,
                ..Default::default()
            },
            false,
            None,
        );
        test_build(
            r"a",
            Modifiers {
                wide: true,
                ..Default::default()
            },
            false,
            None,
        );

        test_build(
            "a.()d",
            Modifiers::default(),
            false,
            Some(&[
                SimpleNode::Byte(b'a'),
                SimpleNode::Dot,
                SimpleNode::Byte(b'd'),
            ]),
        );

        test_build(
            "a.()d",
            Modifiers::default(),
            true,
            Some(&[
                SimpleNode::Byte(b'd'),
                SimpleNode::Dot,
                SimpleNode::Byte(b'a'),
            ]),
        );

        test_build(
            "..a.",
            Modifiers {
                dot_all: true,
                ..Default::default()
            },
            false,
            Some(&[
                SimpleNode::Jump(2),
                SimpleNode::Byte(b'a'),
                SimpleNode::Jump(1),
            ]),
        );

        test_build(
            &".".repeat(300),
            Modifiers {
                dot_all: true,
                ..Default::default()
            },
            false,
            Some(&[SimpleNode::Jump(255), SimpleNode::Jump(45)]),
        );
    }

    #[test]
    fn test_jumps() {
        let mods = Modifiers {
            dot_all: true,
            ..Default::default()
        };

        // Greedy so rejected
        test_build(".?", mods, false, None);

        test_build(
            "..??",
            mods,
            false,
            Some(&[SimpleNode::Jump(1), SimpleNode::JumpRange(0, 1)]),
        );
        test_build(
            ".{2}?.{3}?a.{4}?",
            mods,
            false,
            Some(&[
                SimpleNode::Jump(5),
                SimpleNode::Byte(b'a'),
                SimpleNode::Jump(4),
            ]),
        );
        test_build(
            ".{100}?.{100}?.{100}?.{100}?",
            mods,
            false,
            Some(&[SimpleNode::Jump(200), SimpleNode::Jump(200)]),
        );

        test_build(".{300}?", mods, false, None);
        test_build(".{300,400}?", mods, false, None);
        test_build(".{100,400}?", mods, false, None);
        test_build(
            ".{0,7}?.{5,12}?",
            mods,
            false,
            Some(&[SimpleNode::JumpRange(0, 7), SimpleNode::JumpRange(5, 12)]),
        );
        test_build(".{0,7}?.{5,13}?", mods, false, None);
        test_build(
            ".{0,31}?.??",
            mods,
            false,
            Some(&[SimpleNode::JumpRange(0, 31), SimpleNode::JumpRange(0, 1)]),
        );
        test_build(".{0,32}?.??", mods, false, None);

        test_build("a{2}", mods, false, None);
        test_build("a{2}", mods, false, None);
    }

    #[test]
    fn test_alternations() {
        let mods = Modifiers {
            dot_all: true,
            ..Default::default()
        };

        test_build(
            "{ 00 ( AA ?? BB | CC | DD EE ) 11 }",
            mods,
            false,
            Some(&[
                SimpleNode::Byte(b'\x00'),
                SimpleNode::Alternation(9),
                SimpleNode::AltBranch(3),
                SimpleNode::Byte(b'\xAA'),
                SimpleNode::Jump(1),
                SimpleNode::Byte(b'\xBB'),
                SimpleNode::AltBranch(1),
                SimpleNode::Byte(b'\xCC'),
                SimpleNode::AltBranch(2),
                SimpleNode::Byte(b'\xDD'),
                SimpleNode::Byte(b'\xEE'),
                SimpleNode::Byte(b'\x11'),
            ]),
        );

        // Imbricated is rejected
        test_build("(a|b(c|d)e)", mods, false, None);
        test_build("(b(c|d)e|a)", mods, false, None);

        // Too many combinations is rejected
        test_build("(0|1|2|3|4) (0|1|2|3|4) (5|6|7)", mods, false, None);

        // Non fixed jumps is rejected
        test_build("{ ( AA | BB [1-3] CC ) }", mods, false, None);
        test_build("{ ( BB [1-3] CC | AA ) }", mods, false, None);
        test_build("(a|cd??e)", mods, false, None);

        // fixed jump is ok
        test_build(
            "{ ( AA | BB [3-3] CC ) }",
            mods,
            false,
            Some(&[
                SimpleNode::Alternation(6),
                SimpleNode::AltBranch(1),
                SimpleNode::Byte(b'\xAA'),
                SimpleNode::AltBranch(3),
                SimpleNode::Byte(b'\xBB'),
                SimpleNode::Jump(3),
                SimpleNode::Byte(b'\xCC'),
            ]),
        );
    }

    #[test]
    fn test_simple_validator_reject() {
        let mut builder = SimpleValidatorBuilder {
            nodes: Vec::new(),
            dot_all: false,
            reverse: false,
            combinations: 1,
            in_alternation: false,
        };
        assert!(!builder.add_hir(&Hir::Concat(vec![
            Hir::Dot,
            Hir::Assertion(AssertionKind::StartLine)
        ]),));
        assert!(!builder.add_hir(&Hir::Repetition {
            hir: Box::new(Hir::Dot),
            kind: RepetitionKind::Range(RepetitionRange::Bounded(0, 200)),
            greedy: false,
        }));
        assert!(!builder.add_hir(&Hir::Concat(vec![
            Hir::Repetition {
                hir: Box::new(Hir::Dot),
                kind: RepetitionKind::Range(RepetitionRange::Bounded(0, 40)),
                greedy: false,
            },
            Hir::Repetition {
                hir: Box::new(Hir::Dot),
                kind: RepetitionKind::Range(RepetitionRange::Bounded(0, 40)),
                greedy: false,
            }
        ],)));
    }

    #[test]
    fn test_simple_validator() {
        let validator = build_validator(
            "a.c",
            Modifiers {
                dot_all: true,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        let revidator = build_validator(
            "a.c",
            Modifiers {
                dot_all: true,
                ..Default::default()
            },
            true,
        )
        .unwrap();

        // Test the start/end handling
        assert_eq!(validator.find_anchored_fwd(b"abc", 0, 3), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 0, 3), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 0, 2), None);
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 0, 6), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 1, 6), None);
        assert_eq!(validator.find_anchored_fwd(b"cbabcd", 2, 6), Some(5));

        // Test with reverse search as well
        assert_eq!(revidator.find_anchored_rev(b"abc", 0, 3), Some(0));
        assert_eq!(revidator.find_anchored_rev(b"abcdef", 0, 3), Some(0));
        assert_eq!(revidator.find_anchored_rev(b"abcdef", 0, 2), None);
        assert_eq!(revidator.find_anchored_rev(b"defabc", 0, 6), Some(3));
        assert_eq!(revidator.find_anchored_rev(b"defabc", 0, 5), None);
        assert_eq!(revidator.find_anchored_rev(b"cbabcd", 0, 5), Some(2));

        // Test matching of bytes and dot
        assert_eq!(validator.find_anchored_fwd(b"bbc", 0, 3), None);
        assert_eq!(validator.find_anchored_fwd(b"a\nc", 0, 3), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"a\na", 0, 3), None);
        assert_eq!(validator.find_anchored_fwd(b"c\na", 0, 3), None);

        assert_eq!(revidator.find_anchored_rev(b"bbc", 0, 3), None);
        assert_eq!(revidator.find_anchored_rev(b"a\nc", 0, 3), Some(0));
        assert_eq!(revidator.find_anchored_rev(b"a\na", 0, 3), None);
        assert_eq!(revidator.find_anchored_rev(b"c\na", 0, 3), None);
    }

    #[test]
    fn test_simple_validator_masks() {
        let validator = build_validator("{ 5? ~?A }", Modifiers::default(), false).unwrap();
        let revidator = build_validator("{ 5? ~?A }", Modifiers::default(), true).unwrap();

        // Test matching of masks
        assert_eq!(validator.find_anchored_fwd(b"\x50\x0B", 0, 2), Some(2));
        assert_eq!(validator.find_anchored_fwd(b"\x51\x1D", 0, 2), Some(2));
        assert_eq!(validator.find_anchored_fwd(b"\x5F\xFF", 0, 2), Some(2));
        assert_eq!(validator.find_anchored_fwd(b"\x7F\xFF", 0, 2), None);
        assert_eq!(validator.find_anchored_fwd(b"\x5F\xFA", 0, 2), None);

        assert_eq!(revidator.find_anchored_rev(b"\x50\x0B", 0, 2), Some(0));
        assert_eq!(revidator.find_anchored_rev(b"\x51\x1D", 0, 2), Some(0));
        assert_eq!(revidator.find_anchored_rev(b"\x5F\xFF", 0, 2), Some(0));
        assert_eq!(revidator.find_anchored_rev(b"\x7F\xFF", 0, 2), None);
        assert_eq!(revidator.find_anchored_rev(b"\x5F\xFA", 0, 2), None);
    }

    #[test]
    fn test_simple_validator_dot() {
        let v1 = build_validator(".", Modifiers::default(), false).unwrap();
        let v2 = build_validator(
            ".",
            Modifiers {
                dot_all: true,
                ..Default::default()
            },
            false,
        )
        .unwrap();

        assert_eq!(v1.find_anchored_fwd(b"a", 0, 1), Some(1));
        assert_eq!(v2.find_anchored_fwd(b"a", 0, 1), Some(1));
        assert_eq!(v1.find_anchored_fwd(b"\n", 0, 1), None);
        assert_eq!(v2.find_anchored_fwd(b"\n", 0, 1), Some(1));
    }

    #[test]
    fn test_simple_validator_jump_range() {
        let mods = Modifiers {
            dot_all: true,
            ..Default::default()
        };
        let expr = "{ AA [0-2] BB }";
        let v = build_validator(expr, mods, false).unwrap();
        let vrev = build_validator(expr, mods, true).unwrap();

        assert_eq!(v.find_anchored_fwd(b"\xAA", 0, 1), None);
        assert_eq!(v.find_anchored_fwd(b"\xAA\xBB", 0, 1), None);
        assert_eq!(v.find_anchored_fwd(b"\xAA\xBB", 0, 2), Some(2));
        assert_eq!(v.find_anchored_fwd(b"\xAA\xBB\xBB", 0, 3), Some(2));
        assert_eq!(v.find_anchored_fwd(b"\xAA\x00\xBB", 0, 3), Some(3));
        assert_eq!(v.find_anchored_fwd(b"\xAA\x00\x00\xBB", 0, 4), Some(4));
        assert_eq!(v.find_anchored_fwd(b"\xAA\x00\x00\x00\xBB", 0, 5), None);

        assert_eq!(v.find_anchored_fwd(b"\xAA\x00\xAA", 0, 3), None);
        assert_eq!(v.find_anchored_fwd(b"\xBB\x00\xAA", 0, 3), None);

        assert_eq!(vrev.find_anchored_rev(b"\xAA", 0, 1), None);
        assert_eq!(vrev.find_anchored_rev(b"\xAA\xBB", 0, 1), None);
        assert_eq!(vrev.find_anchored_rev(b"\xAA\xBB", 0, 2), Some(0));
        assert_eq!(vrev.find_anchored_rev(b"\xAA\xBB\xBB", 0, 3), Some(0));
        assert_eq!(vrev.find_anchored_rev(b"\xAA\xAA\xBB", 0, 3), Some(0));
        assert_eq!(vrev.find_anchored_rev(b"\xAA\xAA\xAA\xBB", 0, 4), Some(0));
        assert_eq!(vrev.find_anchored_rev(b"\xBB\xAA\xAA\xBB", 0, 4), Some(1));

        assert_eq!(vrev.find_anchored_rev(b"\xAA\x00\xAA", 0, 3), None);
    }

    #[test]
    fn test_simple_validator_alternation() {
        let mods = Modifiers::default();
        let expr = "{ 00 ( AA ?? BB | CC | DD EE ) 11 ( 22 | 33 ) 44 }";
        let v = build_validator(expr, mods, false).unwrap();
        let vrev = build_validator(expr, mods, true).unwrap();

        assert_eq!(
            v.find_anchored_fwd(b"\x00\xAA\x00\xBB\x11\x22\x44", 0, 7),
            Some(7)
        );
        assert_eq!(
            vrev.find_anchored_rev(b"\x00\xAA\x00\xBB\x11\x22\x44", 0, 7),
            Some(0)
        );

        assert_eq!(
            v.find_anchored_fwd(b"\x00\xAA\x00\xBB\x11\x22\x44\x55", 0, 8),
            Some(7)
        );
        assert_eq!(
            vrev.find_anchored_rev(b"\x00\xAA\x00\xBB\x11\x22\x44\x55", 0, 8),
            None
        );

        assert_eq!(
            v.find_anchored_fwd(b"\xFF\x00\xAA\x00\xBB\x11\x22\x44", 0, 8),
            None
        );
        assert_eq!(
            vrev.find_anchored_rev(b"\xFF\x00\xAA\x00\xBB\x11\x22\x44", 0, 8),
            Some(1)
        );

        assert_eq!(
            v.find_anchored_fwd(b"\x00\xAA\x00\xBB\x11\x33\x44", 0, 7),
            Some(7)
        );
        assert_eq!(
            vrev.find_anchored_rev(b"\x00\xAA\x00\xBB\x11\x33\x44", 0, 7),
            Some(0)
        );

        assert_eq!(
            v.find_anchored_fwd(b"\x00\xDD\xEE\x11\x33\x44", 0, 6),
            Some(6)
        );
        assert_eq!(
            vrev.find_anchored_rev(b"\x00\xDD\xEE\x11\x33\x44", 0, 6),
            Some(0)
        );

        assert_eq!(v.find_anchored_fwd(b"\x00\xCC\x11\x22\x44", 0, 5), Some(5));
        assert_eq!(
            vrev.find_anchored_rev(b"\x00\xCC\x11\x22\x44", 0, 5),
            Some(0)
        );
    }

    #[test]
    fn test_simple_validator_alternation_backtrack() {
        // This test that even if a branch is valid, we must test the rest
        // of the nodes and backtrack to another branch if the rest fails.
        let mods = Modifiers::default();
        let expr = "{ ( AA | AA BB ) CC }";
        let v = build_validator(expr, mods, false).unwrap();

        assert_eq!(v.find_anchored_fwd(b"\xAA", 0, 1), None);
        assert_eq!(v.find_anchored_fwd(b"\xAA\xDD", 0, 2), None);
        assert_eq!(v.find_anchored_fwd(b"\xAA\xCC", 0, 2), Some(2));
        assert_eq!(v.find_anchored_fwd(b"\xAA\xBB", 0, 2), None);
        assert_eq!(v.find_anchored_fwd(b"\xAA\xBB\xDD", 0, 3), None);
        assert_eq!(v.find_anchored_fwd(b"\xAA\xBB\xCC", 0, 3), Some(3));

        let expr = "{ CC ( AA | BB AA ) }";
        let vrev = build_validator(expr, mods, true).unwrap();

        assert_eq!(vrev.find_anchored_rev(b"\xAA", 0, 1), None);
        assert_eq!(vrev.find_anchored_rev(b"\xDD\xAA", 0, 2), None);
        assert_eq!(vrev.find_anchored_rev(b"\xCC\xAA", 0, 2), Some(0));
        assert_eq!(vrev.find_anchored_rev(b"\xBB\xAA", 0, 2), None);
        assert_eq!(vrev.find_anchored_rev(b"\xDD\xBB\xAA", 0, 3), None);
        assert_eq!(vrev.find_anchored_rev(b"\xCC\xBB\xAA", 0, 3), Some(0));
    }

    #[test]
    fn test_simple_validator_alternations_limit() {
        let mods = Modifiers::default();

        // No more than u8::max branches
        let mut expr = String::new();
        expr.push_str("(a");
        for _ in 0..u8::MAX {
            expr.push_str("|a");
        }
        expr.push(')');
        test_build(&expr, mods, false, None);

        // A single branch cannot be longer than u8::max
        let mut expr = String::new();
        expr.push_str("(a|");
        for _ in 0..=u8::MAX {
            expr.push('a');
        }
        expr.push_str("|a)");
        test_build(&expr, mods, false, None);
    }
}
