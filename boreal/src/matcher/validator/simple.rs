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
            || analysis.has_alternations
        {
            // TODO: handle fixed size repetitions.
            return None;
        }

        if modifiers.nocase || modifiers.wide {
            // TODO: all those modifiers could be handled.
            return None;
        }

        let mut nodes = Vec::new();
        if !add_hir_to_simple_nodes(hir, modifiers, reverse, &mut nodes) {
            return None;
        }

        Some(Self {
            nodes: nodes.into_boxed_slice(),
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

fn add_hir_to_simple_nodes(
    hir: &Hir,
    modifiers: Modifiers,
    reverse: bool,
    nodes: &mut Vec<SimpleNode>,
) -> bool {
    match hir {
        Hir::Alternation(_) | Hir::Assertion(_) | Hir::Class(_) => false,
        Hir::Mask {
            value,
            mask,
            negated,
        } => {
            nodes.push(if *negated {
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
            if reverse {
                for h in hirs.iter().rev() {
                    if !add_hir_to_simple_nodes(h, modifiers, reverse, nodes) {
                        return false;
                    }
                }
            } else {
                for h in hirs {
                    if !add_hir_to_simple_nodes(h, modifiers, reverse, nodes) {
                        return false;
                    }
                }
            }

            true
        }
        Hir::Dot => {
            if modifiers.dot_all {
                add_jump(nodes, 1);
            } else {
                nodes.push(SimpleNode::Dot);
            }
            true
        }
        Hir::Empty => true,
        Hir::Literal(b) => {
            nodes.push(SimpleNode::Byte(*b));
            true
        }
        Hir::Group(hir) => add_hir_to_simple_nodes(hir, modifiers, reverse, nodes),
        Hir::Repetition { hir, kind, greedy } => {
            // Only handle non-greedy ".{...}" repetitions, with dot_all set. This
            // means the repeated byte can just be ignored, and matches
            // the [X-Y] jumps in hex strings.
            if !matches!(&**hir, Hir::Dot) || !modifiers.dot_all || *greedy {
                return false;
            }

            match kind {
                RepetitionKind::ZeroOrOne => nodes.push(SimpleNode::JumpRange(0, 1)),
                RepetitionKind::Range(RepetitionRange::Exactly(m)) => {
                    let Ok(m) = u8::try_from(*m) else {
                        return false;
                    };
                    add_jump(nodes, m);
                }
                RepetitionKind::Range(RepetitionRange::Bounded(m, n)) => {
                    let Ok(m) = u8::try_from(*m) else {
                        return false;
                    };
                    let Ok(n) = u8::try_from(*n) else {
                        return false;
                    };
                    // TODO: check combination of jumps across the whole
                    // hir, which can multiply and make this pathologic.
                    nodes.push(SimpleNode::JumpRange(m, n));
                }
                // Unbounded jumps are not handled
                RepetitionKind::ZeroOrMore
                | RepetitionKind::OneOrMore
                | RepetitionKind::Range(RepetitionRange::AtLeast(_)) => return false,
            }
            true
        }
    }
}

fn add_jump(nodes: &mut Vec<SimpleNode>, jump_length: u8) {
    if nodes.is_empty() {
        nodes.push(SimpleNode::Jump(jump_length));
    } else {
        let last_index = nodes.len() - 1;
        if let SimpleNode::Jump(value) = &mut nodes[last_index] {
            match value.checked_add(jump_length) {
                Some(new_value) => *value = new_value,
                None => nodes.push(SimpleNode::Jump(jump_length)),
            }
        } else {
            nodes.push(SimpleNode::Jump(jump_length));
        }
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

    #[test]
    fn test_simple_validator_build() {
        fn test(
            expr: &str,
            modifiers: Modifiers,
            reverse: bool,
            expected_nodes: Option<&[SimpleNode]>,
        ) {
            let v = build_validator(expr, modifiers, reverse);
            assert_eq!(v.as_ref().map(|v| &*v.nodes), expected_nodes);
        }

        // Regex contains nodes that are not handled
        test("a?", Modifiers::default(), false, None);
        test("a|b", Modifiers::default(), false, None);
        test("^a", Modifiers::default(), false, None);
        test("a$", Modifiers::default(), false, None);
        test(r"a\b", Modifiers::default(), false, None);
        test(r"a\B", Modifiers::default(), false, None);
        test(r"[aA]", Modifiers::default(), false, None);

        // Modifiers not handled
        test(
            r"a",
            Modifiers {
                nocase: true,
                ..Default::default()
            },
            false,
            None,
        );
        test(
            r"a",
            Modifiers {
                wide: true,
                ..Default::default()
            },
            false,
            None,
        );

        test(
            "a.()d",
            Modifiers::default(),
            false,
            Some(&[
                SimpleNode::Byte(b'a'),
                SimpleNode::Dot,
                SimpleNode::Byte(b'd'),
            ]),
        );

        test(
            "a.()d",
            Modifiers::default(),
            true,
            Some(&[
                SimpleNode::Byte(b'd'),
                SimpleNode::Dot,
                SimpleNode::Byte(b'a'),
            ]),
        );

        test(
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

        test(
            &".".repeat(300),
            Modifiers {
                dot_all: true,
                ..Default::default()
            },
            false,
            Some(&[SimpleNode::Jump(255), SimpleNode::Jump(45)]),
        );

        assert!(!add_hir_to_simple_nodes(
            &Hir::Alternation(vec![Hir::Empty]),
            Modifiers::default(),
            false,
            &mut Vec::new()
        ));
        assert!(!add_hir_to_simple_nodes(
            &Hir::Concat(vec![Hir::Dot, Hir::Assertion(AssertionKind::StartLine)]),
            Modifiers::default(),
            false,
            &mut Vec::new()
        ));
        assert!(!add_hir_to_simple_nodes(
            &Hir::Concat(vec![Hir::Dot, Hir::Assertion(AssertionKind::StartLine)]),
            Modifiers::default(),
            true,
            &mut Vec::new()
        ));
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
}
