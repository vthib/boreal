//! Validator able to handle "simple" expressions.
//!
//! "Simple" expression means any expression that do not require branching or complex logic.
//! Basically, any expression that can be resolved by simply checking each byte one by one.
//!
//! This mainly excludes alternations and repetitions.
use crate::matcher::analysis::HirAnalysis;
use crate::matcher::Modifiers;
use crate::regex::Hir;

#[derive(Debug, PartialEq)]
pub(crate) struct SimpleValidator {
    /// List of nodes to match
    nodes: Vec<SimpleNode>,
    /// Total length of the expression
    length: usize,
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
            || analysis.has_repetitions
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

        let length = nodes.iter().fold(0, |acc, node| match node {
            SimpleNode::Jump(len) => acc + usize::from(*len),
            _ => acc + 1,
        });
        Some(Self { nodes, length })
    }

    pub(crate) fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let mem = &haystack[start..end];
        if mem.len() < self.length {
            return None;
        }

        let mut index = 0;
        for node in &self.nodes {
            index += check_node(node, mem, index)?;
        }

        Some(start + index)
    }

    pub(crate) fn find_anchored_rev(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let mem = &haystack[start..end];
        if mem.len() < self.length {
            return None;
        }

        let mut index = mem.len();
        for node in &self.nodes {
            index -= check_node(node, mem, index - 1)?;
        }

        Some(index + start)
    }
}

#[inline(always)]
fn check_node(node: &SimpleNode, mem: &[u8], index: usize) -> Option<usize> {
    let matched = match node {
        SimpleNode::Jump(v) => return Some(usize::from(*v)),
        SimpleNode::Dot => mem[index] != b'\n',
        SimpleNode::Byte(a) => mem[index] == *a,
        SimpleNode::Mask { value, mask } => (mem[index] & *mask) == *value,
        SimpleNode::NegatedMask { value, mask } => (mem[index] & *mask) != *value,
    };

    if matched {
        Some(1)
    } else {
        None
    }
}

fn add_hir_to_simple_nodes(
    hir: &Hir,
    modifiers: Modifiers,
    reverse: bool,
    nodes: &mut Vec<SimpleNode>,
) -> bool {
    match hir {
        Hir::Alternation(_) | Hir::Assertion(_) | Hir::Class(_) | Hir::Repetition { .. } => false,
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
                if nodes.is_empty() {
                    nodes.push(SimpleNode::Jump(1));
                } else {
                    let last_index = nodes.len() - 1;
                    match &mut nodes[last_index] {
                        SimpleNode::Jump(v) if *v < 255 => *v += 1,
                        _ => nodes.push(SimpleNode::Jump(1)),
                    }
                }
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
            self.length.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for SimpleValidator {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let nodes = <Vec<SimpleNode>>::deserialize_reader(reader)?;
            let length = usize::deserialize_reader(reader)?;

            Ok(Self { nodes, length })
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
                    nodes: vec![SimpleNode::Byte(23), SimpleNode::Dot],
                    length: 23,
                },
                &[0, 1, 6, 12],
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

            test_invalid_deserialization::<SimpleNode>(b"\x05");
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
}
