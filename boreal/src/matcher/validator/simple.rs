//! Validator able to handle "simple" expressions.
//!
//! "Simple" expression means any expression that do not require branching or complex logic.
//! Basically, any expression that can be resolved by simply checking each byte one by one.
//!
//! This mainly excludes alternations and repetitions.
use crate::matcher::analysis::HirAnalysis;
use crate::matcher::Modifiers;
use crate::regex::Hir;

#[derive(Debug)]
pub(crate) struct SimpleValidator {
    nodes: Vec<SimpleNode>,
}

#[derive(Debug)]
enum SimpleNode {
    // Byte to match
    Byte(u8),
    // Masked byte
    Mask { value: u8, mask: u8 },
    // Negated Masked byte
    NegatedMask { value: u8, mask: u8 },
    // Dot, any byte
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
            || analysis.has_classes
            || analysis.has_alternations
        {
            // TODO: handle fixed size repetitions and handle classes.
            return None;
        }

        if !modifiers.dot_all || modifiers.nocase || modifiers.wide {
            // TODO: all those modifiers could be handled.
            return None;
        }

        let mut nodes = Vec::new();
        if !add_hir_to_simple_nodes(hir, reverse, &mut nodes) {
            return None;
        }

        Some(Self { nodes })
    }

    pub(crate) fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        let mem = &haystack[start..end];
        if mem.len() < self.nodes.len() {
            return None;
        }

        let mut index = 0;
        for node in &self.nodes {
            if !check_node(node, mem, index) {
                return None;
            }

            index += 1;
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
        if mem.len() < self.nodes.len() {
            return None;
        }

        let mut index = mem.len();
        for node in &self.nodes {
            if !check_node(node, mem, index - 1) {
                return None;
            }

            index -= 1;
        }

        Some(index + start)
    }
}

#[inline(always)]
fn check_node(node: &SimpleNode, mem: &[u8], index: usize) -> bool {
    match node {
        SimpleNode::Dot => true,
        SimpleNode::Byte(a) => mem[index] == *a,
        SimpleNode::Mask { value, mask } => (mem[index] & *mask) == *value,
        SimpleNode::NegatedMask { value, mask } => (mem[index] & *mask) != *value,
    }
}

fn add_hir_to_simple_nodes(hir: &Hir, reverse: bool, nodes: &mut Vec<SimpleNode>) -> bool {
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
                    if !add_hir_to_simple_nodes(h, reverse, nodes) {
                        return false;
                    }
                }
            } else {
                for h in hirs {
                    if !add_hir_to_simple_nodes(h, reverse, nodes) {
                        return false;
                    }
                }
            }

            true
        }
        Hir::Dot => {
            nodes.push(SimpleNode::Dot);
            true
        }
        Hir::Empty => true,
        Hir::Literal(b) => {
            nodes.push(SimpleNode::Byte(*b));
            true
        }
        Hir::Group(hir) => add_hir_to_simple_nodes(hir, reverse, nodes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::analysis::analyze_hir;
    use crate::test_helpers::test_type_traits_non_clonable;

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
    }

    #[test]
    fn test_simple_validator() {
        let validator = SimpleValidator {
            nodes: vec![
                SimpleNode::Byte(b'a'),
                SimpleNode::Dot,
                SimpleNode::Byte(b'c'),
            ],
        };

        // Test the start/end handling
        assert_eq!(validator.find_anchored_fwd(b"abc", 0, 3), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 0, 3), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 0, 2), None);
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 0, 6), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"abcdef", 1, 6), None);
        assert_eq!(validator.find_anchored_fwd(b"cbabcd", 2, 6), Some(5));

        // Test with reverse search as well
        assert_eq!(validator.find_anchored_rev(b"cba", 0, 3), Some(0));
        assert_eq!(validator.find_anchored_rev(b"cbadef", 0, 3), Some(0));
        assert_eq!(validator.find_anchored_rev(b"cbadef", 0, 2), None);
        assert_eq!(validator.find_anchored_rev(b"defcba", 0, 6), Some(3));
        assert_eq!(validator.find_anchored_rev(b"defcba", 0, 5), None);
        assert_eq!(validator.find_anchored_rev(b"abcbad", 0, 5), Some(2));

        // Test matching of bytes and dot
        assert_eq!(validator.find_anchored_fwd(b"bbc", 0, 3), None);
        assert_eq!(validator.find_anchored_fwd(b"a\nc", 0, 3), Some(3));
        assert_eq!(validator.find_anchored_fwd(b"a\na", 0, 3), None);
        assert_eq!(validator.find_anchored_fwd(b"c\na", 0, 3), None);

        assert_eq!(validator.find_anchored_rev(b"bbc", 0, 3), None);
        assert_eq!(validator.find_anchored_rev(b"a\nc", 0, 3), None);
        assert_eq!(validator.find_anchored_rev(b"a\na", 0, 3), None);
        assert_eq!(validator.find_anchored_rev(b"c\na", 0, 3), Some(0));

        let validator = SimpleValidator {
            nodes: vec![
                SimpleNode::Mask {
                    value: 0x50,
                    mask: 0xF0,
                },
                SimpleNode::NegatedMask {
                    value: 0x0A,
                    mask: 0x0F,
                },
            ],
        };

        // Test matching of masks
        assert_eq!(validator.find_anchored_fwd(b"\x50\x0B", 0, 2), Some(2));
        assert_eq!(validator.find_anchored_fwd(b"\x51\x1D", 0, 2), Some(2));
        assert_eq!(validator.find_anchored_fwd(b"\x5F\xFF", 0, 2), Some(2));
        assert_eq!(validator.find_anchored_fwd(b"\x7F\xFF", 0, 2), None);
        assert_eq!(validator.find_anchored_fwd(b"\x5F\xFA", 0, 2), None);

        assert_eq!(validator.find_anchored_rev(b"\x0B\x50", 0, 2), Some(0));
        assert_eq!(validator.find_anchored_rev(b"\x1D\x51", 0, 2), Some(0));
        assert_eq!(validator.find_anchored_rev(b"\xFF\x5F", 0, 2), Some(0));
        assert_eq!(validator.find_anchored_rev(b"\xFF\x7F", 0, 2), None);
        assert_eq!(validator.find_anchored_rev(b"\xFA\x5F", 0, 2), None);
    }
}
