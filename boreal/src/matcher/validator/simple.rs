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
}
