use boreal_parser::regex::Node;

/// Trait used to visit a regex ast in constant stack space.
pub trait Visitor {
    /// Type of the result of the visit.
    type Output;

    /// Called for all nodes, before visiting children nodes.
    fn visit_pre(&mut self, node: &Node) -> VisitAction;

    /// Called for all nodes, after visiting children nodes.
    fn visit_post(&mut self, _node: &Node) {}

    /// Called between alternation nodes.
    fn visit_alternation_in(&mut self) {}

    /// Close the visitor and return the result.
    fn finish(self) -> Self::Output;
}

/// Action to take on a given node regarding its children.
///
/// This only make sense on compound nodes.
pub enum VisitAction {
    /// Continue walking inside the node, visiting its children.
    Continue,
    /// Skip the visit of the children nodes.
    Skip,
}

/// Visit a regex AST.
///
/// This is done with a heap-based stack to ensure that the stack does not grow while visiting
/// the regex, preventing stack overflows on expressions with too much depth.
// This is greatly inspired by the HeapVisitor of the regex crate.
// See
// <https://github.com/rust-lang/regex/blob/regex-syntax-0.6.25/regex-syntax/src/hir/visitor.rs>
pub fn visit<V: Visitor>(mut node: &Node, mut visitor: V) -> V::Output {
    // Heap-base stack to visit nodes without growing the stack.
    // Each element is:
    // - a node that is currently being visited.
    // - a list of its children nodes left to visit.
    let mut stack = Vec::new();

    loop {
        if let VisitAction::Continue = visitor.visit_pre(node) {
            if let Some(frame) = build_stack_frame(node) {
                // New stack frame for the node. Push the node and its frame onto the stack,
                // and visit its first children.
                let child = frame.node;
                stack.push((frame, node));
                node = child;
                continue;
            }
        }

        // Node has either no children or `VisitAction::Skip` was returned. End the visit on
        // this node and go through the stack until finding a new node to visit.
        visitor.visit_post(node);
        loop {
            match stack.pop() {
                Some((frame, parent)) => {
                    match frame.next() {
                        // More children in the current frame
                        Some(new_frame) => {
                            // If frame is an alternation, and we have a new children,
                            // we are between two alternated nodes.
                            if new_frame.is_alternation {
                                visitor.visit_alternation_in();
                            }

                            // Push the new frame onto the stack
                            let child = new_frame.node;
                            stack.push((new_frame, parent));
                            node = child;
                            break;
                        }
                        // Frame is exhausted, visit_post the parent and pop the next element
                        None => visitor.visit_post(parent),
                    }
                }
                None => {
                    return visitor.finish();
                }
            }
        }
    }
}

#[derive(Debug)]
struct StackFrame<'a> {
    node: &'a Node,

    rest: &'a [Node],

    is_alternation: bool,
}

impl<'a> StackFrame<'a> {
    /// Get the next node in the frame.
    ///
    /// This returns:
    /// - None if there are no other nodes in the frame.
    /// - a new stack frame and the next node otherwise.
    fn next(self) -> Option<StackFrame<'a>> {
        if self.rest.is_empty() {
            None
        } else {
            Some(StackFrame {
                node: &self.rest[0],
                rest: &self.rest[1..],
                is_alternation: self.is_alternation,
            })
        }
    }
}

/// Build a stack frame for the given node.
fn build_stack_frame(node: &Node) -> Option<StackFrame> {
    match node {
        Node::Group(node) | Node::Repetition { node, .. } => Some(StackFrame {
            node,
            rest: &[],
            is_alternation: false,
        }),
        Node::Concat(nodes) | Node::Alternation(nodes) if nodes.is_empty() => None,
        Node::Concat(nodes) => Some(StackFrame {
            node: &nodes[0],
            rest: &nodes[1..],
            is_alternation: false,
        }),
        Node::Alternation(nodes) => Some(StackFrame {
            node: &nodes[0],
            rest: &nodes[1..],
            is_alternation: true,
        }),
        _ => None,
    }
}
