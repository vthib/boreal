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
pub fn visit<V: Visitor>(node: &Node, mut visitor: V) -> V::Output {
    visit_inner(node, &mut visitor);
    visitor.finish()
}

fn visit_inner<V: Visitor>(node: &Node, visitor: &mut V) {
    match visitor.visit_pre(node) {
        VisitAction::Skip => {
            visitor.visit_post(node);
            return;
        }
        VisitAction::Continue => (),
    }

    match node {
        Node::Alternation(nodes) => {
            for (i, node) in nodes.iter().enumerate() {
                if i != 0 {
                    visitor.visit_alternation_in();
                }
                visit_inner(node, visitor);
            }
        }
        Node::Dot | Node::Empty | Node::Literal(_) | Node::Assertion(_) | Node::Class(_) => (),
        Node::Concat(nodes) => {
            for node in nodes {
                visit_inner(node, visitor);
            }
        }
        Node::Group(node) => visit_inner(node, visitor),
        Node::Repetition { node, .. } => visit_inner(node, visitor),
    }

    visitor.visit_post(node);
}
