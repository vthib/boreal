use super::hir::Hir;

/// Trait used to visit a regex HIR in constant stack space.
pub trait Visitor {
    /// Type of the result of the visit.
    type Output;

    /// Called for all hirs, before visiting children hirs.
    ///
    /// If an error is returned, the visit is stopped and the error bubbled up.
    fn visit_pre(&mut self, hir: &Hir) -> VisitAction;

    /// Called for all hirs, after visiting children hirs.
    ///
    /// If an error is returned, the visit is stopped and the error bubbled up.
    fn visit_post(&mut self, _hir: &Hir) {}

    /// Called between alternation hirs.
    fn visit_alternation_in(&mut self) {}

    /// Close the visitor and return the result.
    fn finish(self) -> Self::Output;
}

/// Action to take on a given hir regarding its children.
///
/// This only make sense on compound hirs.
pub enum VisitAction {
    /// Continue walking inside the hir, visiting its children.
    Continue,
    /// Skip the visit of the children hirs.
    Skip,
}

/// Visit a regex HIR.
///
/// This is done with a heap-based stack to ensure that the stack does not grow while visiting
/// the regex, preventing stack overflows on expressions with too much depth.
///
/// # Errors
///
/// If the visitor generates an error any time during the visit, the visit ends and the error
/// is returned.
// This is greatly inspired by the HeapVisitor of the regex crate.
// See
// <https://github.com/rust-lang/regex/blob/regex-syntax-0.6.25/regex-syntax/src/hir/visitor.rs>
pub fn visit<V: Visitor>(mut hir: &Hir, mut visitor: V) -> V::Output {
    // Heap-base stack to visit hirs without growing the stack.
    // Each element is:
    // - a hir that is currently being visited.
    // - a list of its children hirs left to visit.
    let mut stack = Vec::new();

    loop {
        if let VisitAction::Continue = visitor.visit_pre(hir) {
            if let Some(frame) = build_stack_frame(hir) {
                // New stack frame for the hir. Push the hir and its frame onto the stack,
                // and visit its first children.
                let child = frame.hir;
                stack.push((frame, hir));
                hir = child;
                continue;
            }
        }

        // Hir has either no children or `VisitAction::Skip` was returned. End the visit on
        // this hir and go through the stack until finding a new hir to visit.
        visitor.visit_post(hir);
        loop {
            match stack.pop() {
                Some((frame, parent)) => {
                    match frame.next() {
                        // More children in the current frame
                        Some(new_frame) => {
                            // If frame is an alternation, and we have a new children,
                            // we are between two alternated hirs.
                            if new_frame.is_alternation {
                                visitor.visit_alternation_in();
                            }

                            // Push the new frame onto the stack
                            let child = new_frame.hir;
                            stack.push((new_frame, parent));
                            hir = child;
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

struct StackFrame<'a> {
    hir: &'a Hir,

    rest: &'a [Hir],

    is_alternation: bool,
}

impl<'a> StackFrame<'a> {
    /// Get the next hir in the frame.
    ///
    /// This returns:
    /// - None if there are no other hirs in the frame.
    /// - a new stack frame and the next hir otherwise.
    fn next(self) -> Option<StackFrame<'a>> {
        if self.rest.is_empty() {
            None
        } else {
            Some(StackFrame {
                hir: &self.rest[0],
                rest: &self.rest[1..],
                is_alternation: self.is_alternation,
            })
        }
    }
}

/// Build a stack frame for the given hir.
fn build_stack_frame(hir: &Hir) -> Option<StackFrame> {
    match hir {
        Hir::Group(hir) | Hir::Repetition { hir, .. } => Some(StackFrame {
            hir,
            rest: &[],
            is_alternation: false,
        }),
        Hir::Concat(hirs) | Hir::Alternation(hirs) if hirs.is_empty() => None,
        Hir::Concat(hirs) => Some(StackFrame {
            hir: &hirs[0],
            rest: &hirs[1..],
            is_alternation: false,
        }),
        Hir::Alternation(hirs) => Some(StackFrame {
            hir: &hirs[0],
            rest: &hirs[1..],
            is_alternation: true,
        }),
        _ => None,
    }
}
