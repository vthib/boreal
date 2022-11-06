use std::convert::Infallible;

use boreal_parser::regex::{AssertionKind, Node};
use boreal_parser::VariableFlags;

use crate::regex::{regex_ast_to_string, visit, Regex, VisitAction, Visitor};

use super::atom::AtomsDetails;
use super::{CompiledVariable, MatcherType, VariableCompilationError};

/// Build a matcher for the given regex and string modifiers.
///
/// This function returns two values:
/// - The regex expression to use to match on this variable
/// - An optional expr used to validate matches, only set in the specific case of a widen regex
///   containing word boundaries.
pub(super) fn compile_regex(
    ast: &Node,
    mut case_insensitive: bool,
    dot_all: bool,
    flags: VariableFlags,
) -> Result<CompiledVariable, VariableCompilationError> {
    if flags.contains(VariableFlags::NOCASE) {
        case_insensitive = true;
    }

    let AtomsDetails {
        mut literals,
        pre_ast,
        post_ast,
    } = super::atom::get_atoms_details(ast).map_err(|e| match e {
        super::atom::AtomsExtractionError => VariableCompilationError::AtomsExtractionError,
    })?;

    let use_ac = visit(ast, AcCompatibility::default()).unwrap_or_else(|e| match e {});

    let mut has_wide_word_boundaries = false;
    let matcher_type = if literals.is_empty() || !use_ac {
        let (expr, has_ww_boundaries) = convert_ast_to_string_with_flags(ast, flags)?;
        has_wide_word_boundaries |= has_ww_boundaries;

        apply_ascii_wide_flags_on_literals(&mut literals, flags);

        MatcherType::Raw(super::compile_regex_expr(&expr, case_insensitive, dot_all)?)
    } else {
        let pre = match pre_ast {
            Some(ast) => {
                let (pre, has_ww_boundaries) = convert_ast_to_string_with_flags(&ast, flags)?;
                has_wide_word_boundaries |= has_ww_boundaries;
                Some(pre)
            }
            None => None,
        };
        let post = match post_ast {
            Some(ast) => {
                let (post, has_ww_boundaries) = convert_ast_to_string_with_flags(&ast, flags)?;
                has_wide_word_boundaries |= has_ww_boundaries;
                Some(post)
            }
            None => None,
        };
        apply_ascii_wide_flags_on_literals(&mut literals, flags);

        MatcherType::Atomized {
            left_validator: compile_validator(pre, case_insensitive, dot_all)?,
            right_validator: compile_validator(post, case_insensitive, dot_all)?,
        }
    };

    let non_wide_regex = if has_wide_word_boundaries {
        let expr = regex_ast_to_string(ast);
        Some(super::compile_regex_expr(&expr, case_insensitive, dot_all)?)
    } else {
        None
    };

    Ok(CompiledVariable {
        literals,
        matcher_type,
        non_wide_regex,
    })
}

struct AcCompatibility(bool);

impl Default for AcCompatibility {
    fn default() -> Self {
        Self(true)
    }
}

impl Visitor for AcCompatibility {
    type Output = bool;
    type Err = Infallible;

    fn visit_pre(&mut self, node: &Node) -> Result<VisitAction, Self::Err> {
        match node {
            Node::Assertion(AssertionKind::StartLine) | Node::Assertion(AssertionKind::EndLine) => {
                // Do not use an AC if anchors are present, it will be much efficient to just run
                // the regex directly.
                self.0 = false;
            }
            Node::Repetition { greedy: true, .. } => {
                // TODO: allow greedy when it does not contain characters from the literals?
                // This would allow matching \s* which would be useful.
                self.0 = false;
            }
            _ => (),
        }

        Ok(VisitAction::Continue)
    }

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self.0)
    }
}

fn compile_validator(
    expr: Option<String>,
    case_insensitive: bool,
    dot_all: bool,
) -> Result<Option<Regex>, VariableCompilationError> {
    match expr {
        Some(expr) => Ok(Some(super::compile_regex_expr(
            &expr,
            case_insensitive,
            dot_all,
        )?)),
        None => Ok(None),
    }
}

fn apply_ascii_wide_flags_on_literals(literals: &mut Vec<Vec<u8>>, flags: VariableFlags) {
    if !flags.contains(VariableFlags::WIDE) {
        return;
    }

    if flags.contains(VariableFlags::ASCII) {
        let wide_literals: Vec<_> = literals.iter().map(|v| widen_literal(v)).collect();
        literals.extend(wide_literals);
    } else {
        for lit in literals {
            *lit = widen_literal(lit);
        }
    }
}

fn widen_literal(literal: &[u8]) -> Vec<u8> {
    let mut new_lit = Vec::with_capacity(literal.len() * 2);
    for b in literal {
        new_lit.push(*b);
        new_lit.push(0);
    }
    new_lit
}

/// Convert the AST of a regex variable to a string, taking into account variable modifiers.
fn convert_ast_to_string_with_flags(
    ast: &Node,
    flags: VariableFlags,
) -> Result<(String, bool), VariableCompilationError> {
    if flags.contains(VariableFlags::WIDE) {
        let (wide_ast, has_wide_word_boundaries) = visit(ast, AstWidener::new())?;

        let expr = if flags.contains(VariableFlags::ASCII) {
            format!(
                "{}|{}",
                regex_ast_to_string(ast),
                regex_ast_to_string(&wide_ast),
            )
        } else {
            regex_ast_to_string(&wide_ast)
        };
        Ok((expr, has_wide_word_boundaries))
    } else {
        Ok((regex_ast_to_string(ast), false))
    }
}

/// Visitor used to transform a regex AST to make the regex match "wide" characters.
///
/// This is intented to transform a regex with the "wide" modifier, that is make it so
/// the regex will not match raw ASCII but UCS-2.
///
/// This means translating every match on a literal or class into this literal/class followed by a
/// nul byte. See the implementation of the [`Visitor`] trait on [`NodeWidener`] for more details.
#[derive(Debug)]
struct AstWidener {
    /// Top level AST object
    node: Option<Node>,

    /// Stack of AST objects built.
    ///
    /// Each visit to a compound AST value (group, alternation, etc) will push a new level
    /// to the stack. Then when we finish visiting the compound value, the level will be pop-ed,
    /// and the new compound AST value built.
    stack: Vec<StackLevel>,

    /// Does the regex contains word boundaries
    has_word_boundaries: bool,
}

#[derive(Debug)]
struct StackLevel {
    /// AST values built in this level.
    nodes: Vec<Node>,

    /// Is this level for a concat AST value.
    in_concat: bool,
}

impl StackLevel {
    fn new(in_concat: bool) -> Self {
        Self {
            nodes: Vec::new(),
            in_concat,
        }
    }

    fn push(&mut self, node: Node) {
        self.nodes.push(node);
    }
}

impl AstWidener {
    fn new() -> Self {
        Self {
            node: None,
            stack: Vec::new(),
            has_word_boundaries: false,
        }
    }

    fn add(&mut self, node: Node) -> Result<(), VariableCompilationError> {
        if self.stack.is_empty() {
            // Empty stack: we should only have a single AST to set at top-level.
            match self.node.replace(node) {
                Some(_) => Err(VariableCompilationError::WidenError),
                None => Ok(()),
            }
        } else {
            let pos = self.stack.len() - 1;
            self.stack[pos].push(node);
            Ok(())
        }
    }

    fn add_wide(&mut self, node: Node) -> Result<(), VariableCompilationError> {
        let nul_byte = Node::Literal(b'\0');

        if self.stack.is_empty() {
            match self.node.replace(Node::Concat(vec![node, nul_byte])) {
                Some(_) => Err(VariableCompilationError::WidenError),
                None => Ok(()),
            }
        } else {
            let pos = self.stack.len() - 1;
            let level = &mut self.stack[pos];
            if level.in_concat {
                level.nodes.push(node);
                level.nodes.push(nul_byte);
            } else {
                level
                    .nodes
                    .push(Node::Group(Box::new(Node::Concat(vec![node, nul_byte]))));
            }
            Ok(())
        }
    }

    fn pop(&mut self) -> Option<Vec<Node>> {
        self.stack.pop().map(|v| v.nodes)
    }
}

impl Visitor for AstWidener {
    type Output = (Node, bool);
    type Err = VariableCompilationError;

    fn finish(self) -> Result<(Node, bool), Self::Err> {
        match self.node {
            Some(v) => Ok((v, self.has_word_boundaries)),
            None => Err(VariableCompilationError::WidenError),
        }
    }

    fn visit_pre(&mut self, node: &Node) -> Result<VisitAction, Self::Err> {
        match node {
            Node::Dot | Node::Empty | Node::Literal(_) | Node::Class(_) | Node::Assertion(_) => (),

            Node::Repetition { .. } | Node::Group(_) | Node::Alternation(_) => {
                self.stack.push(StackLevel::new(false));
            }
            Node::Concat(_) => {
                self.stack.push(StackLevel::new(true));
            }
        }
        Ok(VisitAction::Continue)
    }

    fn visit_post(&mut self, node: &Node) -> Result<(), Self::Err> {
        match node {
            Node::Empty => self.add(Node::Empty),

            // Literal, dot or class: add a nul_byte after it
            Node::Dot => self.add_wide(Node::Dot),
            Node::Literal(lit) => self.add_wide(Node::Literal(*lit)),
            Node::Class(cls) => self.add_wide(Node::Class(cls.clone())),

            // Anchor: no need to add anything
            Node::Assertion(AssertionKind::StartLine) | Node::Assertion(AssertionKind::EndLine) => {
                self.add(node.clone())
            }

            // Boundary is tricky as it looks for a match between two characters:
            // \b means: word on the left side, non-word on the right, or the opposite:
            // - \ta, a\t, \0a, \t\0 matches
            // - ab, \t\n does not match
            // When the input is wide, this is harder:
            // - \t\0a\0, a\0\t\0 matches
            // - a\0b\0, \t\0\b\0 does not match
            //
            // This cannot be transformed properly. Instead, we have two possibilities:
            // - Unwide the input, and run the regex on it.
            // - widen the regex but without the word boundaries. On matches, unwide the match,
            //   then use the non wide regex to check if the match is valid.
            //
            // We use the second solution. Note that there are some differences in results
            // depending on which solution is picked. Those are mostly edge cases on carefully
            // crafted regexes, so it should not matter, but the test
            // `test_variable_regex_word_boundaries_edge_cases` tests some of those.
            Node::Assertion(AssertionKind::WordBoundary)
            | Node::Assertion(AssertionKind::NonWordBoundary) => {
                self.has_word_boundaries = true;
                self.add(Node::Empty)
            }

            Node::Repetition {
                node: _,
                kind,
                greedy,
            } => {
                let node = self
                    .pop()
                    .and_then(|mut v| v.pop())
                    .ok_or(VariableCompilationError::WidenError)?;
                self.add(Node::Repetition {
                    kind: kind.clone(),
                    greedy: *greedy,
                    node: Box::new(node),
                })
            }
            Node::Group(_) => {
                let node = self
                    .pop()
                    .and_then(|mut v| v.pop())
                    .ok_or(VariableCompilationError::WidenError)?;
                self.add(Node::Group(Box::new(node)))
            }
            Node::Concat(_) => {
                let vec = self.pop().ok_or(VariableCompilationError::WidenError)?;
                self.add(Node::Concat(vec))
            }
            Node::Alternation(_) => {
                let vec = self.pop().ok_or(VariableCompilationError::WidenError)?;
                self.add(Node::Alternation(vec))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(AstWidener::new());
        test_type_traits_non_clonable(StackLevel::new(false));
    }
}
