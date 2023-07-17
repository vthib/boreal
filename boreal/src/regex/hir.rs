use boreal_parser::{
    hex_string::{Mask, Token},
    regex::{
        AssertionKind, BracketedClass, BracketedClassItem, ClassKind, Node, RepetitionKind,
        RepetitionRange,
    },
};

/// HIR of a regular expression.
///
/// Both regexes and hex strings are translated into this representation, which
/// is then compiled into optimized matchers.
#[derive(Clone, Debug)]
pub enum Hir {
    /// Alternation, ie `a|b|...`.
    Alternation(Vec<Hir>),

    /// Zero-width assertion, e.g. ^, \b, ...
    Assertion(AssertionKind),

    /// Set of allowed values for a single byte.
    Class(ClassKind),

    /// Mask over a byte, e.g. `?A`, `~5?`, ...
    Mask {
        /// Value to compare once the mask has been applied.
        ///
        /// For example, for `5?`, this is `0x50`.
        value: u8,

        /// Mask to apply before comparing the value.
        ///
        /// For example, for `5?`, this is `0xF0`.
        mask: u8,

        /// Is the comparison negated.
        ///
        /// If true, this matches if the comparison does not match.
        negated: bool,
    },

    /// Concatenation, must match in order.
    Concat(Vec<Hir>),

    /// The special `.` character.
    Dot,

    /// Empty expression.
    Empty,

    /// Literal byte.
    Literal(u8),

    /// A group, i.e. (...).
    Group(Box<Hir>),

    /// Repetition of an expression.
    Repetition {
        /// Expression to repeat.
        hir: Box<Hir>,

        /// Kind of repetition.
        kind: RepetitionKind,

        /// Is the repetition greedy or not.
        greedy: bool,
    },
}

impl From<Node> for Hir {
    fn from(value: Node) -> Self {
        match value {
            Node::Alternation(v) => Hir::Alternation(v.into_iter().map(Into::into).collect()),
            Node::Assertion(v) => Hir::Assertion(v),
            Node::Class(v) => Hir::Class(v),
            Node::Concat(v) => Hir::Concat(v.into_iter().map(Into::into).collect()),
            Node::Dot => Hir::Dot,
            Node::Empty => Hir::Empty,
            Node::Literal(v) => Hir::Literal(v),
            Node::Group(v) => Hir::Group(Box::new((*v).into())),
            Node::Repetition { node, kind, greedy } => Hir::Repetition {
                hir: Box::new((*node).into()),
                kind,
                greedy,
            },
        }
    }
}

impl From<Vec<Token>> for Hir {
    fn from(tokens: Vec<Token>) -> Self {
        Hir::Concat(tokens.into_iter().map(Into::into).collect())
    }
}

impl From<Token> for Hir {
    fn from(token: Token) -> Self {
        match token {
            Token::Byte(b) => Hir::Literal(b),
            Token::NotByte(b) => Hir::Class(ClassKind::Bracketed(BracketedClass {
                items: vec![BracketedClassItem::Literal(b)],
                negated: true,
            })),
            Token::MaskedByte(b, mask) => masked_byte_to_hir(b, &mask, false),
            Token::NotMaskedByte(b, mask) => masked_byte_to_hir(b, &mask, true),
            Token::Jump(jump) => {
                let kind = match (jump.from, jump.to) {
                    (from, None) => RepetitionKind::Range(RepetitionRange::AtLeast(from)),
                    (from, Some(to)) => RepetitionKind::Range(RepetitionRange::Bounded(from, to)),
                };
                Hir::Repetition {
                    hir: Box::new(Hir::Dot),
                    kind,
                    greedy: false,
                }
            }
            Token::Alternatives(elems) => Hir::Group(Box::new(Hir::Alternation(
                elems.into_iter().map(Into::into).collect(),
            ))),
        }
    }
}

fn masked_byte_to_hir(byte: u8, mask: &Mask, negated: bool) -> Hir {
    match mask {
        Mask::Left => Hir::Mask {
            value: byte,
            mask: 0x0F,
            negated,
        },
        Mask::Right => Hir::Mask {
            value: byte << 4,
            mask: 0xF0,
            negated,
        },
        Mask::All => Hir::Dot,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits(Hir::Empty);
    }
}
