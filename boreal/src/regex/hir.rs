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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hir {
    /// Alternation, ie `a|b|...`.
    Alternation(Vec<Hir>),

    /// Zero-width assertion, e.g. ^, \b, ...
    Assertion(AssertionKind),

    /// Set of allowed values for a single byte.
    Class(ClassKind),

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
            Token::MaskedByte(b, mask) => masked_byte_to_class(b, &mask, false),
            Token::NotMaskedByte(b, mask) => masked_byte_to_class(b, &mask, true),
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

fn masked_byte_to_class(byte: u8, mask: &Mask, negated: bool) -> Hir {
    match mask {
        Mask::Left => Hir::Class(ClassKind::Bracketed(BracketedClass {
            items: (0..=0xF)
                .map(|i| BracketedClassItem::Literal((i << 4) + byte))
                .collect(),
            negated,
        })),
        Mask::Right => {
            let byte = byte << 4;
            Hir::Class(ClassKind::Bracketed(BracketedClass {
                items: vec![BracketedClassItem::Range(byte, byte + 0x0F)],
                negated,
            }))
        }
        Mask::All => Hir::Dot,
    }
}
