use crate::bitmaps::Bitmap;
use boreal_parser::hex_string::{Mask, Token};
use boreal_parser::regex::{
    AssertionKind, BracketedClass, BracketedClassItem, ClassKind, Literal, LiteralChar, Node,
    PerlClass, PerlClassKind, RepetitionKind, RepetitionRange,
};
use std::ops::Range;

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
    Class(Class),

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

/// Class of bytes.
#[derive(Clone, Debug)]
pub struct Class {
    /// Class definition.
    //
    // TODO: This is kept around so that the HIR can be retranslated back into a proper regex
    // string when converting to the regex_automata expressions.
    // This could be removed by either:
    // - converting our HIR into the regex_automata HIR
    // - converting this class into an explicit class with one byte for each bit in the
    //   bitmap. But it would require ensuring this does not cause regressions (it should
    //   not).
    pub definition: ClassKind,

    /// Bitfield of which bytes are in the class.
    pub bitmap: Bitmap,
}

/// Convert a parsed regex AST into our HIR.
///
/// This is quite straightforward, but for one particular transformation: the parsing
/// is unicode aware, while the HIR is bytes only.
///
/// See <https://github.com/VirusTotal/yara/pull/1770#issuecomment-1357622486> for some
/// discussions on this. To be compatible with YARA, we need to accept unicode bytes, but
/// match as if the explicit bytes were provided. This function takes care of that.
// TODO: implement a visitor for the regex ast
pub(crate) fn regex_ast_to_hir(node: Node, warnings: &mut Vec<RegexAstError>) -> Hir {
    match node {
        Node::Alternation(v) => Hir::Alternation(
            v.into_iter()
                .map(|n| regex_ast_to_hir(n, warnings))
                .collect(),
        ),
        Node::Assertion(v) => Hir::Assertion(v),
        Node::Class(definition) => Hir::Class(Class {
            bitmap: class_to_bitmap(&definition, warnings),
            definition,
        }),
        Node::Concat(v) => Hir::Concat(
            v.into_iter()
                .map(|n| regex_ast_to_hir(n, warnings))
                .collect(),
        ),
        Node::Dot => Hir::Dot,
        Node::Empty => Hir::Empty,
        Node::Literal(lit) => {
            let byte = unwrap_literal(&lit, warnings);
            Hir::Literal(byte)
        }
        Node::Group(v) => Hir::Group(Box::new(regex_ast_to_hir(*v, warnings))),
        Node::Repetition { node, kind, greedy } => {
            match *node {
                // This special code is here to normalize the HIR. The issue is that
                // the parsing is unicode aware, but the yara engine is not. So non ascii
                // characters are transformed into the utf-8 representation, which
                // causes an issue with repetitions: when `<char><repetition>` is
                // parsed, what we want to evaluate is
                // `<byte0><byte1>...<byteN><repetition>`, so the repetition only
                // applies on the last byte of the utf-7 representation of the character.
                //
                // We *could* only transform Node::Char into an Hir::Concat
                // of its utf-8 bytes. This however leads to an HIR that is no
                // longer stable through a string representation. For example,
                // take this example:
                //
                // - the regex `ù+` is parsed, giving the AST
                //   `Repetition(Char('ù'), OneOrMore)`.
                // - this is normalized into the HIR
                //   `Repetition(Concat([b'\xC3', b'\xB9']), OneOrMore)`
                // - converting to a string gives `\xC3\xB9+`.
                // - this is parsed and converted into the HIR
                //   `Concat([b'\xC3', Repetition(b'\xB9', OneOrMore))`
                //
                // This attempts to fall into working currently, since we print
                // the HIR to give it to `regex_automata`. But it is extremely
                // flimsy, and could lead to a many bugs, since it means we
                // still work with an HIR that is invalid, since its
                // representation of the regex does not match the matching
                // behavior.
                //
                // This is all to say: we want to normalize the HIR into
                // a stable and faithful representation. Hence this code
                // a bit hacky, where we handle the special
                // "repetition over a char" case, to put the repetition
                // only over the last byte.
                Node::Char(LiteralChar { c, span, escaped }) => {
                    if escaped {
                        warnings.push(RegexAstError::UnknownEscape {
                            span: span.clone(),
                            c,
                        });
                    }
                    warnings.push(RegexAstError::NonAsciiChar { span });

                    let mut enc = vec![0; 4];
                    let _r = c.encode_utf8(&mut enc);
                    let len = c.len_utf8();

                    // Move the repetition to the last char only.
                    let mut concat = Vec::with_capacity(len);
                    for b in &enc[0..(len - 1)] {
                        concat.push(Hir::Literal(*b));
                    }
                    concat.push(Hir::Repetition {
                        hir: Box::new(Hir::Literal(enc[len - 1])),
                        kind,
                        greedy,
                    });
                    Hir::Concat(concat)
                }
                v => Hir::Repetition {
                    hir: Box::new(regex_ast_to_hir(v, warnings)),
                    kind,
                    greedy,
                },
            }
        }
        Node::Char(LiteralChar { c, span, escaped }) => {
            if escaped {
                warnings.push(RegexAstError::UnknownEscape {
                    span: span.clone(),
                    c,
                });
            }
            warnings.push(RegexAstError::NonAsciiChar { span });

            let mut enc = vec![0; 4];
            let res = c.encode_utf8(&mut enc);
            Hir::Concat(res.as_bytes().iter().map(|v| Hir::Literal(*v)).collect())
        }
    }
}

fn unwrap_literal(lit: &Literal, warnings: &mut Vec<RegexAstError>) -> u8 {
    let Literal {
        byte,
        span,
        escaped,
    } = lit;

    if *escaped && !is_meta_character(*byte) {
        warnings.push(RegexAstError::UnknownEscape {
            span: span.clone(),
            c: char::from(*byte),
        });
    }

    *byte
}

fn is_meta_character(byte: u8) -> bool {
    matches!(
        byte,
        b'\\'
            | b'/'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
            | b'-'
    )
}

fn class_to_bitmap(class_kind: &ClassKind, warnings: &mut Vec<RegexAstError>) -> Bitmap {
    match class_kind {
        ClassKind::Perl(p) => perl_class_to_bitmap(p),
        ClassKind::Bracketed(BracketedClass { items, negated }) => {
            let mut bitmap = Bitmap::new();

            for item in items {
                match item {
                    BracketedClassItem::Perl(p) => {
                        bitmap |= perl_class_to_bitmap(p);
                    }
                    BracketedClassItem::Literal(lit) => {
                        let byte = unwrap_literal(lit, warnings);
                        bitmap.set(byte);
                    }
                    BracketedClassItem::Range(lita, litb) => {
                        let a = unwrap_literal(lita, warnings);
                        let b = unwrap_literal(litb, warnings);
                        for c in a..=b {
                            bitmap.set(c);
                        }
                    }
                }
            }

            if *negated {
                bitmap.invert();
            }
            bitmap
        }
    }
}

fn perl_class_to_bitmap(cls: &PerlClass) -> Bitmap {
    let PerlClass { kind, negated } = cls;

    let mut bitmap = Bitmap::new();
    match kind {
        PerlClassKind::Word => {
            for c in b'0'..=b'9' {
                bitmap.set(c);
            }
            for c in b'A'..=b'Z' {
                bitmap.set(c);
            }
            bitmap.set(b'_');
            for c in b'a'..=b'z' {
                bitmap.set(c);
            }
        }
        PerlClassKind::Space => {
            for c in [b'\t', b'\n', b'\x0B', b'\x0C', b'\r', b' '] {
                bitmap.set(c);
            }
        }
        PerlClassKind::Digit => {
            for c in b'0'..=b'9' {
                bitmap.set(c);
            }
        }
    }
    if *negated {
        bitmap.invert();
    }
    bitmap
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
            Token::NotByte(b) => {
                let mut bitmap = Bitmap::new();
                bitmap.set(b);
                bitmap.invert();

                Hir::Class(Class {
                    definition: ClassKind::Bracketed(BracketedClass {
                        items: vec![BracketedClassItem::Literal(Literal {
                            byte: b,
                            span: 0..1,
                            escaped: false,
                        })],
                        negated: true,
                    }),
                    bitmap,
                })
            }
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

/// Errors related to a regex AST.
#[derive(Clone, Debug)]
pub enum RegexAstError {
    /// A non ascii character is present in the regex.
    NonAsciiChar {
        /// Span of the character.
        span: Range<usize>,
    },
    /// An unknown escape sequence is present in the regex.
    UnknownEscape {
        /// Span of the escape sequence.
        span: Range<usize>,

        /// Character equivalent to the sequence, without the escape.
        c: char,
    },
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits(Hir::Empty);
        test_type_traits(Class {
            definition: ClassKind::Perl(PerlClass {
                kind: PerlClassKind::Word,
                negated: false,
            }),
            bitmap: Bitmap::new(),
        });
        test_type_traits(RegexAstError::NonAsciiChar { span: 0..1 });
    }
}
