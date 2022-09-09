//! Parsing related to strings, regexes and identifiers.
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{anychar, char, digit0, digit1, none_of},
    combinator::{cut, map, opt},
    multi::many0,
    sequence::{delimited, separated_pair},
};

use crate::error::{Error, ErrorKind};
use crate::types::{Input, ParseResult};

/// AST node of a regular expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// Alternation of nodes, ie `node|node|...`.
    Alternation(Vec<Node>),

    /// Zero-width assertion, e.g. ^, \b, ...
    Assertion(AssertionKind),

    /// Set of allowed values for a single byte.
    Class(ClassKind),

    /// Concatenation, must match in order.
    Concat(Vec<Node>),

    /// The special `.` character.
    Dot,

    /// Empty expression.
    Empty,

    /// Literal byte.
    Literal(u8),

    /// A group, i.e. (...).
    Group(Box<Node>),

    /// Repetition of an expression.
    Repetition {
        /// Expression to repeat.
        node: Box<Node>,

        /// Kind of repetition.
        kind: RepetitionKind,

        /// Is the repetition greedy or not.
        greedy: bool,
    },
}

/// Regex class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassKind {
    /// Perl style class, e.g. `\w`, `\d`.
    Perl(PerlClass),
    /// Bracket class, i.e. `[...]`.
    Bracketed(BracketedClass),
}

/// PERL style class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerlClass {
    /// Class kind.
    pub kind: PerlClassKind,
    /// Is the class negated.
    pub negated: bool,
}

/// Kind of PERL style class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerlClassKind {
    /// Word class, i.e. `[a-zA-Z0-9_]`.
    Word,
    /// Space class, i.e. `[\t\n\r\f]`.
    Space,
    /// Digit class, i.e. `[0-9]`.
    Digit,
}

/// Class expressed in brackets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BracketedClass {
    /// List of items in the class.
    pub items: Vec<BracketedClassItem>,
    /// Is the class negated.
    pub negated: bool,
}

/// Item in a bracketed class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BracketedClassItem {
    /// Perl style class.
    Perl(PerlClass),
    /// Literal byte.
    Literal(u8),
    /// Range of bytes.
    Range(u8, u8),
}

/// Kind of repetition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepetitionKind {
    /// zero or one, i.e. `?`
    ZeroOrOne,
    /// zero or more, i.e. `*`
    ZeroOrMore,
    /// one or more, i.e. `+`
    OneOrMore,
    /// Range, i.e. `{N}`, `{N,M}`, etc.
    Range(RepetitionRange),
}

/// Repetition range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepetitionRange {
    /// Exactly the given number, i.e. `{N}`.
    Exactly(u32),
    /// At least the given number, i.e. `{N,}`.
    AtLeast(u32),
    /// Between two numbers, i.e. `{N,M}`.
    Bounded(u32, u32),
}

/// Kind of zero-width assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssertionKind {
    /// Start of the line, i.e. `^`.
    StartLine,
    /// End of the line, i.e. `$`.
    EndLine,
    /// Word boundary, i.e. `\b`.
    WordBoundary,
    /// Non word boundary, i.e. `\B`.
    NonWordBoundary,
}

pub(super) fn alternative(mut input: Input) -> ParseResult<Node> {
    let mut alts = Vec::new();

    loop {
        let (input2, node) = concatenation(input)?;
        let (input2, alt_char) = opt(char('|'))(input2)?;
        if alt_char.is_none() {
            if alts.is_empty() {
                return Ok((input2, node));
            }
            alts.push(node);
            return Ok((input2, Node::Alternation(alts)));
        }
        alts.push(node);
        input = input2;
    }
}

fn concatenation(input: Input) -> ParseResult<Node> {
    let (input, mut nodes) = many0(repeat)(input)?;

    let node = if nodes.is_empty() {
        Node::Empty
    } else if nodes.len() == 1 {
        nodes.pop().unwrap()
    } else {
        Node::Concat(nodes)
    };

    Ok((input, node))
}

fn repeat(input: Input) -> ParseResult<Node> {
    // First, parse assertions
    let (input, node) = opt(assertion)(input)?;
    if let Some(node) = node {
        return Ok((input, node));
    }

    // Otherwise, parse single node with optional repetition
    let (input, node) = single(input)?;
    let (input, repetition) = opt(repetition)(input)?;
    match repetition {
        Some((kind, greedy)) => Ok((
            input,
            Node::Repetition {
                node: Box::new(node),
                kind,
                greedy,
            },
        )),
        None => Ok((input, node)),
    }
}

// Parse node that contains a repetition, or nodes that cannot be repeated
fn assertion(input: Input) -> ParseResult<Node> {
    alt((
        map(tag(r"\b"), |_| Node::Assertion(AssertionKind::WordBoundary)),
        map(tag(r"\B"), |_| {
            Node::Assertion(AssertionKind::NonWordBoundary)
        }),
        map(char('^'), |_| Node::Assertion(AssertionKind::StartLine)),
        map(char('$'), |_| Node::Assertion(AssertionKind::EndLine)),
    ))(input)
}

fn repetition(input: Input) -> ParseResult<(RepetitionKind, bool)> {
    alt((
        map(tag("*?"), |_| (RepetitionKind::ZeroOrMore, false)),
        map(tag("+?"), |_| (RepetitionKind::OneOrMore, false)),
        map(tag("??"), |_| (RepetitionKind::ZeroOrOne, false)),
        map(tag("*"), |_| (RepetitionKind::ZeroOrMore, true)),
        map(tag("+"), |_| (RepetitionKind::OneOrMore, true)),
        map(tag("?"), |_| (RepetitionKind::ZeroOrOne, true)),
        map(range_repetition, |(kind, greedy)| {
            (RepetitionKind::Range(kind), greedy)
        }),
    ))(input)
}

fn single(input: Input) -> ParseResult<Node> {
    alt((
        map(delimited(char('('), alternative, char(')')), |node| {
            Node::Group(Box::new(node))
        }),
        map(char('.'), |_| Node::Dot),
        map(perl_class, |p| Node::Class(ClassKind::Perl(p))),
        map(bracketed_class, |p| Node::Class(ClassKind::Bracketed(p))),
        map(escaped_char, Node::Literal),
        map(literal, Node::Literal),
    ))(input)
}

fn perl_class(input: Input) -> ParseResult<PerlClass> {
    alt((
        map(tag(r"\w"), |_| PerlClass {
            kind: PerlClassKind::Word,
            negated: false,
        }),
        map(tag(r"\W"), |_| PerlClass {
            kind: PerlClassKind::Word,
            negated: true,
        }),
        map(tag(r"\s"), |_| PerlClass {
            kind: PerlClassKind::Space,
            negated: false,
        }),
        map(tag(r"\S"), |_| PerlClass {
            kind: PerlClassKind::Space,
            negated: true,
        }),
        map(tag(r"\d"), |_| PerlClass {
            kind: PerlClassKind::Digit,
            negated: false,
        }),
        map(tag(r"\D"), |_| PerlClass {
            kind: PerlClassKind::Digit,
            negated: true,
        }),
    ))(input)
}

fn bracketed_class(input: Input) -> ParseResult<BracketedClass> {
    let (input, _) = char('[')(input)?;
    // As soon as we parse a '[', we are in class mode, hence the cut if parsing fails.
    cut(bracketed_class_inner)(input)
}

fn bracketed_class_inner(input: Input) -> ParseResult<BracketedClass> {
    let (input, negated) = opt(char('^'))(input)?;
    let (input, contains_closing_bracket) = opt(char(']'))(input)?;

    let (input, mut items) = many0(bracketed_class_item)(input)?;
    let (input, _) = char(']')(input)?;

    if contains_closing_bracket.is_some() {
        items.push(BracketedClassItem::Literal(b']'));
    }
    Ok((
        input,
        BracketedClass {
            items,
            negated: negated.is_some(),
        },
    ))
}

fn bracketed_class_item(input: Input) -> ParseResult<BracketedClassItem> {
    alt((
        map(perl_class, BracketedClassItem::Perl),
        bracketed_class_range_or_literal,
    ))(input)
}

fn bracketed_class_range_or_literal(input: Input) -> ParseResult<BracketedClassItem> {
    let start = input;
    let (input, lit) = bracketed_class_literal(input)?;
    let (input2, dash) = opt(char('-'))(input)?;

    match dash {
        Some(_) => {
            let (input3, lit2) = opt(bracketed_class_literal)(input2)?;
            match lit2 {
                Some(lit2) if lit2 < lit => Err(nom::Err::Failure(Error::new(
                    input.get_span_from(start),
                    ErrorKind::RegexClassRangeInvalid,
                ))),
                Some(lit2) => Ok((input3, BracketedClassItem::Range(lit, lit2))),
                None => Ok((input, BracketedClassItem::Literal(lit))),
            }
        }
        None => Ok((input, BracketedClassItem::Literal(lit))),
    }
}

fn bracketed_class_literal(input: Input) -> ParseResult<u8> {
    alt((escaped_char, bracketed_class_char))(input)
}

fn bracketed_class_char(input: Input) -> ParseResult<u8> {
    let start = input;

    // / and \n are disallowed because of the surrounding rule (we are parsing a /.../ variable,
    // and newlines are not allowed
    // ] is disallowed because it indicates the end of the class
    let (input, b) = none_of("/\n]")(input)?;
    let b = char_to_u8(b)
        .map_err(|kind| nom::Err::Failure(Error::new(input.get_span_from(start), kind)))?;

    Ok((input, b))
}

fn literal(input: Input) -> ParseResult<u8> {
    let start = input;

    // / and \n are disallowed because of the surrounding rule (we are parsing a /.../ variable,
    // and newlines are not allowed
    // rest is disallowed because they have specific meaning.
    let (input, b) = none_of("/\n()[\\|.$^+*?")(input)?;
    let b = char_to_u8(b)
        .map_err(|kind| nom::Err::Failure(Error::new(input.get_span_from(start), kind)))?;

    Ok((input, b))
}

fn escaped_char(input: Input) -> ParseResult<u8> {
    let start = input;
    let (input2, _) = char('\\')(input)?;
    let (input, b) = anychar(input2)?;

    let c = match b {
        'n' => b'\n',
        't' => b'\t',
        'r' => b'\r',
        'f' => b'\x0C',
        'a' => b'\x07',
        'x' => {
            let (input, n) = cut(take(2_u32))(input)?;

            let n = match u8::from_str_radix(&n, 16) {
                Ok(n) => n,
                Err(e) => {
                    return Err(nom::Err::Failure(Error::new(
                        input.get_span_from(start),
                        ErrorKind::StrToHexIntError(e),
                    )));
                }
            };
            return Ok((input, n));
        }
        _ => char_to_u8(b)
            .map_err(|kind| nom::Err::Failure(Error::new(input.get_span_from(input2), kind)))?,
    };

    Ok((input, c))
}

fn char_to_u8(c: char) -> Result<u8, ErrorKind> {
    if c.is_ascii() {
        Ok(c as u8)
    } else {
        Err(ErrorKind::RegexNonAsciiByte)
    }
}

fn range_repetition(input: Input) -> ParseResult<(RepetitionRange, bool)> {
    let (input, range) = alt((range_single, range_multi))(input)?;
    let (input, non_greedy) = opt(char('?'))(input)?;

    Ok((input, (range, non_greedy.is_none())))
}

fn range_single(input: Input) -> ParseResult<RepetitionRange> {
    let (input, v) = delimited(char('{'), parse_u32, char('}'))(input)?;

    Ok((input, RepetitionRange::Exactly(v)))
}

fn range_multi(input: Input) -> ParseResult<RepetitionRange> {
    let start = input;
    let (input, (from, to)) = delimited(
        char('{'),
        separated_pair(parse_opt_u32, char(','), parse_opt_u32),
        char('}'),
    )(input)?;

    let range = match (from, to) {
        (None, None) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::RegexRangeEmpty,
            )))
        }
        (Some(from), None) => RepetitionRange::AtLeast(from),
        (None, Some(to)) => RepetitionRange::Bounded(0, to),
        (Some(from), Some(to)) if to < from => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::RegexRangeInvalid,
            )))
        }
        (Some(from), Some(to)) => RepetitionRange::Bounded(from, to),
    };

    Ok((input, range))
}

fn parse_u32(input: Input) -> ParseResult<u32> {
    let start = input;
    let (input, v) = digit1(input)?;

    let n = match str::parse::<u32>(&v) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::StrToIntError(e),
            )))
        }
    };

    Ok((input, n))
}

fn parse_opt_u32(input: Input) -> ParseResult<Option<u32>> {
    let start = input;
    let (input, v) = digit0(input)?;

    if v.is_empty() {
        return Ok((input, None));
    }

    let n = match str::parse::<u32>(&v) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                ErrorKind::StrToIntError(e),
            )))
        }
    };

    Ok((input, Some(n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{parse, parse_err};

    #[test]
    fn test_alternative() {
        parse(alternative, "(", "(", Node::Empty);
        parse(alternative, "a)", ")", Node::Literal(b'a'));
        parse(
            alternative,
            "a|b",
            "",
            Node::Alternation(vec![Node::Literal(b'a'), Node::Literal(b'b')]),
        );
        parse(
            alternative,
            "a|)",
            ")",
            Node::Alternation(vec![Node::Literal(b'a'), Node::Empty]),
        );

        parse(
            alternative,
            r"ab|.\||\b$|",
            "",
            Node::Alternation(vec![
                Node::Concat(vec![Node::Literal(b'a'), Node::Literal(b'b')]),
                Node::Concat(vec![Node::Dot, Node::Literal(b'|')]),
                Node::Concat(vec![
                    Node::Assertion(AssertionKind::WordBoundary),
                    Node::Assertion(AssertionKind::EndLine),
                ]),
                Node::Empty,
            ]),
        );

        parse_err(alternative, "é");
    }

    #[test]
    fn test_concatenation() {
        parse(concatenation, "", "", Node::Empty);
        parse(concatenation, "a", "", Node::Literal(b'a'));
        parse(
            concatenation,
            "ab",
            "",
            Node::Concat(vec![Node::Literal(b'a'), Node::Literal(b'b')]),
        );
        parse(
            concatenation,
            "a$*",
            "*",
            Node::Concat(vec![
                Node::Literal(b'a'),
                Node::Assertion(AssertionKind::EndLine),
            ]),
        );
        parse(
            concatenation,
            r"^a+\b\d{2,3}[^z]*?)",
            ")",
            Node::Concat(vec![
                Node::Assertion(AssertionKind::StartLine),
                Node::Repetition {
                    node: Box::new(Node::Literal(b'a')),
                    kind: RepetitionKind::OneOrMore,
                    greedy: true,
                },
                Node::Assertion(AssertionKind::WordBoundary),
                Node::Repetition {
                    node: Box::new(Node::Class(ClassKind::Perl(PerlClass {
                        kind: PerlClassKind::Digit,
                        negated: false,
                    }))),
                    kind: RepetitionKind::Range(RepetitionRange::Bounded(2, 3)),
                    greedy: true,
                },
                Node::Repetition {
                    node: Box::new(Node::Class(ClassKind::Bracketed(BracketedClass {
                        items: vec![BracketedClassItem::Literal(b'z')],
                        negated: true,
                    }))),
                    kind: RepetitionKind::ZeroOrMore,
                    greedy: false,
                },
            ]),
        );

        parse_err(concatenation, "é");
    }

    #[test]
    fn test_assertion() {
        parse(
            assertion,
            r"\ba",
            "a",
            Node::Assertion(AssertionKind::WordBoundary),
        );
        parse(
            assertion,
            r"\B ",
            " ",
            Node::Assertion(AssertionKind::NonWordBoundary),
        );
        parse(
            assertion,
            r"^^",
            "^",
            Node::Assertion(AssertionKind::StartLine),
        );
        parse(
            assertion,
            r"$^",
            "^",
            Node::Assertion(AssertionKind::EndLine),
        );

        parse_err(assertion, r"\w");
    }

    #[test]
    fn test_repetition() {
        parse(repetition, "*??", "?", (RepetitionKind::ZeroOrMore, false));
        parse(repetition, "+??", "?", (RepetitionKind::OneOrMore, false));
        parse(repetition, "???", "?", (RepetitionKind::ZeroOrOne, false));
        parse(repetition, "*a?", "a?", (RepetitionKind::ZeroOrMore, true));
        parse(repetition, "+a?", "a?", (RepetitionKind::OneOrMore, true));
        parse(repetition, "?a?", "a?", (RepetitionKind::ZeroOrOne, true));
        parse(
            repetition,
            "{5}??",
            "?",
            (RepetitionKind::Range(RepetitionRange::Exactly(5)), false),
        );

        parse_err(repetition, "5");
    }

    #[test]
    fn test_single() {
        parse(single, ".a", "a", Node::Dot);
        parse(single, "()a", "a", Node::Group(Box::new(Node::Empty)));
        parse(
            single,
            "(ab)a",
            "a",
            Node::Group(Box::new(Node::Concat(vec![
                Node::Literal(b'a'),
                Node::Literal(b'b'),
            ]))),
        );
        parse(
            single,
            r"\s",
            "",
            Node::Class(ClassKind::Perl(PerlClass {
                kind: PerlClassKind::Space,
                negated: false,
            })),
        );
        parse(
            single,
            r"[a-fA-F] ",
            " ",
            Node::Class(ClassKind::Bracketed(BracketedClass {
                items: vec![
                    BracketedClassItem::Range(b'a', b'f'),
                    BracketedClassItem::Range(b'A', b'F'),
                ],
                negated: false,
            })),
        );
        parse(single, r"\xFFa", "a", Node::Literal(b'\xFF'));
        parse(single, r"]a", "a", Node::Literal(b']'));

        parse_err(single, "");
        parse_err(single, "(");
        parse_err(single, ")");
        parse_err(single, "[");
        parse_err(single, "|");
        parse_err(single, "$");
        parse_err(single, "^");
        parse_err(single, "+");
        parse_err(single, "*");
        parse_err(single, "?");
        parse_err(single, "(a");
    }

    #[test]
    fn test_perl_class() {
        parse(
            perl_class,
            r"\w ",
            " ",
            PerlClass {
                kind: PerlClassKind::Word,
                negated: false,
            },
        );
        parse(
            perl_class,
            r"\Wa",
            "a",
            PerlClass {
                kind: PerlClassKind::Word,
                negated: true,
            },
        );
        parse(
            perl_class,
            r"\s",
            "",
            PerlClass {
                kind: PerlClassKind::Space,
                negated: false,
            },
        );
        parse(
            perl_class,
            r"\S\",
            "\\",
            PerlClass {
                kind: PerlClassKind::Space,
                negated: true,
            },
        );
        parse(
            perl_class,
            r"\d",
            "",
            PerlClass {
                kind: PerlClassKind::Digit,
                negated: false,
            },
        );
        parse(
            perl_class,
            r"\Da",
            "a",
            PerlClass {
                kind: PerlClassKind::Digit,
                negated: true,
            },
        );

        parse_err(perl_class, "");
        parse_err(perl_class, "\\");
        parse_err(perl_class, "\\k");
    }

    #[test]
    fn test_bracketed_class() {
        parse(
            bracketed_class,
            "[a]b",
            "b",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(b'a')],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[^a-z_\\S0-9]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Range(b'a', b'z'),
                    BracketedClassItem::Literal(b'_'),
                    BracketedClassItem::Perl(PerlClass {
                        kind: PerlClassKind::Space,
                        negated: true,
                    }),
                    BracketedClassItem::Range(b'0', b'9'),
                ],
                negated: true,
            },
        );
        parse(
            bracketed_class,
            "[]\\j]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Literal(b'j'),
                    BracketedClassItem::Literal(b']'),
                ],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[]]",
            "",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(b']')],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[^]]",
            "",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(b']')],
                negated: true,
            },
        );
        parse(
            bracketed_class,
            "[^a\\]b-]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Literal(b'a'),
                    BracketedClassItem::Literal(b']'),
                    BracketedClassItem::Literal(b'b'),
                    BracketedClassItem::Literal(b'-'),
                ],
                negated: true,
            },
        );

        parse_err(bracketed_class, "[");
        parse_err(bracketed_class, "[]");
        parse_err(bracketed_class, "[^]");
        parse_err(bracketed_class, "[é]");
        parse_err(bracketed_class, "[\\]");
        parse_err(bracketed_class, "[\\x]");
        parse_err(bracketed_class, "[\\x0]");
    }

    #[test]
    fn test_bracketed_class_item() {
        parse(
            bracketed_class_item,
            "\\sw",
            "w",
            BracketedClassItem::Perl(PerlClass {
                kind: PerlClassKind::Space,
                negated: false,
            }),
        );
        parse(
            bracketed_class_item,
            "a-z]",
            "]",
            BracketedClassItem::Range(b'a', b'z'),
        );

        parse_err(bracketed_class_item, "é");
    }

    #[test]
    fn test_bracketed_class_range_or_literal() {
        parse(
            bracketed_class_range_or_literal,
            "ab",
            "b",
            BracketedClassItem::Literal(b'a'),
        );
        parse(
            bracketed_class_range_or_literal,
            "\x01-",
            "-",
            BracketedClassItem::Literal(b'\x01'),
        );
        parse(
            bracketed_class_range_or_literal,
            "-\\]",
            "\\]",
            BracketedClassItem::Literal(b'-'),
        );
        parse(
            bracketed_class_range_or_literal,
            "A-]",
            "-]",
            BracketedClassItem::Literal(b'A'),
        );

        parse(
            bracketed_class_range_or_literal,
            "a-\\sb",
            "b",
            BracketedClassItem::Range(b'a', b's'),
        );
        parse(
            bracketed_class_range_or_literal,
            "!--",
            "",
            BracketedClassItem::Range(b'!', b'-'),
        );
        parse(
            bracketed_class_range_or_literal,
            "---",
            "",
            BracketedClassItem::Range(b'-', b'-'),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\n-\n",
            "",
            BracketedClassItem::Range(b'\n', b'\n'),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\x01-\xFE",
            "",
            BracketedClassItem::Range(b'\x01', b'\xFE'),
        );

        parse_err(bracketed_class_range_or_literal, "é");
        parse_err(bracketed_class_range_or_literal, "b-a");
        parse_err(bracketed_class_range_or_literal, "é-a");
        parse_err(bracketed_class_range_or_literal, "a-é");
        parse_err(bracketed_class_range_or_literal, "]-a");
    }

    #[test]
    fn test_bracketed_class_literal() {
        parse(bracketed_class_literal, "ab", "b", b'a');
        parse(bracketed_class_literal, "\\nb", "b", b'\n');
        parse(bracketed_class_literal, "\\]", "", b']');

        parse_err(bracketed_class_literal, "]b");
        parse_err(bracketed_class_literal, "é");
        parse_err(bracketed_class_literal, "\\x1");
    }

    #[test]
    fn test_bracketed_class_char() {
        parse(bracketed_class_char, "ab", "b", b'a');

        parse_err(bracketed_class_char, "]b");
        parse_err(bracketed_class_char, "é");
    }

    #[test]
    fn test_literal() {
        parse(literal, "ab", "b", b'a');
        parse(literal, "]", "", b']');

        parse_err(literal, "é");
    }

    #[test]
    fn test_escaped_char() {
        parse(escaped_char, "\\na", "a", b'\n');
        parse(escaped_char, "\\ta", "a", b'\t');
        parse(escaped_char, "\\ra", "a", b'\r');
        parse(escaped_char, "\\fa", "a", b'\x0C');
        parse(escaped_char, "\\aa", "a", b'\x07');
        parse(escaped_char, "\\x00a", "a", b'\0');
        parse(escaped_char, "\\xAF a", " a", b'\xAF');
        parse(escaped_char, "\\k", "", b'k');

        parse_err(escaped_char, "\\");
        parse_err(escaped_char, "\\é");
        parse_err(escaped_char, "\\x");
        parse_err(escaped_char, "\\x2");
        parse_err(escaped_char, "\\x2G");
    }

    #[test]
    fn test_char_to_u8() {
        assert_eq!(char_to_u8('(').unwrap(), b'(');
        assert!(char_to_u8('é').is_err());
    }

    #[test]
    fn test_range_repetition() {
        parse(
            range_repetition,
            "{0} ?a",
            " ?a",
            (RepetitionRange::Exactly(0), true),
        );
        parse(
            range_repetition,
            "{5}?a",
            "a",
            (RepetitionRange::Exactly(5), false),
        );

        parse(
            range_repetition,
            "{5,15} a",
            " a",
            (RepetitionRange::Bounded(5, 15), true),
        );
        parse(
            range_repetition,
            "{5,}?a",
            "a",
            (RepetitionRange::AtLeast(5), false),
        );

        parse_err(range_repetition, "{}?");
    }

    #[test]
    fn test_range_single() {
        parse(range_single, "{0}a", "a", RepetitionRange::Exactly(0));
        parse(range_single, "{350} a", " a", RepetitionRange::Exactly(350));

        parse_err(range_single, "{");
        parse_err(range_single, "{}");
        parse_err(range_single, "{-5}");
    }

    #[test]
    fn test_range_multi() {
        parse(range_multi, "{,5}a", "a", RepetitionRange::Bounded(0, 5));
        parse(range_multi, "{5,}a", "a", RepetitionRange::AtLeast(5));
        parse(range_multi, "{5,10}a", "a", RepetitionRange::Bounded(5, 10));
        parse(range_multi, "{0,0} a", " a", RepetitionRange::Bounded(0, 0));

        parse_err(range_multi, "{");
        parse_err(range_multi, "{,}");
        parse_err(range_multi, "{,5");
        parse_err(range_multi, "{,-5}");
        parse_err(range_multi, "{-5,}");
        parse_err(range_multi, "{10,5}");
    }

    #[test]
    fn test_parse_u32() {
        parse(parse_u32, "5a", "a", 5_u32);

        parse_err(parse_u32, "a");
        parse_err(parse_u32, "-5a");
        parse_err(parse_u32, "5000000000000");
    }

    #[test]
    fn test_parse_opt_u32() {
        parse(parse_opt_u32, "a", "a", None);
        parse(parse_opt_u32, "5a", "a", Some(5));
        parse(parse_opt_u32, "-5a", "-5a", None);

        parse_err(parse_opt_u32, "5000000000000");
    }
}