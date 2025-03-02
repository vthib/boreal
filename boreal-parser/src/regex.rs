//! AST elements related to YARA regexes.
use std::ops::Range;

use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::character::complete::{anychar, char, digit0, digit1, multispace0, none_of};
use nom::combinator::{cut, map, opt};
use nom::multi::many0;
use nom::sequence::{delimited, separated_pair, terminated};
use nom::Parser;

use crate::error::ErrorKind;

use super::error::Error;
use super::nom_recipes::rtrim;
use super::types::{Input, ParseResult};

const MAX_REGEX_RECURSION: usize = 10;

/// A regular expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Regex {
    /// The AST of the regular expression parsed inside the `/` delimiters.
    pub ast: Node,
    /// case insensitive (`i` flag).
    pub case_insensitive: bool,
    /// `.` matches `\n` (`s` flag).
    pub dot_all: bool,

    /// The span of the regex expression
    pub span: Range<usize>,
}

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
    Literal(Literal),

    /// Literal char, not ascii.
    Char(LiteralChar),

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
    /// Space class, i.e. `[\t\n\v\f\r ]`.
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
    Literal(Literal),
    /// Range of bytes.
    Range(Literal, Literal),
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

/// Literal unicode character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralChar {
    /// The unicode character.
    pub c: char,

    /// Position in the input for this char.
    pub span: Range<usize>,

    /// Was the character escaped.
    ///
    /// See `Literal::escaped` for more details on what this means.
    pub escaped: bool,
}

/// Literal byte
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Literal {
    /// Byte value.
    pub byte: u8,

    /// Span of the literal
    pub span: Range<usize>,

    /// Was the byte escaped.
    ///
    /// This is for example true for '\[' or '\.', but not for '\n' or '\xAB'.
    pub escaped: bool,
}

impl PartialOrd for Literal {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.byte.partial_cmp(&other.byte)
    }
}

/// Parse a regex.
///
/// The input is expected to look like `/<regex>/<modifiers>`.
///
/// # Errors
///
/// Returns an error if the parsing fails.
pub fn parse_regex(input: &str) -> Result<Regex, Error> {
    use nom::Finish;

    let input = Input::new(input);
    let (_, res) = regex(input).finish()?;

    Ok(res)
}

/// Parse a regular expression.
///
/// Similar to the _REGEX_ lexical pattern in libyara. but the parsing of the AST is done
/// directly.
///
/// XXX: There is change of behavior from libyara. `\<nul_byte>` was forbidden,
/// but we do not have an issue about this (we do not save the regular expression
/// as a C string). See [Issue #576 in Yara](https://github.com/VirusTotal/yara/issues/576).
pub(crate) fn regex(input: Input) -> ParseResult<Regex> {
    let start = input.pos();
    let (input, _) = char('/').parse(input)?;

    // We cannot use escaped_transform, as it is not an error to use
    // the control character with any char other than `/`.
    let (input, ast) = cut(terminated(alternative, char('/'))).parse(input)?;
    let (input, (no_case, dot_all)) = rtrim((opt(char('i')), opt(char('s')))).parse(input)?;

    Ok((
        input,
        Regex {
            ast,
            case_insensitive: no_case.is_some(),
            dot_all: dot_all.is_some(),
            span: input.get_span_from(start),
        },
    ))
}

fn alternative(mut input: Input) -> ParseResult<Node> {
    // This combinator is recursive:
    //
    // tokens => hex_token => alternatives => tokens
    //
    // Use the inner recursive counter to make sure this recursion cannot grow too much.
    if input.inner_recursion_counter >= MAX_REGEX_RECURSION {
        return Err(nom::Err::Failure(Error::new(
            input.get_span_from(input.pos()),
            ErrorKind::RegexTooDeep,
        )));
    }

    let mut alts = Vec::new();
    loop {
        input.inner_recursion_counter += 1;
        let (mut input2, node) = concatenation(input)?;
        input2.inner_recursion_counter -= 1;

        let (input2, has_alt_char) = eat_opt_char('|', input2);
        if has_alt_char {
            alts.push(node);
            input = input2;
            continue;
        }

        return Ok((
            input2,
            if alts.is_empty() {
                node
            } else {
                alts.push(node);
                Node::Alternation(alts)
            },
        ));
    }
}

fn eat_opt_char(c: char, mut input: Input) -> (Input, bool) {
    match input.cursor().chars().next() {
        Some(c2) if c2 == c => {
            input.advance(c.len_utf8());
            (input, true)
        }
        _ => (input, false),
    }
}

fn concatenation(input: Input) -> ParseResult<Node> {
    let (input, mut nodes) = many0(repeat).parse(input)?;

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
    if let Ok((input, node)) = assertion(input) {
        return Ok((input, node));
    }

    // Otherwise, parse single node with optional repetition
    let (input, node) = single(input)?;
    let (input, repetition) = opt(repetition).parse(input)?;
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
    ))
    .parse(input)
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
    ))
    .parse(input)
}

fn single(input: Input) -> ParseResult<Node> {
    alt((
        map(delimited(char('('), alternative, char(')')), |node| {
            Node::Group(Box::new(node))
        }),
        map(char('.'), |_| Node::Dot),
        map(perl_class, |p| Node::Class(ClassKind::Perl(p))),
        map(bracketed_class, |p| Node::Class(ClassKind::Bracketed(p))),
        escaped_char,
        literal,
    ))
    .parse(input)
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
    ))
    .parse(input)
}

fn bracketed_class(input: Input) -> ParseResult<BracketedClass> {
    let (input, _) = char('[').parse(input)?;
    // As soon as we parse a '[', we are in class mode, hence the cut if parsing fails.
    cut(bracketed_class_inner).parse(input)
}

fn bracketed_class_inner(input: Input) -> ParseResult<BracketedClass> {
    let (input, negated) = eat_opt_char('^', input);
    let start = input.pos();
    let (input2, contains_closing_bracket) = eat_opt_char(']', input);

    let (input, mut items) = many0(bracketed_class_item).parse(input2)?;
    let (input, _) = char(']').parse(input)?;

    if contains_closing_bracket {
        items.push(BracketedClassItem::Literal(Literal {
            byte: b']',
            span: input2.get_span_from_no_rtrim(start),
            escaped: false,
        }));
    }
    Ok((input, BracketedClass { items, negated }))
}

fn bracketed_class_item(input: Input) -> ParseResult<BracketedClassItem> {
    alt((
        map(perl_class, BracketedClassItem::Perl),
        bracketed_class_range_or_literal,
    ))
    .parse(input)
}

fn bracketed_class_range_or_literal(input: Input) -> ParseResult<BracketedClassItem> {
    let start = input.pos();
    let (input, lit) = bracketed_class_literal(input)?;
    let (input2, has_dash) = eat_opt_char('-', input);

    if has_dash {
        let (input3, lit2) = opt(bracketed_class_literal).parse(input2)?;
        match lit2 {
            Some(lit2) if lit2 < lit => Err(nom::Err::Failure(Error::new(
                input3.get_span_from_no_rtrim(start),
                ErrorKind::RegexClassRangeInvalid,
            ))),
            Some(lit2) => Ok((input3, BracketedClassItem::Range(lit, lit2))),
            None => Ok((input, BracketedClassItem::Literal(lit))),
        }
    } else {
        Ok((input, BracketedClassItem::Literal(lit)))
    }
}

fn bracketed_class_literal(input: Input) -> ParseResult<Literal> {
    alt((escaped_char_only_ascii, bracketed_class_char)).parse(input)
}

fn bracketed_class_char(input: Input) -> ParseResult<Literal> {
    let start = input.pos();

    // / and \n are disallowed because of the surrounding rule (we are parsing a /.../ variable,
    // and newlines are not allowed
    // ] is disallowed because it indicates the end of the class
    let (input, b) = none_of("/\n]").parse(input)?;
    if b.is_ascii() {
        Ok((
            input,
            Literal {
                byte: b as u8,
                span: input.get_span_from_no_rtrim(start),
                escaped: false,
            },
        ))
    } else {
        Err(nom::Err::Failure(Error::new(
            input.get_span_from_no_rtrim(start),
            ErrorKind::RegexNonAsciiByte,
        )))
    }
}

fn literal(input: Input) -> ParseResult<Node> {
    let start = input.pos();

    // / and \n are disallowed because of the surrounding rule (we are parsing a /.../ variable,
    // and newlines are not allowed
    // rest is disallowed because they have specific meaning.
    let (input, c) = none_of("/\n()[\\|.$^+*?").parse(input)?;
    let node = if c.is_ascii() {
        Node::Literal(Literal {
            byte: c as u8,
            span: input.get_span_from_no_rtrim(start),
            escaped: false,
        })
    } else {
        Node::Char(LiteralChar {
            c,
            span: input.get_span_from_no_rtrim(start),
            escaped: false,
        })
    };

    Ok((input, node))
}

fn escaped_char(input: Input) -> ParseResult<Node> {
    let (input, res) = escaped_char_inner(input)?;

    let node = match res {
        Escaped {
            kind: EscapedKind::Byte(byte),
            span,
            escaped,
        } => Node::Literal(Literal {
            byte,
            span,
            escaped,
        }),
        Escaped {
            kind: EscapedKind::Char(c),
            span,
            escaped,
        } => Node::Char(LiteralChar { c, span, escaped }),
    };

    Ok((input, node))
}

fn escaped_char_only_ascii(input: Input) -> ParseResult<Literal> {
    let (input, res) = escaped_char_inner(input)?;

    match res {
        Escaped {
            kind: EscapedKind::Byte(byte),
            span,
            escaped,
        } => Ok((
            input,
            Literal {
                byte,
                span,
                escaped,
            },
        )),
        Escaped {
            kind: EscapedKind::Char(_),
            span,
            ..
        } => Err(nom::Err::Failure(Error::new(
            span,
            ErrorKind::RegexNonAsciiByte,
        ))),
    }
}

fn escaped_char_inner(input: Input) -> ParseResult<Escaped> {
    let start = input.pos();
    let (input2, _) = char('\\').parse(input)?;
    let (input, b) = anychar(input2)?;

    let span = input.get_span_from_no_rtrim(start);
    let (kind, escaped) = match b {
        'n' => (EscapedKind::Byte(b'\n'), false),
        't' => (EscapedKind::Byte(b'\t'), false),
        'r' => (EscapedKind::Byte(b'\r'), false),
        'f' => (EscapedKind::Byte(b'\x0C'), false),
        'a' => (EscapedKind::Byte(b'\x07'), false),
        'x' => {
            let (input, n) = cut(take(2_u32)).parse(input)?;

            let n = match u8::from_str_radix(&n, 16) {
                Ok(n) => n,
                Err(e) => {
                    return Err(nom::Err::Failure(Error::new(
                        input.get_span_from_no_rtrim(start),
                        ErrorKind::StrToHexIntError(e),
                    )));
                }
            };
            return Ok((
                input,
                Escaped {
                    kind: EscapedKind::Byte(n),
                    span: input.get_span_from_no_rtrim(start),
                    escaped: false,
                },
            ));
        }
        c if c.is_ascii() => (EscapedKind::Byte(c as u8), true),
        c => (EscapedKind::Char(c), true),
    };

    Ok((
        input,
        Escaped {
            kind,
            span,
            escaped,
        },
    ))
}

struct Escaped {
    kind: EscapedKind,
    span: Range<usize>,
    escaped: bool,
}

#[allow(variant_size_differences)]
enum EscapedKind {
    Byte(u8),
    Char(char),
}

fn range_repetition(input: Input) -> ParseResult<(RepetitionRange, bool)> {
    let (input, range) = alt((range_single, range_multi)).parse(input)?;
    let (input, non_greedy) = eat_opt_char('?', input);

    Ok((input, (range, !non_greedy)))
}

fn range_single(input: Input) -> ParseResult<RepetitionRange> {
    let (input, v) = delimited(char('{'), parse_u32, char('}')).parse(input)?;

    Ok((input, RepetitionRange::Exactly(v)))
}

fn range_multi(input: Input) -> ParseResult<RepetitionRange> {
    let start = input.pos();
    let (input, (from, to)) = delimited(
        char('{'),
        separated_pair(
            parse_opt_u32,
            delimited(multispace0, char(','), multispace0),
            parse_opt_u32,
        ),
        char('}'),
    )
    .parse(input)?;

    let range = match (from, to) {
        (None, None) => RepetitionRange::AtLeast(0),
        (Some(from), None) => RepetitionRange::AtLeast(from),
        (None, Some(to)) => RepetitionRange::Bounded(0, to),
        (Some(from), Some(to)) if to < from => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from_no_rtrim(start),
                ErrorKind::RegexRangeInvalid,
            )))
        }
        (Some(from), Some(to)) => RepetitionRange::Bounded(from, to),
    };

    Ok((input, range))
}

fn parse_u32(input: Input) -> ParseResult<u32> {
    let start = input.pos();
    let (input, v) = digit1(input)?;

    let n = match str::parse::<u32>(&v) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from_no_rtrim(start),
                ErrorKind::StrToIntError(e),
            )))
        }
    };

    Ok((input, n))
}

fn parse_opt_u32(input: Input) -> ParseResult<Option<u32>> {
    let start = input.pos();
    let (input, v) = match digit0::<_, Error>(input) {
        Ok((input, s)) if !s.is_empty() => (input, s),
        _ => return Ok((input, None)),
    };

    let n = match str::parse::<u32>(&v) {
        Ok(n) => n,
        Err(e) => {
            return Err(nom::Err::Failure(Error::new(
                input.get_span_from_no_rtrim(start),
                ErrorKind::StrToIntError(e),
            )))
        }
    };

    Ok((input, Some(n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{parse, parse_err, parse_err_type, test_public_type};

    fn lit(byte: u8, span: Range<usize>, escaped: bool) -> Literal {
        Literal {
            byte,
            span,
            escaped,
        }
    }

    #[test]
    fn test_parse() {
        parse(
            regex,
            "/a/i",
            "",
            Regex {
                ast: Node::Literal(lit(b'a', 1..2, false)),
                case_insensitive: true,
                dot_all: false,
                span: 0..4,
            },
        );
        parse(
            regex,
            "/[^0-9]+/a",
            "a",
            Regex {
                ast: Node::Repetition {
                    node: Box::new(Node::Class(ClassKind::Bracketed(BracketedClass {
                        items: vec![BracketedClassItem::Range(
                            lit(b'0', 3..4, false),
                            lit(b'9', 5..6, false),
                        )],
                        negated: true,
                    }))),
                    kind: RepetitionKind::OneOrMore,
                    greedy: true,
                },
                case_insensitive: false,
                dot_all: false,
                span: 0..9,
            },
        );
        parse(
            regex,
            r"/a\/b\cd/isb",
            "b",
            Regex {
                ast: Node::Concat(vec![
                    Node::Literal(lit(b'a', 1..2, false)),
                    Node::Literal(lit(b'/', 2..4, true)),
                    Node::Literal(lit(b'b', 4..5, false)),
                    Node::Literal(lit(b'c', 5..7, true)),
                    Node::Literal(lit(b'd', 7..8, false)),
                ]),
                case_insensitive: true,
                dot_all: true,
                span: 0..11,
            },
        );
        parse(
            regex,
            r"/.{2}/si c",
            "i c",
            Regex {
                ast: Node::Repetition {
                    node: Box::new(Node::Dot),
                    kind: RepetitionKind::Range(RepetitionRange::Exactly(2)),
                    greedy: true,
                },
                case_insensitive: false,
                dot_all: true,
                span: 0..7,
            },
        );
        parse(
            regex,
            "/\0\\\0/ c",
            "c",
            Regex {
                ast: Node::Concat(vec![
                    Node::Literal(lit(b'\0', 1..2, false)),
                    Node::Literal(lit(b'\0', 2..4, true)),
                ]),
                case_insensitive: false,
                dot_all: false,
                span: 0..5,
            },
        );

        parse_err(regex, "");
        parse_err(regex, "/");
        parse_err(regex, "/\n/");
        parse_err(regex, "/a{2}");
        parse_err(regex, "/a///");
        parse_err(regex, "/a{5,4}/");
    }

    #[test]
    fn test_alternative() {
        parse(alternative, "(", "(", Node::Empty);
        parse(
            alternative,
            "a)",
            ")",
            Node::Literal(lit(b'a', 0..1, false)),
        );
        parse(
            alternative,
            "a|b",
            "",
            Node::Alternation(vec![
                Node::Literal(lit(b'a', 0..1, false)),
                Node::Literal(lit(b'b', 2..3, false)),
            ]),
        );
        parse(
            alternative,
            "a|)",
            ")",
            Node::Alternation(vec![Node::Literal(lit(b'a', 0..1, false)), Node::Empty]),
        );

        parse(
            alternative,
            r"ab|.\||\b$|",
            "",
            Node::Alternation(vec![
                Node::Concat(vec![
                    Node::Literal(lit(b'a', 0..1, false)),
                    Node::Literal(lit(b'b', 1..2, false)),
                ]),
                Node::Concat(vec![Node::Dot, Node::Literal(lit(b'|', 4..6, true))]),
                Node::Concat(vec![
                    Node::Assertion(AssertionKind::WordBoundary),
                    Node::Assertion(AssertionKind::EndLine),
                ]),
                Node::Empty,
            ]),
        );

        parse_err(alternative, "\\xEG");
    }

    #[test]
    fn test_concatenation() {
        parse(concatenation, "", "", Node::Empty);
        parse(
            concatenation,
            "a",
            "",
            Node::Literal(lit(b'a', 0..1, false)),
        );
        parse(
            concatenation,
            "ab",
            "",
            Node::Concat(vec![
                Node::Literal(lit(b'a', 0..1, false)),
                Node::Literal(lit(b'b', 1..2, false)),
            ]),
        );
        parse(
            concatenation,
            "a$*",
            "*",
            Node::Concat(vec![
                Node::Literal(lit(b'a', 0..1, false)),
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
                    node: Box::new(Node::Literal(lit(b'a', 1..2, false))),
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
                        items: vec![BracketedClassItem::Literal(lit(b'z', 14..15, false))],
                        negated: true,
                    }))),
                    kind: RepetitionKind::ZeroOrMore,
                    greedy: false,
                },
            ]),
        );

        parse_err(concatenation, "\\xEG");
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
                Node::Literal(lit(b'a', 1..2, false)),
                Node::Literal(lit(b'b', 2..3, false)),
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
                    BracketedClassItem::Range(lit(b'a', 1..2, false), lit(b'f', 3..4, false)),
                    BracketedClassItem::Range(lit(b'A', 4..5, false), lit(b'F', 6..7, false)),
                ],
                negated: false,
            })),
        );
        parse(
            single,
            r"\xFFa",
            "a",
            Node::Literal(lit(b'\xFF', 0..4, false)),
        );
        parse(single, r"]a", "a", Node::Literal(lit(b']', 0..1, false)));

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
                items: vec![BracketedClassItem::Literal(lit(b'a', 1..2, false))],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[^a-z_\\S0-9]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Range(lit(b'a', 2..3, false), lit(b'z', 4..5, false)),
                    BracketedClassItem::Literal(lit(b'_', 5..6, false)),
                    BracketedClassItem::Perl(PerlClass {
                        kind: PerlClassKind::Space,
                        negated: true,
                    }),
                    BracketedClassItem::Range(lit(b'0', 8..9, false), lit(b'9', 10..11, false)),
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
                    BracketedClassItem::Literal(lit(b'j', 2..4, true)),
                    BracketedClassItem::Literal(lit(b']', 1..2, false)),
                ],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[]]",
            "",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(lit(b']', 1..2, false))],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[^]]",
            "",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(lit(b']', 2..3, false))],
                negated: true,
            },
        );
        parse(
            bracketed_class,
            "[^a\\]b-]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Literal(lit(b'a', 2..3, false)),
                    BracketedClassItem::Literal(lit(b']', 3..5, true)),
                    BracketedClassItem::Literal(lit(b'b', 5..6, false)),
                    BracketedClassItem::Literal(lit(b'-', 6..7, false)),
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
        parse_err(bracketed_class, "[\\é]");
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
            "\\c-z]",
            "]",
            BracketedClassItem::Range(lit(b'c', 0..2, true), lit(b'z', 3..4, false)),
        );

        parse_err(bracketed_class_item, "é");
    }

    #[test]
    fn test_bracketed_class_range_or_literal() {
        parse(
            bracketed_class_range_or_literal,
            "ab",
            "b",
            BracketedClassItem::Literal(lit(b'a', 0..1, false)),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\x01-",
            "-",
            BracketedClassItem::Literal(lit(b'\x01', 0..4, false)),
        );
        parse(
            bracketed_class_range_or_literal,
            "-\\]",
            "\\]",
            BracketedClassItem::Literal(lit(b'-', 0..1, false)),
        );
        parse(
            bracketed_class_range_or_literal,
            "A-]",
            "-]",
            BracketedClassItem::Literal(lit(b'A', 0..1, false)),
        );

        parse(
            bracketed_class_range_or_literal,
            "a-\\sb",
            "b",
            BracketedClassItem::Range(lit(b'a', 0..1, false), lit(b's', 2..4, true)),
        );
        parse(
            bracketed_class_range_or_literal,
            "!--",
            "",
            BracketedClassItem::Range(lit(b'!', 0..1, false), lit(b'-', 2..3, false)),
        );
        parse(
            bracketed_class_range_or_literal,
            "---",
            "",
            BracketedClassItem::Range(lit(b'-', 0..1, false), lit(b'-', 2..3, false)),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\n-\n",
            "",
            BracketedClassItem::Range(lit(b'\n', 0..2, false), lit(b'\n', 3..5, false)),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\x01-\xFE",
            "",
            BracketedClassItem::Range(lit(b'\x01', 0..4, false), lit(b'\xFE', 5..9, false)),
        );

        parse_err(bracketed_class_range_or_literal, "é");
        parse_err(bracketed_class_range_or_literal, "b-a");
        parse_err(bracketed_class_range_or_literal, "é-a");
        parse_err(bracketed_class_range_or_literal, "a-é");
        parse_err(bracketed_class_range_or_literal, "]-a");
    }

    #[test]
    fn test_bracketed_class_literal() {
        parse(bracketed_class_literal, "ab", "b", lit(b'a', 0..1, false));
        parse(
            bracketed_class_literal,
            "\\nb",
            "b",
            lit(b'\n', 0..2, false),
        );
        parse(bracketed_class_literal, "\\]", "", lit(b']', 0..2, true));

        parse_err(bracketed_class_literal, "]b");
        parse_err(bracketed_class_literal, "é");
        parse_err(bracketed_class_literal, "\\x1");
        parse_err(bracketed_class_literal, "\\é");
    }

    #[test]
    fn test_bracketed_class_char() {
        parse(bracketed_class_char, "ab", "b", lit(b'a', 0..1, false));

        parse_err(bracketed_class_char, "]b");
        parse_err(bracketed_class_char, "é");
    }

    #[test]
    fn test_literal() {
        parse(literal, "ab", "b", Node::Literal(lit(b'a', 0..1, false)));
        parse(literal, "]", "", Node::Literal(lit(b']', 0..1, false)));

        parse(
            literal,
            "éb",
            "b",
            Node::Char(LiteralChar {
                c: 'é',
                span: 0..2,
                escaped: false,
            }),
        );
    }

    #[test]
    fn test_escaped_char() {
        parse(
            escaped_char,
            "\\na",
            "a",
            Node::Literal(lit(b'\n', 0..2, false)),
        );
        parse(
            escaped_char,
            "\\ta",
            "a",
            Node::Literal(lit(b'\t', 0..2, false)),
        );
        parse(
            escaped_char,
            "\\ra",
            "a",
            Node::Literal(lit(b'\r', 0..2, false)),
        );
        parse(
            escaped_char,
            "\\fa",
            "a",
            Node::Literal(lit(b'\x0C', 0..2, false)),
        );
        parse(
            escaped_char,
            "\\aa",
            "a",
            Node::Literal(lit(b'\x07', 0..2, false)),
        );
        parse(
            escaped_char,
            "\\x00a",
            "a",
            Node::Literal(lit(b'\0', 0..4, false)),
        );
        parse(
            escaped_char,
            "\\xAF a",
            " a",
            Node::Literal(lit(b'\xAF', 0..4, false)),
        );
        parse(
            escaped_char,
            "\\k",
            "",
            Node::Literal(lit(b'k', 0..2, true)),
        );
        parse(
            escaped_char,
            "\\é_",
            "_",
            Node::Char(LiteralChar {
                c: 'é',
                span: 0..3,
                escaped: true,
            }),
        );

        parse_err(escaped_char, "\\");
        parse_err(escaped_char, "\\x");
        parse_err(escaped_char, "\\x2");
        parse_err(escaped_char, "\\x2G");
    }

    #[test]
    fn test_escaped_char_only_ascii() {
        parse(
            escaped_char_only_ascii,
            "\\na",
            "a",
            lit(b'\n', 0..2, false),
        );
        parse(
            escaped_char_only_ascii,
            "\\ta",
            "a",
            lit(b'\t', 0..2, false),
        );
        parse(
            escaped_char_only_ascii,
            "\\ra",
            "a",
            lit(b'\r', 0..2, false),
        );
        parse(
            escaped_char_only_ascii,
            "\\fa",
            "a",
            lit(b'\x0C', 0..2, false),
        );
        parse(
            escaped_char_only_ascii,
            "\\aa",
            "a",
            lit(b'\x07', 0..2, false),
        );
        parse(
            escaped_char_only_ascii,
            "\\x00a",
            "a",
            lit(b'\0', 0..4, false),
        );
        parse(
            escaped_char_only_ascii,
            "\\xAF a",
            " a",
            lit(b'\xAF', 0..4, false),
        );
        parse(escaped_char_only_ascii, "\\k", "", lit(b'k', 0..2, true));

        parse_err(escaped_char_only_ascii, "\\");
        parse_err(escaped_char_only_ascii, "\\é");
        parse_err(escaped_char_only_ascii, "\\x");
        parse_err(escaped_char_only_ascii, "\\x2");
        parse_err(escaped_char_only_ascii, "\\x2G");
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
        parse(range_multi, "{,}", "", RepetitionRange::AtLeast(0));
        parse(range_multi, "{, }", "", RepetitionRange::AtLeast(0));
        parse(range_multi, "{ ,}", "", RepetitionRange::AtLeast(0));
        parse(range_multi, "{ , }", "", RepetitionRange::AtLeast(0));
        parse(range_multi, "{2 , }", "", RepetitionRange::AtLeast(2));
        parse(range_multi, "{ , 2}", "", RepetitionRange::Bounded(0, 2));
        parse(range_multi, "{1 , 2}", "", RepetitionRange::Bounded(1, 2));

        parse_err(range_multi, "{");
        parse_err(range_multi, "{,5");
        parse_err(range_multi, "{,-5}");
        parse_err(range_multi, "{-5,}");
        parse_err(range_multi, "{10,5}");
        parse_err(range_multi, "{ 1,5}");
        parse_err(range_multi, "{1,5 }");
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

    #[test]
    fn test_stack_overflow() {
        // Parsing of a regex includes recursion, so it must be protected against
        // stack overflowing.
        let mut v = String::new();
        v.push('/');
        for _ in 0..1_000 {
            v.push_str("a(b");
        }
        for _ in 0..1_000 {
            v.push_str(")c");
        }
        v.push('/');

        parse_err_type(regex, &v, &Error::new(30..30, ErrorKind::RegexTooDeep));

        // counter should reset, so many imbricated groups, but all below the limit should be fine.
        let mut v = String::new();
        v.push('/');
        let nb = MAX_REGEX_RECURSION - 1;
        for _ in 0..nb {
            v.push_str("a(b");
        }
        for _ in 0..nb {
            v.push_str(")c");
        }
        v.push('d');
        for _ in 0..nb {
            v.push_str("e(f");
        }
        for _ in 0..nb {
            v.push_str(")h");
        }
        v.push('/');

        let input = Input::new(&v);
        let _res = regex(input).unwrap();
        assert_eq!(input.inner_recursion_counter, 0);
    }

    #[test]
    fn test_parse_regex() {
        assert!(parse_regex(r"/a{2}/").is_ok());
        assert!(parse_regex(r"a{2}/").is_err());
    }

    #[test]
    fn test_public_types() {
        test_public_type(regex(Input::new(r"/a{2}[az]\b\s|.+$/")).unwrap());
    }
}
