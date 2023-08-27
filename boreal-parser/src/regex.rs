//! AST elements related to YARA regexes.
use std::ops::Range;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{anychar, char, digit0, digit1, none_of},
    combinator::{cut, map, opt},
    multi::many0,
    sequence::{delimited, separated_pair, terminated, tuple},
};

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
}

/// Literal byte
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Literal {
    /// byte value.
    pub byte: u8,
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
    let (input, _) = char('/')(input)?;

    // We cannot use escaped_transform, as it is not an error to use
    // the control character with any char other than `/`.
    let (input, ast) = cut(terminated(alternative, char('/')))(input)?;
    let (input, (no_case, dot_all)) = rtrim(tuple((opt(char('i')), opt(char('s')))))(input)?;

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
    if let Ok((input, node)) = assertion(input) {
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
        escaped_char,
        literal,
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
    let (input, negated) = eat_opt_char('^', input);
    let (input, contains_closing_bracket) = eat_opt_char(']', input);

    let (input, mut items) = many0(bracketed_class_item)(input)?;
    let (input, _) = char(']')(input)?;

    if contains_closing_bracket {
        items.push(BracketedClassItem::Literal(Literal { byte: b']' }));
    }
    Ok((input, BracketedClass { items, negated }))
}

fn bracketed_class_item(input: Input) -> ParseResult<BracketedClassItem> {
    alt((
        map(perl_class, BracketedClassItem::Perl),
        bracketed_class_range_or_literal,
    ))(input)
}

fn bracketed_class_range_or_literal(input: Input) -> ParseResult<BracketedClassItem> {
    let start = input.pos();
    let (input, lit) = bracketed_class_literal(input)?;
    let (input2, has_dash) = eat_opt_char('-', input);

    if has_dash {
        let (input3, lit2) = opt(bracketed_class_literal)(input2)?;
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
    alt((escaped_char_only_ascii, bracketed_class_char))(input)
}

fn bracketed_class_char(input: Input) -> ParseResult<Literal> {
    let start = input.pos();

    // / and \n are disallowed because of the surrounding rule (we are parsing a /.../ variable,
    // and newlines are not allowed
    // ] is disallowed because it indicates the end of the class
    let (input, b) = none_of("/\n]")(input)?;
    if b.is_ascii() {
        Ok((input, Literal { byte: b as u8 }))
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
    let (input, c) = none_of("/\n()[\\|.$^+*?")(input)?;
    let node = if c.is_ascii() {
        Node::Literal(Literal { byte: c as u8 })
    } else {
        Node::Char(LiteralChar {
            c,
            span: input.get_span_from_no_rtrim(start),
        })
    };

    Ok((input, node))
}

fn escaped_char(input: Input) -> ParseResult<Node> {
    let (input, res) = escaped_char_inner(input)?;

    let node = match res {
        EscapedChar::Byte(byte) => Node::Literal(Literal { byte }),
        EscapedChar::Char { c, span } => Node::Char(LiteralChar { c, span }),
    };

    Ok((input, node))
}

fn escaped_char_only_ascii(input: Input) -> ParseResult<Literal> {
    let (input, res) = escaped_char_inner(input)?;

    match res {
        EscapedChar::Byte(byte) => Ok((input, Literal { byte })),
        EscapedChar::Char { span, .. } => Err(nom::Err::Failure(Error::new(
            span,
            ErrorKind::RegexNonAsciiByte,
        ))),
    }
}

fn escaped_char_inner(input: Input) -> ParseResult<EscapedChar> {
    let start = input.pos();
    let (input2, _) = char('\\')(input)?;
    let (input, b) = anychar(input2)?;

    let res = match b {
        'n' => EscapedChar::Byte(b'\n'),
        't' => EscapedChar::Byte(b'\t'),
        'r' => EscapedChar::Byte(b'\r'),
        'f' => EscapedChar::Byte(b'\x0C'),
        'a' => EscapedChar::Byte(b'\x07'),
        'x' => {
            let (input, n) = cut(take(2_u32))(input)?;

            let n = match u8::from_str_radix(&n, 16) {
                Ok(n) => n,
                Err(e) => {
                    return Err(nom::Err::Failure(Error::new(
                        input.get_span_from_no_rtrim(start),
                        ErrorKind::StrToHexIntError(e),
                    )));
                }
            };
            return Ok((input, EscapedChar::Byte(n)));
        }
        c if c.is_ascii() => EscapedChar::Byte(c as u8),
        c => EscapedChar::Char {
            c,
            span: input.get_span_from_no_rtrim(input2.pos()),
        },
    };

    Ok((input, res))
}

enum EscapedChar {
    Byte(u8),
    Char { c: char, span: Range<usize> },
}

fn range_repetition(input: Input) -> ParseResult<(RepetitionRange, bool)> {
    let (input, range) = alt((range_single, range_multi))(input)?;
    let (input, non_greedy) = eat_opt_char('?', input);

    Ok((input, (range, !non_greedy)))
}

fn range_single(input: Input) -> ParseResult<RepetitionRange> {
    let (input, v) = delimited(char('{'), parse_u32, char('}'))(input)?;

    Ok((input, RepetitionRange::Exactly(v)))
}

fn range_multi(input: Input) -> ParseResult<RepetitionRange> {
    let start = input.pos();
    let (input, (from, to)) = delimited(
        char('{'),
        separated_pair(parse_opt_u32, char(','), parse_opt_u32),
        char('}'),
    )(input)?;

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

    #[test]
    fn test_parse() {
        parse(
            regex,
            "/a/i",
            "",
            Regex {
                ast: Node::Literal(Literal { byte: b'a' }),
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
                            Literal { byte: b'0' },
                            Literal { byte: b'9' },
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
                    Node::Literal(Literal { byte: b'a' }),
                    Node::Literal(Literal { byte: b'/' }),
                    Node::Literal(Literal { byte: b'b' }),
                    Node::Literal(Literal { byte: b'c' }),
                    Node::Literal(Literal { byte: b'd' }),
                ]),
                case_insensitive: true,
                dot_all: true,
                span: 0..11,
            },
        );
        parse(
            regex,
            r#"/.{2}/si c"#,
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
                    Node::Literal(Literal { byte: b'\0' }),
                    Node::Literal(Literal { byte: b'\0' }),
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
            Node::Literal(Literal { byte: b'a' }),
        );
        parse(
            alternative,
            "a|b",
            "",
            Node::Alternation(vec![
                Node::Literal(Literal { byte: b'a' }),
                Node::Literal(Literal { byte: b'b' }),
            ]),
        );
        parse(
            alternative,
            "a|)",
            ")",
            Node::Alternation(vec![Node::Literal(Literal { byte: b'a' }), Node::Empty]),
        );

        parse(
            alternative,
            r"ab|.\||\b$|",
            "",
            Node::Alternation(vec![
                Node::Concat(vec![
                    Node::Literal(Literal { byte: b'a' }),
                    Node::Literal(Literal { byte: b'b' }),
                ]),
                Node::Concat(vec![Node::Dot, Node::Literal(Literal { byte: b'|' })]),
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
            Node::Literal(Literal { byte: b'a' }),
        );
        parse(
            concatenation,
            "ab",
            "",
            Node::Concat(vec![
                Node::Literal(Literal { byte: b'a' }),
                Node::Literal(Literal { byte: b'b' }),
            ]),
        );
        parse(
            concatenation,
            "a$*",
            "*",
            Node::Concat(vec![
                Node::Literal(Literal { byte: b'a' }),
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
                    node: Box::new(Node::Literal(Literal { byte: b'a' })),
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
                        items: vec![BracketedClassItem::Literal(Literal { byte: b'z' })],
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
                Node::Literal(Literal { byte: b'a' }),
                Node::Literal(Literal { byte: b'b' }),
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
                    BracketedClassItem::Range(Literal { byte: b'a' }, Literal { byte: b'f' }),
                    BracketedClassItem::Range(Literal { byte: b'A' }, Literal { byte: b'F' }),
                ],
                negated: false,
            })),
        );
        parse(
            single,
            r"\xFFa",
            "a",
            Node::Literal(Literal { byte: b'\xFF' }),
        );
        parse(single, r"]a", "a", Node::Literal(Literal { byte: b']' }));

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
                items: vec![BracketedClassItem::Literal(Literal { byte: b'a' })],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[^a-z_\\S0-9]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Range(Literal { byte: b'a' }, Literal { byte: b'z' }),
                    BracketedClassItem::Literal(Literal { byte: b'_' }),
                    BracketedClassItem::Perl(PerlClass {
                        kind: PerlClassKind::Space,
                        negated: true,
                    }),
                    BracketedClassItem::Range(Literal { byte: b'0' }, Literal { byte: b'9' }),
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
                    BracketedClassItem::Literal(Literal { byte: b'j' }),
                    BracketedClassItem::Literal(Literal { byte: b']' }),
                ],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[]]",
            "",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(Literal { byte: b']' })],
                negated: false,
            },
        );
        parse(
            bracketed_class,
            "[^]]",
            "",
            BracketedClass {
                items: vec![BracketedClassItem::Literal(Literal { byte: b']' })],
                negated: true,
            },
        );
        parse(
            bracketed_class,
            "[^a\\]b-]",
            "",
            BracketedClass {
                items: vec![
                    BracketedClassItem::Literal(Literal { byte: b'a' }),
                    BracketedClassItem::Literal(Literal { byte: b']' }),
                    BracketedClassItem::Literal(Literal { byte: b'b' }),
                    BracketedClassItem::Literal(Literal { byte: b'-' }),
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
            "a-z]",
            "]",
            BracketedClassItem::Range(Literal { byte: b'a' }, Literal { byte: b'z' }),
        );

        parse_err(bracketed_class_item, "é");
    }

    #[test]
    fn test_bracketed_class_range_or_literal() {
        parse(
            bracketed_class_range_or_literal,
            "ab",
            "b",
            BracketedClassItem::Literal(Literal { byte: b'a' }),
        );
        parse(
            bracketed_class_range_or_literal,
            "\x01-",
            "-",
            BracketedClassItem::Literal(Literal { byte: b'\x01' }),
        );
        parse(
            bracketed_class_range_or_literal,
            "-\\]",
            "\\]",
            BracketedClassItem::Literal(Literal { byte: b'-' }),
        );
        parse(
            bracketed_class_range_or_literal,
            "A-]",
            "-]",
            BracketedClassItem::Literal(Literal { byte: b'A' }),
        );

        parse(
            bracketed_class_range_or_literal,
            "a-\\sb",
            "b",
            BracketedClassItem::Range(Literal { byte: b'a' }, Literal { byte: b's' }),
        );
        parse(
            bracketed_class_range_or_literal,
            "!--",
            "",
            BracketedClassItem::Range(Literal { byte: b'!' }, Literal { byte: b'-' }),
        );
        parse(
            bracketed_class_range_or_literal,
            "---",
            "",
            BracketedClassItem::Range(Literal { byte: b'-' }, Literal { byte: b'-' }),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\n-\n",
            "",
            BracketedClassItem::Range(Literal { byte: b'\n' }, Literal { byte: b'\n' }),
        );
        parse(
            bracketed_class_range_or_literal,
            r"\x01-\xFE",
            "",
            BracketedClassItem::Range(Literal { byte: b'\x01' }, Literal { byte: b'\xFE' }),
        );

        parse_err(bracketed_class_range_or_literal, "é");
        parse_err(bracketed_class_range_or_literal, "b-a");
        parse_err(bracketed_class_range_or_literal, "é-a");
        parse_err(bracketed_class_range_or_literal, "a-é");
        parse_err(bracketed_class_range_or_literal, "]-a");
    }

    #[test]
    fn test_bracketed_class_literal() {
        parse(bracketed_class_literal, "ab", "b", Literal { byte: b'a' });
        parse(
            bracketed_class_literal,
            "\\nb",
            "b",
            Literal { byte: b'\n' },
        );
        parse(bracketed_class_literal, "\\]", "", Literal { byte: b']' });

        parse_err(bracketed_class_literal, "]b");
        parse_err(bracketed_class_literal, "é");
        parse_err(bracketed_class_literal, "\\x1");
        parse_err(bracketed_class_literal, "\\é");
    }

    #[test]
    fn test_bracketed_class_char() {
        parse(bracketed_class_char, "ab", "b", Literal { byte: b'a' });

        parse_err(bracketed_class_char, "]b");
        parse_err(bracketed_class_char, "é");
    }

    #[test]
    fn test_literal() {
        parse(literal, "ab", "b", Node::Literal(Literal { byte: b'a' }));
        parse(literal, "]", "", Node::Literal(Literal { byte: b']' }));

        parse(
            literal,
            "éb",
            "b",
            Node::Char(LiteralChar {
                c: 'é', span: 0..2
            }),
        );
    }

    #[test]
    fn test_escaped_char() {
        parse(
            escaped_char,
            "\\na",
            "a",
            Node::Literal(Literal { byte: b'\n' }),
        );
        parse(
            escaped_char,
            "\\ta",
            "a",
            Node::Literal(Literal { byte: b'\t' }),
        );
        parse(
            escaped_char,
            "\\ra",
            "a",
            Node::Literal(Literal { byte: b'\r' }),
        );
        parse(
            escaped_char,
            "\\fa",
            "a",
            Node::Literal(Literal { byte: b'\x0C' }),
        );
        parse(
            escaped_char,
            "\\aa",
            "a",
            Node::Literal(Literal { byte: b'\x07' }),
        );
        parse(
            escaped_char,
            "\\x00a",
            "a",
            Node::Literal(Literal { byte: b'\0' }),
        );
        parse(
            escaped_char,
            "\\xAF a",
            " a",
            Node::Literal(Literal { byte: b'\xAF' }),
        );
        parse(
            escaped_char,
            "\\k",
            "",
            Node::Literal(Literal { byte: b'k' }),
        );
        parse(
            escaped_char,
            "\\é_",
            "_",
            Node::Char(LiteralChar {
                c: 'é', span: 1..3
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
            Literal { byte: b'\n' },
        );
        parse(
            escaped_char_only_ascii,
            "\\ta",
            "a",
            Literal { byte: b'\t' },
        );
        parse(
            escaped_char_only_ascii,
            "\\ra",
            "a",
            Literal { byte: b'\r' },
        );
        parse(
            escaped_char_only_ascii,
            "\\fa",
            "a",
            Literal { byte: b'\x0C' },
        );
        parse(
            escaped_char_only_ascii,
            "\\aa",
            "a",
            Literal { byte: b'\x07' },
        );
        parse(
            escaped_char_only_ascii,
            "\\x00a",
            "a",
            Literal { byte: b'\0' },
        );
        parse(
            escaped_char_only_ascii,
            "\\xAF a",
            " a",
            Literal { byte: b'\xAF' },
        );
        parse(escaped_char_only_ascii, "\\k", "", Literal { byte: b'k' });

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

        parse_err(range_multi, "{");
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
