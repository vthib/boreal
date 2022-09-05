use std::fmt::Write;

use regex::bytes::RegexBuilder;

use boreal_parser::regex::{
    AssertionKind, BracketedClass, BracketedClassItem, ClassKind, Node, PerlClass, PerlClassKind,
    RepetitionKind, RepetitionRange,
};

/// Regex following the YARA format.
///
/// This represents a regex expression as can be used in a YARA rule, either as a
/// string or has a raw value.
#[derive(Clone, Debug)]
pub struct Regex(regex::bytes::Regex);

impl Regex {
    /// Build the regex from a string.
    ///
    /// # Errors
    ///
    /// Will return `err` if the regex is malformed.
    pub fn new(ast: Node, case_insensitive: bool, dot_all: bool) -> Result<Self, Error> {
        Self::new_inner(ast, case_insensitive, dot_all)
    }

    fn new_inner(ast: Node, case_insensitive: bool, dot_all: bool) -> Result<Self, Error> {
        let expr = ast_to_rust_expr(ast);

        RegexBuilder::new(&expr)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .dot_matches_new_line(dot_all)
            .build()
            .map(Regex)
            .map_err(Error)
    }

    /// Return the regex as a [`regex::bytes::Regex`].
    #[must_use]
    pub fn as_regex(&self) -> &regex::bytes::Regex {
        &self.0
    }
}

/// Convert a yara regex AST into a rust regex expression.
pub(crate) fn ast_to_rust_expr(ast: Node) -> String {
    let mut expr = String::new();

    // TODO avoid recursion here.
    push_ast(ast, &mut expr);

    expr
}

fn push_ast(node: Node, out: &mut String) {
    match node {
        Node::Alternation(nodes) => {
            out.push('(');
            for (i, n) in nodes.into_iter().enumerate() {
                if i != 0 {
                    out.push('|');
                }
                push_ast(n, out);
            }
            out.push(')');
        }
        Node::Assertion(AssertionKind::StartLine) => out.push('^'),
        Node::Assertion(AssertionKind::EndLine) => out.push('$'),
        Node::Assertion(AssertionKind::WordBoundary) => out.push_str(r"\b"),
        Node::Assertion(AssertionKind::NonWordBoundary) => out.push_str(r"\B"),
        Node::Class(ClassKind::Perl(p)) => push_perl_class(&p, out),
        Node::Class(ClassKind::Bracketed(c)) => push_bracketed_class(c, out),
        Node::Concat(nodes) => {
            out.push('(');
            for n in nodes {
                push_ast(n, out);
            }
            out.push(')');
        }
        Node::Dot => out.push('.'),
        Node::Empty => (),
        Node::Literal(b) => push_literal(b, out),
        Node::Repetition { node, kind, greedy } => {
            push_ast(*node, out);
            match kind {
                RepetitionKind::ZeroOrOne => out.push('?'),
                RepetitionKind::ZeroOrMore => out.push('*'),
                RepetitionKind::OneOrMore => out.push('+'),
                RepetitionKind::Range(range) => {
                    let _r = match range {
                        RepetitionRange::Exactly(n) => write!(out, "{{{}}}", n),
                        RepetitionRange::AtLeast(n) => write!(out, "{{{},}}", n),
                        RepetitionRange::Bounded(n, m) => write!(out, "{{{},{}}}", n, m),
                    };
                }
            };
            if !greedy {
                out.push('?');
            }
        }
    }
}

fn push_literal(lit: u8, out: &mut String) {
    if lit.is_ascii() && !regex_syntax::is_meta_character(char::from(lit)) {
        out.push(char::from(lit));
    } else {
        let _r = write!(out, r"\x{:02x}", lit);
    }
}

fn push_perl_class(cls: &PerlClass, out: &mut String) {
    match cls {
        PerlClass {
            kind: PerlClassKind::Word,
            negated: false,
        } => out.push_str(r"\w"),
        PerlClass {
            kind: PerlClassKind::Word,
            negated: true,
        } => out.push_str(r"\W"),
        PerlClass {
            kind: PerlClassKind::Space,
            negated: false,
        } => out.push_str(r"\s"),
        PerlClass {
            kind: PerlClassKind::Space,
            negated: true,
        } => out.push_str(r"\S"),
        PerlClass {
            kind: PerlClassKind::Digit,
            negated: false,
        } => out.push_str(r"\d"),
        PerlClass {
            kind: PerlClassKind::Digit,
            negated: true,
        } => out.push_str(r"\D"),
    }
}

fn push_bracketed_class(cls: BracketedClass, out: &mut String) {
    out.push('[');
    if cls.negated {
        out.push('^');
    }
    for item in cls.items {
        match item {
            BracketedClassItem::Perl(p) => push_perl_class(&p, out),
            BracketedClassItem::Literal(b) => push_literal(b, out),
            BracketedClassItem::Range(a, b) => {
                push_literal(a, out);
                out.push('-');
                push_literal(b, out);
            }
        }
    }
    out.push(']');
}

#[derive(Clone, Debug)]
pub struct Error(regex::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
