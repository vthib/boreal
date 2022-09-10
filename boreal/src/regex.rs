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
        let mut expr = String::new();
        add_ast_to_string(ast, &mut expr);

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
pub(crate) fn add_ast_to_string(ast: Node, out: &mut String) {
    // TODO avoid recursion here.
    push_ast(ast, out);
}

fn push_ast(node: Node, out: &mut String) {
    match node {
        Node::Alternation(nodes) => {
            for (i, n) in nodes.into_iter().enumerate() {
                if i != 0 {
                    out.push('|');
                }
                push_ast(n, out);
            }
        }
        Node::Assertion(AssertionKind::StartLine) => out.push('^'),
        Node::Assertion(AssertionKind::EndLine) => out.push('$'),
        Node::Assertion(AssertionKind::WordBoundary) => out.push_str(r"\b"),
        Node::Assertion(AssertionKind::NonWordBoundary) => out.push_str(r"\B"),
        Node::Class(ClassKind::Perl(p)) => push_perl_class(&p, out),
        Node::Class(ClassKind::Bracketed(c)) => push_bracketed_class(c, out),
        Node::Concat(nodes) => {
            for n in nodes {
                push_ast(n, out);
            }
        }
        Node::Dot => out.push('.'),
        Node::Empty => (),
        Node::Literal(b) => push_literal(b, out),
        Node::Group(n) => {
            out.push('(');
            push_ast(*n, out);
            out.push(')');
        }
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
    if (lit.is_ascii_alphanumeric()
        || lit.is_ascii_graphic()
        || lit.is_ascii_punctuation()
        || lit == b' ')
        && !regex_syntax::is_meta_character(char::from(lit))
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use boreal_parser::{VariableDeclaration, VariableDeclarationValue};

    #[test]
    fn test_regex_conversion() {
        fn test(expr: &str, expected_res: Option<&str>) {
            // Build a rule with a variable using the given regex expr. This gives us the AST for
            // the regex, which we convert back to a rust regex expr.
            let rule = format!(
                "rule a {{ strings: $ = /{}/ condition: any of them }}",
                expr
            );
            let mut file = boreal_parser::parse_str(&rule).unwrap();
            let mut rule = match file.components.pop() {
                Some(boreal_parser::YaraFileComponent::Rule(r)) => r,
                _ => unreachable!(),
            };
            let regex = match rule.variables.pop() {
                Some(VariableDeclaration {
                    value: VariableDeclarationValue::Regex(regex),
                    ..
                }) => regex,
                _ => unreachable!(),
            };
            let ast = regex.ast;
            let mut res = String::new();
            add_ast_to_string(ast, &mut res);
            assert_eq!(&res, expected_res.unwrap_or(expr));
        }

        // Syntaxes that matches between yara and rust regexes.
        test("^a.d+$", None);
        test(r"\s?\S??\w*(\W*?\d+?\D\b)+", None);
        test(r"\ba\B[a\w]|a(b|cd)t[^a-z]", None);

        // Syntaxes that are modified to avoid issues
        test(
            r"[]] [^].[^] [!---]",
            Some(r"[\x5d] [^\x2e\x5b\x5e\x5d] [!-\x2d\x2d]"),
        );
        test(
            r"[|\\.+*?()\]{}^$#&\-~]",
            Some(r"[\x7c\x5c\x2e\x2b\x2a\x3f\x28\x29\x5d\x7b\x7d\x5e\x24\x23\x26\x2d\x7e]"),
        );
        // Most of those do not need to be escaped in a class, escaping them does not do anythin.
        // We still convert them to avoid issues.
        test(
            r"[\|\\\.\+\*\?\(\)\]\{\}\^\$\#\&\-\~]",
            Some(r"[\x7c\x5c\x2e\x2b\x2a\x3f\x28\x29\x5d\x7b\x7d\x5e\x24\x23\x26\x2d\x7e]"),
        );
        test(
            r"\|\\\.\+\*\?\(\)\]\{\}\^\$\#\&\-\~\[",
            Some(r"\x7c\x5c\x2e\x2b\x2a\x3f\x28\x29\x5d\x7b\x7d\x5e\x24\x23\x26\x2d\x7e\x5b"),
        );
        // Escaping chars that are not meta do not do anythin.
        test(r#"\k\i\z\p\P\"\A\z"#, Some(r#"kizpP"Az"#));
        // Range repetitions are only parsed if valid, and the {,N} is normalized
        test(
            r"a{0} b{1,} c{,2} d{3,4} e{} f{*} g{1,h}",
            Some(r"a{0} b{1,} c{0,2} d{3,4} e\x7b\x7d f\x7b*\x7d g\x7b1,h\x7d"),
        );
        // Regex from the signature-base repository
        test(
            r#"{"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":""#,
            Some(
                r#"\x7b"Hosts":\x5b".{10,512}"\x5d,"Proxy":".{0,512}","Version":".{1,32}","Guid":""#,
            ),
        );
    }
}
