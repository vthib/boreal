use std::convert::Infallible;
use std::fmt::Write;

use regex::bytes::RegexBuilder;

use boreal_parser::regex::{
    AssertionKind, BracketedClass, BracketedClassItem, ClassKind, Node, PerlClass, PerlClassKind,
    RepetitionKind, RepetitionRange,
};

mod visitor;
pub use visitor::{visit, VisitAction, Visitor};

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
    pub fn new(ast: &Node, case_insensitive: bool, dot_all: bool) -> Result<Self, Error> {
        Self::new_inner(ast, case_insensitive, dot_all)
    }

    fn new_inner(ast: &Node, case_insensitive: bool, dot_all: bool) -> Result<Self, Error> {
        RegexBuilder::new(&regex_ast_to_string(ast))
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
pub(crate) fn regex_ast_to_string(ast: &Node) -> String {
    visit(ast, AstPrinter::default()).unwrap_or_else(|e| match e {})
}

#[derive(Default)]
struct AstPrinter {
    res: String,
}

impl Visitor for AstPrinter {
    type Output = String;
    type Err = Infallible;

    fn visit_pre(&mut self, node: &Node) -> Result<VisitAction, Self::Err> {
        match node {
            Node::Assertion(AssertionKind::StartLine) => self.res.push('^'),
            Node::Assertion(AssertionKind::EndLine) => self.res.push('$'),
            Node::Assertion(AssertionKind::WordBoundary) => self.res.push_str(r"\b"),
            Node::Assertion(AssertionKind::NonWordBoundary) => self.res.push_str(r"\B"),
            Node::Class(ClassKind::Perl(p)) => self.push_perl_class(p),
            Node::Class(ClassKind::Bracketed(c)) => self.push_bracketed_class(c),
            Node::Dot => self.res.push('.'),
            Node::Literal(b) => self.push_literal(*b),
            Node::Group(_) => self.res.push('('),
            Node::Alternation(_) | Node::Concat(_) | Node::Empty | Node::Repetition { .. } => (),
        }

        Ok(VisitAction::Continue)
    }

    fn visit_post(&mut self, node: &Node) -> Result<(), Self::Err> {
        match node {
            Node::Alternation(_)
            | Node::Assertion(_)
            | Node::Class(_)
            | Node::Concat(_)
            | Node::Dot
            | Node::Empty
            | Node::Literal(_) => (),
            Node::Group(_) => self.res.push(')'),
            Node::Repetition {
                kind,
                greedy,
                node: _,
            } => {
                match kind {
                    RepetitionKind::ZeroOrOne => self.res.push('?'),
                    RepetitionKind::ZeroOrMore => self.res.push('*'),
                    RepetitionKind::OneOrMore => self.res.push('+'),
                    RepetitionKind::Range(range) => {
                        let _r = match range {
                            RepetitionRange::Exactly(n) => write!(self.res, "{{{}}}", n),
                            RepetitionRange::AtLeast(n) => write!(self.res, "{{{},}}", n),
                            RepetitionRange::Bounded(n, m) => write!(self.res, "{{{},{}}}", n, m),
                        };
                    }
                };
                if !greedy {
                    self.res.push('?');
                }
            }
        }

        Ok(())
    }

    fn visit_alternation_in(&mut self) {
        self.res.push('|');
    }

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self.res)
    }
}

impl AstPrinter {
    fn push_literal(&mut self, lit: u8) {
        if (lit.is_ascii_alphanumeric()
            || lit.is_ascii_graphic()
            || lit.is_ascii_punctuation()
            || lit == b' ')
            && !regex_syntax::is_meta_character(char::from(lit))
        {
            self.res.push(char::from(lit));
        } else {
            let _r = write!(&mut self.res, r"\x{:02x}", lit);
        }
    }

    fn push_perl_class(&mut self, cls: &PerlClass) {
        match cls {
            PerlClass {
                kind: PerlClassKind::Word,
                negated: false,
            } => self.res.push_str(r"\w"),
            PerlClass {
                kind: PerlClassKind::Word,
                negated: true,
            } => self.res.push_str(r"\W"),
            PerlClass {
                kind: PerlClassKind::Space,
                negated: false,
            } => self.res.push_str(r"\s"),
            PerlClass {
                kind: PerlClassKind::Space,
                negated: true,
            } => self.res.push_str(r"\S"),
            PerlClass {
                kind: PerlClassKind::Digit,
                negated: false,
            } => self.res.push_str(r"\d"),
            PerlClass {
                kind: PerlClassKind::Digit,
                negated: true,
            } => self.res.push_str(r"\D"),
        }
    }

    fn push_bracketed_class(&mut self, cls: &BracketedClass) {
        self.res.push('[');
        if cls.negated {
            self.res.push('^');
        }
        for item in &cls.items {
            match item {
                BracketedClassItem::Perl(p) => self.push_perl_class(p),
                BracketedClassItem::Literal(b) => self.push_literal(*b),
                BracketedClassItem::Range(a, b) => {
                    self.push_literal(*a);
                    self.res.push('-');
                    self.push_literal(*b);
                }
            }
        }
        self.res.push(']');
    }
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
    use crate::test_helpers::parse_regex_string;

    #[test]
    fn test_regex_conversion() {
        fn test(expr: &str, expected_res: Option<&str>) {
            let regex = parse_regex_string(expr);
            assert_eq!(
                regex_ast_to_string(&regex.ast),
                expected_res.unwrap_or(expr)
            );
        }

        // Syntaxes that matches between yara and rust regexes.
        test("^a.d+$", None);
        test(r"\s?\S??\w*(\W*?\d+?\D\b)+", None);
        test(r"(\ba\B[a\w]|a(b|cd)t[^a-z])", None);

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
