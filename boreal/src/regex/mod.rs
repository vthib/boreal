//! YARA regex handling
//!
//! This module contains a set of types and helpers to handle the YARA regex syntax.
use std::error::Error as StdError;
use std::fmt::Write;
use std::ops::Range;

use regex_automata::{meta, util::syntax, Input};

use boreal_parser::regex::{
    AssertionKind, BracketedClass, BracketedClassItem, ClassKind, Literal, PerlClass,
    PerlClassKind, RepetitionKind, RepetitionRange,
};

mod hir;
pub use hir::*;

mod visitor;
pub(crate) use visitor::{visit, VisitAction, Visitor};

/// Regex following the YARA format.
#[derive(Clone, Debug)]
pub struct Regex {
    meta: meta::Regex,
    expr: String,
    #[cfg(feature = "serialize")]
    case_insensitive: bool,
    #[cfg(feature = "serialize")]
    dot_all: bool,
}

impl Regex {
    /// Build the regex from a string expression.
    ///
    /// This string expression must have been generated by a call to [`regex_ast_to_string`], to
    /// ensure it does not uses syntaxes not handled by the yara syntax.
    ///
    /// # Errors
    ///
    /// Return an error if the regex is malformed.
    pub(crate) fn from_string(
        expr: String,
        case_insensitive: bool,
        dot_all: bool,
    ) -> Result<Self, Error> {
        let meta = Self::builder(case_insensitive, dot_all)
            .build(&expr)
            .map_err(Error::from)?;

        Ok(Regex {
            meta,
            expr,
            #[cfg(feature = "serialize")]
            case_insensitive,
            #[cfg(feature = "serialize")]
            dot_all,
        })
    }

    pub(crate) fn builder(case_insensitive: bool, dot_all: bool) -> meta::Builder {
        let mut builder = meta::Builder::new();
        let _b = builder
            .configure(meta::Config::new().utf8_empty(false))
            .syntax(
                syntax::Config::new()
                    .octal(false)
                    .unicode(false)
                    .utf8(false)
                    .multi_line(false)
                    .case_insensitive(case_insensitive)
                    .dot_matches_new_line(dot_all),
            );

        builder
    }

    /// Find a match in the given haystack.
    #[must_use]
    pub fn find(&self, haystack: &[u8]) -> Option<Range<usize>> {
        self.find_in_input(Input::new(haystack))
    }

    /// Find a match in the given haystack starting at the given offset.
    #[must_use]
    pub fn find_at(&self, haystack: &[u8], offset: usize) -> Option<Range<usize>> {
        self.find_in_input(Input::new(haystack).span(offset..haystack.len()))
    }

    /// Find a match on the given haystack in the given range
    #[must_use]
    fn find_in_input(&self, input: Input) -> Option<Range<usize>> {
        self.meta.find(input).map(|m| m.range())
    }

    /// Returns true if and only if this regex matches the given haystack.
    #[must_use]
    pub fn is_match(&self, mem: &[u8]) -> bool {
        self.meta.is_match(mem)
    }

    /// Returns the original string of this regex.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.expr
    }
}

/// Convert a yara regex HIR into a rust regex expression.
pub(crate) fn regex_hir_to_string(hir: &Hir) -> String {
    visit(hir, AstPrinter::default())
}

#[derive(Default)]
struct AstPrinter {
    res: String,
}

impl Visitor for AstPrinter {
    type Output = String;

    fn visit_pre(&mut self, node: &Hir) -> VisitAction {
        match node {
            Hir::Assertion(AssertionKind::StartLine) => self.res.push('^'),
            Hir::Assertion(AssertionKind::EndLine) => self.res.push('$'),
            Hir::Assertion(AssertionKind::WordBoundary) => self.res.push_str(r"\b"),
            Hir::Assertion(AssertionKind::NonWordBoundary) => self.res.push_str(r"\B"),
            Hir::Mask {
                value,
                mask,
                negated,
            } => {
                if *mask == 0xF0 {
                    self.res.push('[');
                    if *negated {
                        self.res.push('^');
                    }
                    self.push_literal(*value);
                    self.res.push('-');
                    self.push_literal(value | 0x0F);
                    self.res.push(']');
                } else {
                    self.res.push('[');
                    if *negated {
                        self.res.push('^');
                    }
                    for b in 0..16 {
                        self.push_literal((b << 4) | value);
                    }
                    self.res.push(']');
                }
            }
            Hir::Class(Class {
                definition: ClassKind::Perl(p),
                bitmap: _bitmap,
            }) => self.push_perl_class(p),
            Hir::Class(Class {
                definition: ClassKind::Bracketed(c),
                bitmap: _bitmap,
            }) => self.push_bracketed_class(c),
            Hir::Dot => self.res.push('.'),
            Hir::Literal(b) => self.push_literal(*b),
            Hir::Group(_) => self.res.push('('),
            Hir::Alternation(_) | Hir::Concat(_) | Hir::Empty | Hir::Repetition { .. } => (),
        }

        VisitAction::Continue
    }

    fn visit_post(&mut self, node: &Hir) {
        match node {
            Hir::Alternation(_)
            | Hir::Assertion(_)
            | Hir::Mask { .. }
            | Hir::Class(_)
            | Hir::Concat(_)
            | Hir::Dot
            | Hir::Empty
            | Hir::Literal(_) => (),
            Hir::Group(_) => self.res.push(')'),
            Hir::Repetition {
                kind,
                greedy,
                hir: _,
            } => {
                match kind {
                    RepetitionKind::ZeroOrOne => self.res.push('?'),
                    RepetitionKind::ZeroOrMore => self.res.push('*'),
                    RepetitionKind::OneOrMore => self.res.push('+'),
                    RepetitionKind::Range(range) => {
                        let _r = match range {
                            RepetitionRange::Exactly(n) => write!(self.res, "{{{n}}}"),
                            RepetitionRange::AtLeast(n) => write!(self.res, "{{{n},}}"),
                            RepetitionRange::Bounded(n, m) => write!(self.res, "{{{n},{m}}}"),
                        };
                    }
                };
                if !greedy {
                    self.res.push('?');
                }
            }
        }
    }

    fn visit_alternation_in(&mut self) {
        self.res.push('|');
    }

    fn finish(self) -> Self::Output {
        self.res
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
            let _r = write!(&mut self.res, r"\x{lit:02x}");
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
                BracketedClassItem::Literal(Literal { byte, .. }) => self.push_literal(*byte),
                BracketedClassItem::Range(Literal { byte: a, .. }, Literal { byte: b, .. }) => {
                    self.push_literal(*a);
                    self.res.push('-');
                    self.push_literal(*b);
                }
            }
        }
        self.res.push(']');
    }
}

/// Error when compiling a regex.
#[derive(Clone, Debug)]
pub struct Error(String);

impl From<meta::BuildError> for Error {
    fn from(err: meta::BuildError) -> Self {
        // Copied from the regex crate: useful to get a good error message on size limit reached.
        if let Some(size_limit) = err.size_limit() {
            Self(format!(
                "Compiled regex exceeds size limit of {size_limit} bytes.",
            ))
        } else {
            Self(err.to_string())
        }
    }
}

impl From<regex_automata::hybrid::BuildError> for Error {
    fn from(err: regex_automata::hybrid::BuildError) -> Self {
        // TODO: would be nice to have a simpler way of finding out this information
        if let Some(source) = err.source() {
            if let Some(nfa_err) =
                source.downcast_ref::<regex_automata::nfa::thompson::BuildError>()
            {
                if let Some(size_limit) = nfa_err.size_limit() {
                    return Self(format!(
                        "Compiled regex exceeds size limit of {size_limit} bytes.",
                    ));
                }
            }
        }

        Self(err.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use borsh::{BorshDeserialize as BD, BorshSerialize};

    use super::Regex;

    impl BorshSerialize for Regex {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.case_insensitive.serialize(writer)?;
            self.dot_all.serialize(writer)?;
            self.expr.serialize(writer)?;
            Ok(())
        }
    }

    impl BD for Regex {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let case_insensitive = BD::deserialize_reader(reader)?;
            let dot_all = BD::deserialize_reader(reader)?;
            let expr = BD::deserialize_reader(reader)?;
            Regex::from_string(expr, case_insensitive, dot_all).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid regex expression: {err:?}"),
                )
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{expr_to_hir, test_type_traits};

    #[test]
    fn test_regex_conversion() {
        #[track_caller]
        fn test(expr: &str, expected_res: Option<&str>) {
            let hir = expr_to_hir(expr);
            assert_eq!(regex_hir_to_string(&hir), expected_res.unwrap_or(expr));
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
            r#" {"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":""#,
            Some(
                r#" \x7b"Hosts":\x5b".{10,512}"\x5d,"Proxy":".{0,512}","Version":".{1,32}","Guid":""#,
            ),
        );
    }

    #[test]
    fn test_hex_string_to_regex() {
        #[track_caller]
        fn test(expr: &str, expected_regex: &str) {
            let hir = expr_to_hir(expr);
            assert_eq!(&regex_hir_to_string(&hir), expected_regex);
        }

        test(
            "{ AB ?D 01 }",
            r"\xab[\x0d\x1d\x2d=M\x5dm\x7d\x8d\x9d\xad\xbd\xcd\xdd\xed\xfd]\x01",
        );
        test("{ C7 [-] ?? }", r"\xc7.{0,}?.");
        test(
            "{ C7 [3-] 5? 03 [-6] C7 ( FF 15 | E8 ) [4] 6A ( FF D? | E8 [2-4] ??) }",
            r"\xc7.{3,}?[P-_]\x03.{0,6}?\xc7(\xff\x15|\xe8).{4,4}?j(\xff[\xd0-\xdf]|\xe8.{2,4}?.)",
        );
    }

    #[test]
    fn test_regex_as_str() {
        // Original expression can be retrieved with the as_str method.
        let expr = r"^a+b\wc";
        let regex = Regex::from_string(expr.to_owned(), false, false).unwrap();
        assert_eq!(regex.as_str(), expr);
    }

    #[test]
    fn test_types_traits() {
        test_type_traits(Regex::from_string("a".to_owned(), false, false));
        test_type_traits(Error("a".to_owned()));
    }
}
