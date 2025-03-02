//! Some common and useful nom recipes, shared by all other modules.

use nom::branch::alt;
use nom::bytes::complete::{tag, take_until};
use nom::character::complete::{char, multispace1};
use nom::combinator::{cut, opt, value};
use nom::error::{ErrorKind as NomErrorKind, ParseError};
use nom::multi::many0;
use nom::Parser;

use super::error::{Error, ErrorKind};
use super::types::{Input, ParseResult};

/// Right trim after the given parser.
pub(crate) fn rtrim<'a, F, O>(mut inner: F) -> impl FnMut(Input<'a>) -> ParseResult<'a, O>
where
    F: Parser<Input<'a>, Output = O, Error = Error> + 'a,
{
    move |input| {
        let (mut input, output) = inner.parse(input)?;
        input.save_cursor_before_rtrim();
        let (input, _) = opt(many0(alt((
            multiline_comment,
            singleline_comment,
            value((), multispace1),
        ))))
        .parse(input)?;
        Ok((input, output))
    }
}

/// Left trim the input.
pub(crate) fn ltrim(mut input: Input) -> ParseResult<()> {
    loop {
        match alt((
            multiline_comment,
            singleline_comment,
            value((), multispace1),
        ))
        .parse(input)
        {
            Ok((i, ())) => input = i,
            Err(nom::Err::Error(_)) => return Ok((input, ())),
            err @ Err(_) => return err,
        }
    }
}

/// Accepts a first parser, only if the second one does not match afterwards
pub(crate) fn not_followed<'a, F, G, OF, OG>(
    mut f: F,
    mut g: G,
) -> impl FnMut(Input<'a>) -> ParseResult<'a, OF>
where
    F: Parser<Input<'a>, Output = OF, Error = Error> + 'a,
    G: Parser<Input<'a>, Output = OG, Error = Error> + 'a,
{
    move |input| {
        let (input, output) = f.parse(input)?;
        if g.parse(input).is_ok() {
            return Err(nom::Err::Error(Error::from_error_kind(
                input,
                NomErrorKind::IsNot,
            )));
        }
        Ok((input, output))
    }
}

/// Accepts a single character if the passed function returns true on it.
pub(crate) fn take_one<F>(f: F) -> impl for<'a> Fn(Input<'a>) -> ParseResult<'a, char>
where
    F: Fn(char) -> bool,
{
    move |mut input| match input.cursor().chars().next().map(|c| (c, f(c))) {
        Some((c, true)) => {
            input.advance(c.len_utf8());
            Ok((input, c))
        }
        _ => Err(nom::Err::Error(Error::from_char(input, '0'))),
    }
}

/// Recognize a textual tag.
///
/// This is the same as [`nom::bytes::complete::tag`], but ensures the
/// following character is not alphanumeric.
/// This avoids recognizing a tag inside a word, for example, recognizing
/// `foo` in `foobar`.
pub(crate) fn textual_tag(
    tag: &'static str,
) -> impl for<'a> Fn(Input<'a>) -> ParseResult<'a, &'static str> {
    move |input: Input| {
        if let Some(input) = input.strip_prefix(tag) {
            match input.cursor().chars().next() {
                Some(c) if c.is_alphanumeric() => Err(nom::Err::Error(Error::from_error_kind(
                    input,
                    NomErrorKind::Tag,
                ))),
                _ => Ok((input, tag)),
            }
        } else {
            Err(nom::Err::Error(Error::from_error_kind(
                input,
                NomErrorKind::Tag,
            )))
        }
    }
}

/// Parse a C-style /* ... */ comment.
///
/// Equivalent to the `comment` state in libyara.
fn multiline_comment(input: Input) -> ParseResult<()> {
    value((), (tag("/*"), cut(take_until("*/")), cut(tag("*/")))).parse(input)
}

/// Parse single line // ... comments.
fn singleline_comment(input: Input) -> ParseResult<()> {
    value((), (tag("//"), cut(take_until("\n")), cut(char('\n')))).parse(input)
}

/// Equivalent to [`nom::combinator::map_res`] but expects an
/// [`super::types::ErrorKind`] type of error.
///
/// This allows using the starting input to generate a proper span
/// for the error.
pub(crate) fn map_res<'a, O1, O2, F, G>(
    mut parser: F,
    mut f: G,
) -> impl FnMut(Input<'a>) -> ParseResult<'a, O2>
where
    F: Parser<Input<'a>, Output = O1, Error = Error>,
    G: FnMut(O1) -> Result<O2, ErrorKind>,
{
    move |input: Input| {
        let start = input.pos();
        let (input, o1) = parser.parse(input)?;
        match f(o1) {
            Ok(o2) => Ok((input, o2)),
            Err(kind) => Err(nom::Err::Failure(Error::new(
                input.get_span_from(start),
                kind,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{parse, parse_err};

    fn dummy_parser(input: Input) -> ParseResult<char> {
        char('-')(input)
    }

    #[test]
    fn test_rtrim() {
        parse(dummy_parser, "- b", " b", '-');
        parse(rtrim(dummy_parser), "- b", "b", '-');
        parse(rtrim(dummy_parser), "-/* */ b", "b", '-');
        parse(rtrim(dummy_parser), "- /* */b", "b", '-');
        parse(rtrim(dummy_parser), "- /* */ /* */ b", "b", '-');
        parse(rtrim(dummy_parser), "- // /* foo\n /**/   b", "b", '-');
    }

    #[test]
    fn test_ltrim() {
        parse(ltrim, " - b", "- b", ());
        parse(ltrim, "/* */ - b", "- b", ());
        parse(ltrim, " /* */- b", "- b", ());
        parse(ltrim, "/* */ /* */   b", "b", ());
        parse(ltrim, "// /* foo\n /**/   ", "", ());

        parse_err(ltrim, "/*");
        parse_err(ltrim, "//");
    }

    #[test]
    fn test_take_one() {
        parse(take_one(char::is_lowercase), "bc", "c", 'b');
        parse_err(take_one(char::is_lowercase), "Bc");
    }

    #[test]
    fn test_multiline_comment() {
        parse(multiline_comment, "/**/a", "a", ());
        parse(multiline_comment, "/* a\n */\n", "\n", ());
        parse(multiline_comment, "/*** a\n\n**//* a */c", "/* a */c", ());
        parse(multiline_comment, "/*** a\n//*/\n*/", "\n*/", ());

        parse_err(multiline_comment, "/");
        parse_err(multiline_comment, "/*");
        parse_err(multiline_comment, "/*/");
        parse_err(multiline_comment, "/*\n/*");
        parse_err(multiline_comment, "/ * */");
        parse_err(multiline_comment, "/* * /");
    }

    #[test]
    fn test_singleline_comment() {
        parse(singleline_comment, "//\n", "", ());
        parse(singleline_comment, "// comment\n// 2", "// 2", ());

        parse_err(singleline_comment, "/");
        parse_err(singleline_comment, "//");
        parse_err(singleline_comment, "// comment");
        parse_err(singleline_comment, "// comment //");
    }
}
