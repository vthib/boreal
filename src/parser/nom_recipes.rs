//! Some common and useful nom recipes, shared by all other modules.

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{char, multispace0},
    combinator::{opt, value},
    error::{Error, ErrorKind, ParseError as NomParseError},
    sequence::{pair, preceded, tuple},
    Parser,
};

use super::types::{Input, ParseError, ParseResult};

/// Right trim after the given parser.
pub fn rtrim<'a, F: 'a, O>(mut inner: F) -> impl FnMut(Input<'a>) -> ParseResult<'a, O>
where
    F: Parser<Input<'a>, O, ParseError<'a>>,
{
    move |mut input| {
        input.save_cursor_before_rtrim();
        let (input, output) = inner.parse(input)?;
        let (input, _) = pair(
            multispace0,
            opt(alt((multiline_comment, singleline_comment))),
        )
        .parse(input)?;
        Ok((input, output))
    }
}

/// Left trim before the given parser.
pub fn ltrim<'a, F: 'a, O>(inner: F) -> impl FnMut(Input<'a>) -> ParseResult<'a, O>
where
    F: FnMut(Input<'a>) -> ParseResult<'a, O>,
{
    preceded(
        pair(
            multispace0,
            opt(alt((multiline_comment, singleline_comment))),
        ),
        inner,
    )
}

/// Accepts a single character if the passed function returns true on it.
pub fn take_one<F>(f: F) -> impl for<'a> Fn(Input<'a>) -> ParseResult<'a, char>
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
pub fn textual_tag(
    tag: &'static str,
) -> impl for<'a> Fn(Input<'a>) -> ParseResult<'a, &'static str> {
    move |input: Input| {
        if let Some(input) = input.strip_prefix(tag) {
            match input.cursor().chars().next() {
                Some(c) if c.is_alphanumeric() => Err(nom::Err::Error(Error::from_error_kind(
                    input,
                    ErrorKind::Tag,
                ))),
                _ => Ok((input, tag)),
            }
        } else {
            Err(nom::Err::Error(Error::from_error_kind(
                input,
                ErrorKind::Tag,
            )))
        }
    }
}

/// Parse a C-style /* ... */ comment.
///
/// Equivalent to the `comment` state in libyara.
fn multiline_comment(input: Input) -> ParseResult<()> {
    rtrim(value((), tuple((tag("/*"), take_until("*/"), tag("*/")))))(input)
}

/// Parse single line // ... comments.
fn singleline_comment(input: Input) -> ParseResult<()> {
    rtrim(value((), tuple((tag("//"), take_until("\n"), char('\n')))))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::tests::{parse, parse_err};

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
        parse(ltrim(dummy_parser), " - b", " b", '-');
        parse(ltrim(dummy_parser), "/* */ - b", " b", '-');
        parse(ltrim(dummy_parser), " /* */- b", " b", '-');
        parse(ltrim(dummy_parser), "/* */ /* */  - b", " b", '-');
        parse(ltrim(dummy_parser), "// /* foo\n /**/   -b", "b", '-');
    }

    #[test]
    fn test_take_one() {
        parse(take_one(char::is_lowercase), "bc", "c", 'b');
        parse_err(take_one(char::is_lowercase), "Bc");
    }

    #[test]
    fn test_multiline_comment() {
        parse(multiline_comment, "/**/a", "a", ());
        parse(multiline_comment, "/* a\n */\n", "", ());
        parse(multiline_comment, "/*** a\n\n**//* a */c", "c", ());
        parse(multiline_comment, "/*** a\n//*/\n*/", "*/", ());

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
