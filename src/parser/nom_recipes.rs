//! Some common and useful nom recipes, shared by all other modules.

use nom::{
    character::complete::multispace0,
    error::{Error, ParseError},
    sequence::terminated,
    IResult,
};

// TODO: have a "tag" equivalent, that enforces that the following character
// is not alnum.
// For example, string modifiers should be split by whitespace, but shouldn't
// force a trailing whitespace.

/// Right trim after the given parser.
pub fn rtrim<'a, F: 'a, O>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    terminated(inner, multispace0)
}

/// Accepts a single character if the passed function returns true on it.
pub fn take_one<F>(f: F) -> impl Fn(&str) -> IResult<&str, char>
where
    F: Fn(char) -> bool,
{
    move |input| match input.chars().next().map(|c| (c, f(c))) {
        Some((c, true)) => Ok((&input[c.len_utf8()..], c)),
        _ => Err(nom::Err::Error(Error::from_char(input, '0'))),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::{parse, parse_err};

    fn dummy_parser(input: &str) -> nom::IResult<&str, char> {
        nom::character::complete::char('-')(input)
    }

    #[test]
    fn test_rtrim() {
        use super::rtrim;

        parse(dummy_parser, "- b", " b", '-');
        parse(rtrim(dummy_parser), "- b", "b", '-');
    }

    #[test]
    fn test_take_one() {
        use super::take_one;

        parse(take_one(char::is_lowercase), "bc", "c", 'b');
        parse_err(take_one(char::is_lowercase), "Bc");
    }
}
