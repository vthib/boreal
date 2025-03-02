//! Parsing related to strings and identifiers.

use nom::bytes::complete::take_while;
use nom::character::complete::char;
use nom::combinator::{cut, map, opt, recognize};
use nom::error::{ErrorKind as NomErrorKind, ParseError};
use nom::sequence::{pair, preceded};
use nom::Parser;

use super::error::Error;
use super::nom_recipes::{rtrim, take_one};
use super::types::{Input, ParseResult};

/// Returns true if the char is an identifier digit, ie a-z, a-Z, 0-9, _
fn is_identifier_digit(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
}

/// Parse the contents of an identifier string.
///
/// This is always the rest of an identifier type, where the first
/// character determines which type of identifier is being parsed.
///
/// This function *does not* right-trim, as it can be followed
/// by a '*' character that is meaningful in some contexts.
fn identifier_contents(input: Input) -> ParseResult<String> {
    map(take_while(is_identifier_digit), |input: Input| {
        input.cursor().to_owned()
    })
    .parse(input)
}

/// Helper for [`string_identifier`] and [`string_identifier_with_wildcard`].
fn string_identifier_no_rtrim(input: Input) -> ParseResult<String> {
    preceded(char('$'), cut(identifier_contents)).parse(input)
}

/// Parse a string identifier.
///
/// This is equivalent to the `_STRING_IDENTIFIER_` lexical patterns in
/// libyara.
/// Roughly equivalent to `$[a-ZA-Z0-9_]*`.
pub(crate) fn string_identifier(input: Input) -> ParseResult<String> {
    rtrim(string_identifier_no_rtrim).parse(input)
}

/// Parse a string identifier with an optional trailing wildcard.
///
/// This is equivalent to
/// `_STRING_IDENTIFIER_ | _STRING_IDENTIFIER_WITH_WILDCARD_` in libyara.
pub(crate) fn string_identifier_with_wildcard(input: Input) -> ParseResult<(String, bool)> {
    rtrim(pair(
        string_identifier_no_rtrim,
        map(opt(char('*')), |v| v.is_some()),
    ))
    .parse(input)
}

/// Parse a string count, roughly equivalent to `#[a-zA-Z0-9_]*`.
pub(crate) fn count(input: Input) -> ParseResult<String> {
    rtrim(preceded(char('#'), cut(identifier_contents))).parse(input)
}

/// Parse a string offset, roughly equivalent to `@[a-zA-Z0-9_]*`.
pub(crate) fn offset(input: Input) -> ParseResult<String> {
    rtrim(preceded(char('@'), cut(identifier_contents))).parse(input)
}

/// Parse a string length, roughly equivalent to `![a-zA-Z0-9_]*`.
pub(crate) fn length(input: Input) -> ParseResult<String> {
    rtrim(preceded(char('!'), cut(identifier_contents))).parse(input)
}

/// Parse an identifier.
///
/// This is roughly equivalent to `[a-ZA-Z_][a-zA-Z0-9_]*`.
pub(crate) fn identifier(input: Input) -> ParseResult<String> {
    rtrim(map(
        recognize((
            take_one(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '_')),
            cut(take_while(is_identifier_digit)),
        )),
        |input| input.cursor().to_owned(),
    ))
    .parse(input)
}

/// Parse a quoted string with escapable characters.
///
/// Equivalent to the `_TEXT_STRING_` lexical pattern in libyara.
/// This is roughly equivalent to the pattern `/"[^\n\"]*"/`, with control
/// patterns `\t`, `\r`, `\n`, `\"`, `\\`, and `\x[0-9a-fA-F]{2}`.
///
/// This parser allows non ascii bytes, hence returning a byte string.
pub(crate) fn quoted(input: Input) -> ParseResult<Vec<u8>> {
    rtrim(quoted_no_rtrim).parse(input)
}

fn quoted_no_rtrim(input: Input) -> ParseResult<Vec<u8>> {
    let (mut input, _) = char('"').parse(input)?;

    let mut index = 0;
    let mut res = Vec::new();

    let mut chars = input.cursor().char_indices();

    while let Some((i, c)) = chars.next() {
        index = i;
        match c {
            '\\' => match chars.next() {
                Some((_, 't')) => res.push(b'\t'),
                Some((_, 'r')) => res.push(b'\r'),
                Some((_, 'n')) => res.push(b'\n'),
                Some((_, '"')) => res.push(b'"'),
                Some((_, '\\')) => res.push(b'\\'),
                Some((_, 'x')) => match (chars.next(), chars.next()) {
                    (Some((i1, a)), Some((i2, b))) => {
                        let Some(a) = a.to_digit(16) else {
                            index = i1;
                            break;
                        };
                        let Some(b) = b.to_digit(16) else {
                            index = i2;
                            break;
                        };
                        #[allow(clippy::cast_possible_truncation)]
                        res.push(((a as u8) << 4) + (b as u8));
                    }
                    _ => break,
                },
                Some((j, _)) => {
                    index = j;
                    break;
                }
                None => break,
            },
            '"' => {
                input.advance(i + 1);
                return Ok((input, res));
            }
            c => {
                let mut buf = [0; 4];
                let _r = c.encode_utf8(&mut buf);
                res.extend(&buf[..c.len_utf8()]);
            }
        }
    }

    input.advance(index);
    Err(nom::Err::Error(Error::from_error_kind(
        input,
        NomErrorKind::EscapedTransform,
    )))
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{parse, parse_err};

    #[test]
    fn test_parse_quoted() {
        use super::quoted;

        parse(quoted, "\"\" b", "b", "");
        parse(quoted, "\"1\"b", "b", "1");
        parse(quoted, "\"abc +$\" b", "b", "abc +$");

        parse(
            quoted,
            r#"" \r \n \t \"\\a \\r""#,
            "",
            " \r \n \t \"\\a \\r",
        );
        parse(quoted, r#""\x10 \x32""#, "", "\u{10} 2");
        parse(quoted, r#""\x00 \xFF""#, "", [0, b' ', 255]);

        parse(quoted, r#""\xc3\x0f]\x00""#, "", [0xc3, 0x0f, b']', 0x00]);

        parse(quoted, r#""é"a"#, "a", [0xc3, 0xa9]);

        parse_err(quoted, "a");
        parse_err(quoted, r#"""#);
        parse_err(quoted, r#""ab"#);
        parse_err(quoted, r#""a\"#);
        parse_err(quoted, r#""a\xAG""#);
        parse_err(quoted, r#""a\xGA""#);
        parse_err(quoted, r#""\a""#);
        parse_err(quoted, r#""\x"#);
        parse_err(quoted, r#""\x1"#);
        parse_err(quoted, r#""\x1""#);
    }

    #[test]
    fn test_string_identifier() {
        use super::string_identifier;

        parse(string_identifier, "$-", "-", "");
        parse(string_identifier, "$*", "*", "");
        parse(string_identifier, "$a c", "c", "a");
        parse(string_identifier, "$9b*c", "*c", "9b");
        parse(string_identifier, "$_1Bd_F+", "+", "_1Bd_F");

        parse_err(string_identifier, "");
        parse_err(string_identifier, "*");
    }

    #[test]
    fn test_string_identifier_with_wildcard() {
        use super::string_identifier_with_wildcard as siww;

        parse(siww, "$_*", "", ("_".to_owned(), true));
        parse(siww, "$", "", (String::new(), false));
        parse(siww, "$a* c", "c", ("a".to_owned(), true));
        parse(siww, "$9b*c", "c", ("9b".to_owned(), true));
        parse(siww, "$_1Bd_F+", "+", ("_1Bd_F".to_owned(), false));

        parse_err(siww, "");
        parse_err(siww, "*");
    }

    #[test]
    fn test_count() {
        use super::count;

        parse(count, "#-", "-", "");
        parse(count, "#*", "*", "");
        parse(count, "#a c", "c", "a");
        parse(count, "#9b*c", "*c", "9b");
        parse(count, "#_1Bd_F+", "+", "_1Bd_F");

        parse_err(count, "");
        parse_err(count, "$");
        parse_err(count, "@");
        parse_err(count, "!");
        parse_err(count, "*");
    }

    #[test]
    fn test_offset() {
        use super::offset;

        parse(offset, "@-", "-", "");
        parse(offset, "@*", "*", "");
        parse(offset, "@a c", "c", "a");
        parse(offset, "@9b*c", "*c", "9b");
        parse(offset, "@_1Bd_F+", "+", "_1Bd_F");

        parse_err(offset, "");
        parse_err(offset, "$");
        parse_err(offset, "#");
        parse_err(offset, "!");
        parse_err(offset, "*");
    }

    #[test]
    fn test_length() {
        use super::length;

        parse(length, "!-", "-", "");
        parse(length, "!*", "*", "");
        parse(length, "!a c", "c", "a");
        parse(length, "!9b*c", "*c", "9b");
        parse(length, "!_1Bd_F+", "+", "_1Bd_F");

        parse_err(length, "");
        parse_err(length, "$");
        parse_err(length, "#");
        parse_err(length, "@");
        parse_err(length, "*");
    }

    #[test]
    fn test_identifier() {
        use super::identifier;

        parse(identifier, "a+", "+", "a");
        parse(identifier, "_*", "*", "_");
        parse(identifier, "A5 c", "c", "A5");
        parse(identifier, "g9b*c", "*c", "g9b");
        parse(identifier, "__1Bd_F+", "+", "__1Bd_F");

        parse_err(identifier, "");
        parse_err(identifier, "*");
        parse_err(identifier, "$");
        parse_err(identifier, "9");
        parse_err(identifier, "9b");
    }
}
