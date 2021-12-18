use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, is_not, tag, take_while},
    character::{
        complete::{char, digit1, hex_digit1, oct_digit1, one_of},
        is_hex_digit,
    },
    combinator::{cut, map, map_res, opt, recognize, success, value},
    multi::fold_many_m_n,
    sequence::{pair, preceded, terminated, tuple},
    IResult,
};

// "..."
// control characters: \t, \r, \n, \", \\, \x[0-9a-fA-F]{2}
pub fn quoted_string(input: &str) -> IResult<&str, String> {
    let (input, _) = char('"')(input)?;

    // escaped transform does not handle having no content, so
    // handle empty string explicitly.
    if let Ok((next_input, '"')) = char::<&str, nom::error::Error<&str>>('"')(input) {
        return Ok((next_input, "".to_owned()));
    }

    cut(terminated(
        escaped_transform(
            is_not("\\\n\""),
            '\\',
            alt((
                value('\t', char('t')),
                value('\r', char('r')),
                value('\n', char('n')),
                value('\"', char('\"')),
                value('\\', char('\\')),
                preceded(
                    char('x'),
                    cut(map(
                        fold_many_m_n(
                            2,
                            2,
                            one_of("0123456789abcdefABCDEF"),
                            || 0,
                            |acc, v| (acc << 4) + (v.to_digit(16).unwrap_or(0) as u8),
                        ),
                        |v| v as char,
                    )),
                ),
            )),
        ),
        char('"'),
    ))(input)
}

#[cfg(test)]
mod tests {
    use nom::Finish;

    fn parse<F, O>(f: F, input: &str, expected_rest_input: &str, expected_number: O)
    where
        F: FnOnce(&str) -> nom::IResult<&str, O>,
        O: PartialEq + std::fmt::Debug,
    {
        let res = f(input).unwrap();
        assert_eq!(res.0, expected_rest_input);
        assert_eq!(res.1, expected_number);
    }

    fn parse_err<F, O>(f: F, input: &str)
    where
        F: FnOnce(&str) -> nom::IResult<&str, O>,
        O: PartialEq + std::fmt::Debug,
    {
        let res = f(input).finish();
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_quoted_string() {
        use super::quoted_string;

        parse(quoted_string, "\"\"", "", "".to_owned());
        parse(quoted_string, "\"1\"b", "b", "1".to_owned());
        parse(quoted_string, "\"abc +$\"", "", "abc +$".to_owned());

        parse(
            quoted_string,
            r#"" \r \n \t \"\\a \\r""#,
            "",
            " \r \n \t \"\\a \\r".to_owned(),
        );
        parse(quoted_string, r#""\x10 \x32""#, "", "\u{10} 2".to_owned());
        parse(
            quoted_string,
            r#""\x00 \xFF""#,
            "",
            "\u{00} \u{FF}".to_owned(),
        );

        parse_err(quoted_string, "a");
        parse_err(quoted_string, "\"");
        parse_err(quoted_string, "\"\n\"");
        parse_err(quoted_string, "\"\n\"");
        parse_err(quoted_string, r#""\a""#);
    }
}
