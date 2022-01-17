//! Parse yara rules.
//!
//! Missing features:
//!  - Xor range modifier on strings
//!  - base64 alphabet modifier on strings
use nom::{
    branch::alt,
    character::complete::char,
    combinator::{cut, map, map_res, opt},
    error::{Error, ErrorKind, FromExternalError},
    multi::many1,
    sequence::{delimited, pair, preceded, separated_pair, tuple},
    IResult,
};

use super::{
    expression::{self, ParsedExpr},
    hex_string,
    nom_recipes::{rtrim, textual_tag as ttag},
    number, string,
};
use crate::rule::StringDeclarationValue;
use crate::rule::{Metadata, MetadataValue, Rule, StringFlags};
use crate::{expression::Expression, rule::StringDeclaration};

/// Parse a rule
///
/// Related to the `rule` pattern in `grammar.y` in libyara.
pub fn rule(mut input: &str) -> IResult<&str, Rule> {
    let mut is_private = false;
    let mut is_global = false;

    loop {
        match rtrim(ttag("rule"))(input) {
            Ok((i, _)) => {
                input = i;
                break;
            }
            Err(e) => {
                if let Ok((i, _)) = rtrim(ttag("private"))(input) {
                    input = i;
                    is_private = true;
                } else if let Ok((i, _)) = rtrim(ttag("global"))(input) {
                    input = i;
                    is_global = true;
                } else {
                    return Err(e);
                }
            }
        }
    }

    map(
        tuple((
            string::identifier,
            opt(tags),
            delimited(
                rtrim(char('{')),
                tuple((opt(meta), opt(strings), condition)),
                rtrim(char('}')),
            ),
        )),
        move |(name, tags, (meta, strings, condition))| Rule {
            name,
            tags: tags.unwrap_or_else(Vec::new),
            metadatas: meta.unwrap_or_else(Vec::new),
            strings: strings.unwrap_or_else(Vec::new),
            condition,
            is_private,
            is_global,
        },
    )(input)
}

/// Parse a list of tags
///
/// This roughly parses `: identifier1 identifier2 ...`
/// and returns a list of the identifiers.
fn tags(input: &str) -> IResult<&str, Vec<String>> {
    let (input, _) = rtrim(char(':'))(input)?;

    cut(many1(string::identifier))(input)
}

/// Parse the "meta:" section in a rule.
///
/// Related to the `meta` and `meta_declarations` patterns
/// in `grammar.y` in libyara.
fn meta(input: &str) -> IResult<&str, Vec<Metadata>> {
    preceded(
        pair(rtrim(ttag("meta")), rtrim(char(':'))),
        cut(many1(meta_declaration)),
    )(input)
}

/// Parse a single metadata declaration.
///
/// Related to the `meta_declaration` pattern in `grammar.y` in libyara.
fn meta_declaration(input: &str) -> IResult<&str, Metadata> {
    map(
        separated_pair(
            string::identifier,
            rtrim(char('=')),
            alt((
                map(string::quoted, MetadataValue::String),
                map(number::number, MetadataValue::Number),
                map(preceded(rtrim(char('-')), number::number), |v| {
                    MetadataValue::Number(-v)
                }),
                map(rtrim(ttag("true")), |_| MetadataValue::Boolean(true)),
                map(rtrim(ttag("false")), |_| MetadataValue::Boolean(false)),
            )),
        ),
        |(name, value)| Metadata { name, value },
    )(input)
}

/// Parse the "strings:" section
///
/// Related to the `strings` and `strings_declarations` pattern
/// in `grammar.y` in libyara.
fn strings(input: &str) -> IResult<&str, Vec<StringDeclaration>> {
    preceded(
        pair(rtrim(ttag("strings")), rtrim(char(':'))),
        cut(many1(string_declaration)),
    )(input)
}

/// Parse a single string declaration.
///
/// Related to the `string_declaration` pattern in `grammar.y` in libyara.
fn string_declaration(input: &str) -> IResult<&str, StringDeclaration> {
    map(
        separated_pair(
            string::string_identifier,
            rtrim(char('=')),
            alt((
                pair(
                    map(string::quoted, StringDeclarationValue::String),
                    string_modifiers,
                ),
                pair(
                    map(string::regex, StringDeclarationValue::Regex),
                    regex_modifiers,
                ),
                pair(
                    map(hex_string::hex_string, StringDeclarationValue::HexString),
                    hex_string_modifiers,
                ),
            )),
        ),
        |(name, (value, modifiers))| StringDeclaration {
            name,
            value,
            modifiers,
        },
    )(input)
}

fn accumulate_modifiers<F>(parser: F, mut input: &str) -> IResult<&str, StringFlags>
where
    F: Fn(&str) -> IResult<&str, StringFlags>,
{
    let mut flags = StringFlags::empty();

    while let Ok((i, flag)) = parser(input) {
        if flags.contains(flag) {
            return Err(nom::Err::Failure(Error::from_external_error(
                input,
                ErrorKind::Verify,
                format!("flag {:?} duplicated", flag),
            )));
        }
        input = i;
        flags |= flag;
    }
    Ok((input, flags))
}

fn string_modifiers(input: &str) -> IResult<&str, StringFlags> {
    accumulate_modifiers(string_modifier, input)
}

fn regex_modifiers(input: &str) -> IResult<&str, StringFlags> {
    accumulate_modifiers(regex_modifier, input)
}

fn hex_string_modifiers(input: &str) -> IResult<&str, StringFlags> {
    accumulate_modifiers(hex_string_modifier, input)
}

fn string_modifier(input: &str) -> IResult<&str, StringFlags> {
    rtrim(alt((
        map(ttag("wide"), |_| StringFlags::WIDE),
        map(ttag("ascii"), |_| StringFlags::ASCII),
        map(ttag("nocase"), |_| StringFlags::NOCASE),
        map(ttag("fullword"), |_| StringFlags::FULLWORD),
        map(ttag("private"), |_| StringFlags::PRIVATE),
        map(ttag("xor"), |_| StringFlags::XOR),
        map(ttag("base64"), |_| StringFlags::BASE64),
        map(ttag("base64wide"), |_| StringFlags::BASE64WIDE),
    )))(input)
}

fn regex_modifier(input: &str) -> IResult<&str, StringFlags> {
    rtrim(alt((
        map(ttag("wide"), |_| StringFlags::WIDE),
        map(ttag("ascii"), |_| StringFlags::ASCII),
        map(ttag("nocase"), |_| StringFlags::NOCASE),
        map(ttag("fullword"), |_| StringFlags::FULLWORD),
        map(ttag("private"), |_| StringFlags::PRIVATE),
    )))(input)
}

fn hex_string_modifier(input: &str) -> IResult<&str, StringFlags> {
    map(rtrim(ttag("private")), |_| StringFlags::PRIVATE)(input)
}

/// Parse a condition
///
/// Related to the `condition` pattern in `grammar.y` in libyara.
fn condition(input: &str) -> IResult<&str, Expression> {
    let (input, _) = rtrim(ttag("condition"))(input)?;

    map_res(
        cut(preceded(rtrim(char(':')), expression::expression)),
        ParsedExpr::validate_boolean_expression,
    )(input)
}

#[cfg(test)]
mod tests {
    use crate::hex_string::{HexToken, Mask};
    use crate::regex::Regex;

    use super::super::test_utils::{parse, parse_err};
    use super::*;

    #[test]
    fn parse_tags() {
        parse(
            tags,
            ": a _ a8 {",
            "{",
            vec!["a".to_owned(), "_".to_owned(), "a8".to_owned()],
        );
        parse(tags, ": b 8", "8", vec!["b".to_owned()]);

        parse_err(tags, "");
        parse_err(tags, ":");
        parse_err(tags, ": {");
    }

    #[test]
    fn parse_meta() {
        parse(
            meta,
            "meta : a = 3 b =-4 _=true d",
            "d",
            vec![
                Metadata {
                    name: "a".to_owned(),
                    value: MetadataValue::Number(3),
                },
                Metadata {
                    name: "b".to_owned(),
                    value: MetadataValue::Number(-4),
                },
                Metadata {
                    name: "_".to_owned(),
                    value: MetadataValue::Boolean(true),
                },
            ],
        );
        parse(
            meta,
            "meta:\n  a = \" a\rb \"  \n  b= false \n  strings",
            "strings",
            vec![
                Metadata {
                    name: "a".to_owned(),
                    value: MetadataValue::String(" a\rb ".to_owned()),
                },
                Metadata {
                    name: "b".to_owned(),
                    value: MetadataValue::Boolean(false),
                },
            ],
        );
        parse(
            meta,
            "meta: a = false test = True",
            "test = True",
            vec![Metadata {
                name: "a".to_owned(),
                value: MetadataValue::Boolean(false),
            }],
        );

        parse_err(meta, "");
        parse_err(meta, "meta");
        parse_err(meta, "meta:");
    }

    #[test]
    fn parse_modifiers() {
        parse(
            string_modifiers,
            "private wide ascii xor base64wide nocase fullword base64 Xor",
            "Xor",
            StringFlags::PRIVATE
                | StringFlags::WIDE
                | StringFlags::ASCII
                | StringFlags::XOR
                | StringFlags::BASE64WIDE
                | StringFlags::NOCASE
                | StringFlags::FULLWORD
                | StringFlags::BASE64,
        );

        parse(
            regex_modifiers,
            "private wide ascii nocase fullword base64",
            "base64",
            StringFlags::PRIVATE
                | StringFlags::WIDE
                | StringFlags::ASCII
                | StringFlags::NOCASE
                | StringFlags::FULLWORD,
        );

        parse(
            hex_string_modifiers,
            "private wide",
            "wide",
            StringFlags::PRIVATE,
        );

        parse_err(string_modifier, "");
        parse_err(string_modifier, "w");

        parse_err(regex_modifier, "");
        parse_err(regex_modifier, "w");
        parse_err(regex_modifier, "base64");
        parse_err(regex_modifier, "base64wide");
        parse_err(regex_modifier, "xor");

        parse_err(hex_string_modifier, "");
        parse_err(hex_string_modifier, "w");
        parse_err(hex_string_modifier, "ascii");
        parse_err(hex_string_modifier, "wide");
        parse_err(hex_string_modifier, "nocase");
        parse_err(hex_string_modifier, "fullword");
        parse_err(hex_string_modifier, "base64");
        parse_err(hex_string_modifier, "base64wide");
        parse_err(hex_string_modifier, "xor");
    }

    #[test]
    fn parse_strings() {
        parse(
            strings,
            "strings : $a = \"b\td\" xor ascii \n  $b= /a?b/  $c= { ?B} private d",
            "d",
            vec![
                StringDeclaration {
                    name: "a".to_owned(),
                    value: StringDeclarationValue::String("b\td".to_owned()),
                    modifiers: StringFlags::XOR | StringFlags::ASCII,
                },
                StringDeclaration {
                    name: "b".to_owned(),
                    value: StringDeclarationValue::Regex(Regex {
                        expr: "a?b".to_owned(),
                        case_insensitive: false,
                        dot_all: false,
                    }),
                    modifiers: StringFlags::empty(),
                },
                StringDeclaration {
                    name: "c".to_owned(),
                    value: StringDeclarationValue::HexString(vec![HexToken::MaskedByte(
                        0x0B,
                        Mask::Left,
                    )]),
                    modifiers: StringFlags::PRIVATE,
                },
            ],
        );

        parse_err(strings, "");
        parse_err(strings, "strings");
        parse_err(strings, "strings:");
    }

    #[test]
    fn parse_rule() {
        parse(
            rule,
            "rule a { condition: false }",
            "",
            Rule {
                name: "a".to_owned(),
                condition: Expression::Boolean(false),
                tags: Vec::new(),
                metadatas: Vec::new(),
                strings: Vec::new(),
                is_private: false,
                is_global: false,
            },
        );
        parse(
            rule,
            "private global rule b : tag1 tag2 { meta: a = true strings: $b = \"t\" condition: false }",
            "",
            Rule {
                name: "b".to_owned(),
                tags: vec!["tag1".to_owned(), "tag2".to_owned()],
                metadatas: vec![
                    Metadata { name: "a".to_owned(), value: MetadataValue::Boolean(true) }
                ],
                strings: vec![
                    StringDeclaration {
                        name: "b".to_owned(),
                        value: StringDeclarationValue::String("t".to_owned()),
                        modifiers: StringFlags::empty()
                    }
                ],
                condition: Expression::Boolean(false),
                is_private: true,
                is_global: true,
            },
        );

        parse(
            rule,
            "global private rule c { condition: false }",
            "",
            Rule {
                name: "c".to_owned(),
                condition: Expression::Boolean(false),
                tags: Vec::new(),
                metadatas: Vec::new(),
                strings: Vec::new(),
                is_private: true,
                is_global: true,
            },
        );
        parse(
            rule,
            "private rule c { condition: false }",
            "",
            Rule {
                name: "c".to_owned(),
                condition: Expression::Boolean(false),
                tags: Vec::new(),
                metadatas: Vec::new(),
                strings: Vec::new(),
                is_private: true,
                is_global: false,
            },
        );
        parse(
            rule,
            "global rule c { condition: false }",
            "",
            Rule {
                name: "c".to_owned(),
                condition: Expression::Boolean(false),
                tags: Vec::new(),
                metadatas: Vec::new(),
                strings: Vec::new(),
                is_private: false,
                is_global: true,
            },
        );

        parse_err(rule, "");
        parse_err(rule, "rule");
        parse_err(rule, "rule {}");
        parse_err(rule, "rule a {}");
        parse_err(rule, "rule b { condition true }");
        parse_err(
            rule,
            "rule c { strings: $a = /a/ meta: a = 3 condition: true }",
        );
        parse_err(rule, "rule d { condition: true");
    }

    // Test that we use textual tags
    #[test]
    fn test_tags() {
        parse_err(rule, "rulea{condition:true}");
        parse_err(rule, "privaterule a{condition:true}");
        parse_err(rule, "globalrule a{condition:true}");

        parse_err(meta, "meta: a=trueb=false");
        parse_err(meta, "meta: a=falseb=true");

        parse_err(string_modifier, "widexor");
        parse_err(string_modifier, "asciixor");
        parse_err(string_modifier, "nocasexor");
        parse_err(string_modifier, "fullwordxor");
        parse_err(string_modifier, "privatexor");
        parse_err(string_modifier, "xorwide");
        parse_err(string_modifier, "base64xor");
        parse_err(string_modifier, "base64widexor");

        parse_err(regex_modifier, "widexor");
        parse_err(regex_modifier, "asciixor");
        parse_err(regex_modifier, "nocasexor");
        parse_err(regex_modifier, "fullwordxor");
        parse_err(regex_modifier, "privatexor");

        parse_err(hex_string_modifier, "privatexor");
    }
}
