//! Parse yara rules.
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, map, opt},
    multi::many1,
    sequence::{delimited, pair, preceded, separated_pair, tuple},
    IResult,
};

use super::{hex_string, nom_recipes::rtrim, number, string};

/// A Yara rule.
#[derive(Debug, Default, PartialEq)]
pub struct Rule {
    /// Name of the rule.
    name: String,

    /// Tags associated with the rule
    tags: Vec<String>,

    /// Metadata associated with the rule.
    metadatas: Vec<Metadata>,

    /// Strings associated with the rule.
    strings: Vec<StringDeclaration>,

    /// Condition of the rule.
    condition: String,

    // Is the rule private.
    is_private: bool,
    // Is the rule global.
    is_global: bool,
}

/// Parse a rule
///
/// Related to the `rule` pattern in `grammar.y` in libyara.
pub fn rule(mut input: &str) -> IResult<&str, Rule> {
    let mut is_private = false;
    let mut is_global = false;

    loop {
        match rtrim(tag("rule"))(input) {
            Ok((i, _)) => {
                input = i;
                break;
            }
            Err(e) => {
                if let Ok((i, _)) = rtrim(tag("private"))(input) {
                    input = i;
                    is_private = true;
                } else if let Ok((i, _)) = rtrim(tag("global"))(input) {
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

/// Value associated with a metadata key.
#[derive(Debug, PartialEq)]
enum MetadataValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

/// A metadata key-value, associated with a rule.
#[derive(Debug, PartialEq)]
struct Metadata {
    /// Name of the metadata.
    name: String,
    /// Value of the metadata.
    value: MetadataValue,
}

/// Parse the "meta:" section in a rule.
///
/// Related to the `meta` and `meta_declarations` patterns
/// in `grammar.y` in libyara.
fn meta(input: &str) -> IResult<&str, Vec<Metadata>> {
    preceded(
        pair(rtrim(tag("meta")), rtrim(char(':'))),
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
                map(rtrim(tag("true")), |_| MetadataValue::Boolean(true)),
                map(rtrim(tag("false")), |_| MetadataValue::Boolean(false)),
            )),
        ),
        |(name, value)| Metadata { name, value },
    )(input)
}

/// Value for a string associated with a rule.
#[derive(Debug, PartialEq)]
enum StringDeclarationValue {
    /// A raw string.
    String(String),
    /// A regular expression.
    Regex(string::Regex),
    /// A hex string.
    HexString(hex_string::HexString),
}

/// String declared in a rule.
#[derive(Debug, PartialEq)]
struct StringDeclaration {
    /// Name of the string.
    name: String,
    /// Value of the string.
    value: StringDeclarationValue,
}

/// Parse the "strings:" section
///
/// Related to the `strings` and `strings_declarations` pattern
/// in `grammar.y` in libyara.
fn strings(input: &str) -> IResult<&str, Vec<StringDeclaration>> {
    preceded(
        pair(rtrim(tag("strings")), rtrim(char(':'))),
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
                map(string::quoted, StringDeclarationValue::String),
                map(string::regex, StringDeclarationValue::Regex),
                map(hex_string::hex_string, StringDeclarationValue::HexString),
            )),
        ),
        |(name, value)| StringDeclaration { name, value },
    )(input)
}

/// Parse a condition
///
/// Related to the `condition` pattern in `grammar.y` in libyara.
fn condition(input: &str) -> IResult<&str, String> {
    let (input, _) = rtrim(tag("condition"))(input)?;

    cut(preceded(rtrim(char(':')), boolean_expression))(input)
}

fn boolean_expression(input: &str) -> IResult<&str, String> {
    // TODO
    string::identifier(input)
}

#[cfg(test)]
mod tests {
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
    fn parse_strings() {
        use super::super::hex_string::{HexToken, Mask};
        use super::super::string::Regex;

        parse(
            strings,
            "strings : $a = \"b\td\" \n  $b= /a?b/  $c= { ?B} d",
            "d",
            vec![
                StringDeclaration {
                    name: "a".to_owned(),
                    value: StringDeclarationValue::String("b\td".to_owned()),
                },
                StringDeclaration {
                    name: "b".to_owned(),
                    value: StringDeclarationValue::Regex(Regex {
                        expr: "a?b".to_owned(),
                        case_insensitive: false,
                        dot_all: false,
                    }),
                },
                StringDeclaration {
                    name: "c".to_owned(),
                    value: StringDeclarationValue::HexString(vec![HexToken::MaskedByte(
                        0x0B,
                        Mask::Left,
                    )]),
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
                condition: "false".to_owned(),
                ..Rule::default()
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
                    StringDeclaration { name: "b".to_owned(), value: StringDeclarationValue::String("t".to_owned()) }
                ],
                condition: "false".to_owned(),
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
                condition: "false".to_owned(),
                is_private: true,
                is_global: true,
                ..Rule::default()
            },
        );
        parse(
            rule,
            "private rule c { condition: false }",
            "",
            Rule {
                name: "c".to_owned(),
                condition: "false".to_owned(),
                is_private: true,
                ..Rule::default()
            },
        );
        parse(
            rule,
            "global rule c { condition: false }",
            "",
            Rule {
                name: "c".to_owned(),
                condition: "false".to_owned(),
                is_global: true,
                ..Rule::default()
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
}
