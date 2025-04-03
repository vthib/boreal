//! Parse yara rules.
use std::ops::Range;

use nom::branch::alt;
use nom::character::complete::char;
use nom::combinator::{cut, map, opt};
use nom::multi::many1;
use nom::sequence::{delimited, pair, preceded, separated_pair};
use nom::Parser;

use super::{
    error::{Error, ErrorKind},
    expression::{self, Expression},
    hex_string,
    nom_recipes::{map_res, rtrim, textual_tag as ttag},
    number, regex,
    regex::Regex,
    string,
    types::{Input, ParseResult, Position},
};

/// A Yara rule.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Name of the rule.
    pub name: String,

    /// Span for the rule name.
    pub name_span: Range<usize>,

    /// Tags associated with the rule.
    pub tags: Vec<RuleTag>,

    /// Metadata associated with the rule.
    pub metadatas: Vec<Metadata>,

    /// Variables associated with the rule.
    ///
    /// In Yara terms, those are "strings" (and they are declared
    /// with the "strings:" declaration in a rule).
    /// However, the "string" denomination is exceedingly confusing in the
    /// implementation. Instead, name those "variables", as they are
    /// declared with a prefix '$', which in multiple languages
    /// indicates variables.
    pub variables: Vec<VariableDeclaration>,

    /// Condition of the rule.
    pub condition: Expression,

    /// Is the rule private.
    pub is_private: bool,
    /// Is the rule global.
    pub is_global: bool,
}

/// Tag for a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleTag {
    /// The tag name.
    pub tag: String,

    /// Span covering the tag.
    pub span: Range<usize>,
}

/// Value associated with a metadata key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataValue {
    /// Bytestring variant.
    Bytes(Vec<u8>),
    /// Integer variant.
    Integer(i64),
    /// Boolean variant.
    Boolean(bool),
}

/// A metadata key-value, associated with a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// Name of the metadata.
    pub name: String,
    /// Value of the metadata.
    pub value: MetadataValue,
}

/// Value for a string associated with a rule.
#[derive(Clone, Debug, PartialEq)]
pub enum VariableDeclarationValue {
    /// A raw byte string.
    Bytes(Vec<u8>),
    /// A regular expression.
    Regex(Regex),
    /// A hex string.
    HexString(Vec<hex_string::Token>),
}

/// Modifiers applicable on a string.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
// Completely useless lint
#[allow(clippy::struct_excessive_bools)]
pub struct VariableModifiers {
    /// Wide modifier.
    pub wide: bool,

    /// Ascii modifier.
    pub ascii: bool,

    /// Nocase modifier.
    pub nocase: bool,

    /// Fullword modifier.
    pub fullword: bool,

    /// Private modifier.
    pub private: bool,

    /// Xor modifier, providing the range.
    pub xor: Option<(u8, u8)>,

    /// Base64 modifier.
    pub base64: Option<VariableModifierBase64>,
}

/// Base64 variable modifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableModifierBase64 {
    /// Wide version.
    pub wide: bool,

    /// Ascii verison.
    pub ascii: bool,

    /// Alphabet to use to deserialize, if provided.
    pub alphabet: Option<[u8; 64]>,
}

/// String declared in a rule.
#[derive(Clone, Debug, PartialEq)]
pub struct VariableDeclaration {
    /// Name of the string.
    pub name: String,
    /// Value of the string.
    pub value: VariableDeclarationValue,
    /// Modifiers for the string.
    pub modifiers: VariableModifiers,
    /// Span for the whole declaration
    pub span: Range<usize>,
}

/// Parse a rule
///
/// Related to the `rule` pattern in `grammar.y` in libyara.
pub(crate) fn rule(mut input: Input) -> ParseResult<Rule> {
    let mut is_private = false;
    let mut is_global = false;

    loop {
        match rtrim(ttag("rule")).parse(input) {
            Ok((i, _)) => {
                input = i;
                break;
            }
            Err(e) => {
                if let Ok((i, _)) = rtrim(ttag("private")).parse(input) {
                    input = i;
                    is_private = true;
                } else if let Ok((i, _)) = rtrim(ttag("global")).parse(input) {
                    input = i;
                    is_global = true;
                } else {
                    return Err(e);
                }
            }
        }
    }

    map(
        (
            rule_name,
            opt(tags),
            delimited(
                rtrim(char('{')),
                (opt(meta), opt(strings), condition),
                rtrim(char('}')),
            ),
        ),
        move |((name, name_span), tags, (meta, strings, condition))| Rule {
            name,
            name_span,
            tags: tags.unwrap_or_default(),
            metadatas: meta.unwrap_or_default(),
            variables: strings.unwrap_or_default(),
            condition,
            is_private,
            is_global,
        },
    )
    .parse(input)
}

fn rule_name(input: Input) -> ParseResult<(String, Range<usize>)> {
    let start = input.pos();
    let (input, name) = string::identifier(input)?;

    Ok((input, (name, input.get_span_from(start))))
}

/// Parse a list of tags
///
/// This roughly parses `: identifier1 identifier2 ...`
/// and returns a list of the identifiers.
fn tags(input: Input) -> ParseResult<Vec<RuleTag>> {
    let (input, _) = rtrim(char(':')).parse(input)?;

    cut(many1(tag)).parse(input)
}

fn tag(input: Input) -> ParseResult<RuleTag> {
    let start = input.pos();
    let (input, tag) = string::identifier(input)?;

    Ok((
        input,
        RuleTag {
            tag,
            span: input.get_span_from(start),
        },
    ))
}

/// Parse the "meta:" section in a rule.
///
/// Related to the `meta` and `meta_declarations` patterns
/// in `grammar.y` in libyara.
fn meta(input: Input) -> ParseResult<Vec<Metadata>> {
    preceded(
        pair(rtrim(ttag("meta")), rtrim(char(':'))),
        cut(many1(meta_declaration)),
    )
    .parse(input)
}

/// Parse a single metadata declaration.
///
/// Related to the `meta_declaration` pattern in `grammar.y` in libyara.
fn meta_declaration(input: Input) -> ParseResult<Metadata> {
    map(
        separated_pair(
            string::identifier,
            rtrim(char('=')),
            alt((
                map(string::quoted, MetadataValue::Bytes),
                map(number::number, MetadataValue::Integer),
                map(preceded(rtrim(char('-')), number::number), |v| {
                    MetadataValue::Integer(-v)
                }),
                map(rtrim(ttag("true")), |_| MetadataValue::Boolean(true)),
                map(rtrim(ttag("false")), |_| MetadataValue::Boolean(false)),
            )),
        ),
        |(name, value)| Metadata { name, value },
    )
    .parse(input)
}

/// Parse the "strings:" section
///
/// Related to the `strings` and `strings_declarations` pattern
/// in `grammar.y` in libyara.
fn strings(input: Input) -> ParseResult<Vec<VariableDeclaration>> {
    let (input, _) = pair(rtrim(ttag("strings")), rtrim(char(':'))).parse(input)?;
    cut(many1(string_declaration)).parse(input)
}

/// Parse a single string declaration.
///
/// Related to the `string_declaration` pattern in `grammar.y` in libyara.
fn string_declaration(input: Input) -> ParseResult<VariableDeclaration> {
    let start = input.pos();

    let (input, (name, (value, modifiers))) = separated_pair(
        string::string_identifier,
        cut(rtrim(char('='))),
        cut(alt((
            pair(
                map(string::quoted, VariableDeclarationValue::Bytes),
                string_modifiers,
            ),
            pair(
                map(regex::regex, VariableDeclarationValue::Regex),
                regex_modifiers,
            ),
            pair(
                map(hex_string::hex_string, VariableDeclarationValue::HexString),
                hex_string_modifiers,
            ),
        ))),
    )
    .parse(input)?;
    Ok((
        input,
        VariableDeclaration {
            name,
            value,
            modifiers,
            span: input.get_span_from(start),
        },
    ))
}

/// A single parsed modifier
#[derive(Clone, Debug, PartialEq)]
enum Modifier {
    Wide,
    Ascii,
    Nocase,
    Fullword,
    Private,
    Xor(u8, u8),
    Base64 {
        wide: bool,
        alphabet: Option<[u8; 64]>,
    },
}

fn modifiers_duplicated(modifier_name: &str, start: Position, input: Input) -> nom::Err<Error> {
    nom::Err::Failure(Error::new(
        input.get_span_from(start),
        ErrorKind::ModifiersDuplicated {
            modifier_name: modifier_name.to_string(),
        },
    ))
}

fn accumulate_modifiers<F>(parser: F, mut input: Input) -> ParseResult<VariableModifiers>
where
    F: Fn(Input) -> ParseResult<Modifier>,
{
    let mut modifiers = VariableModifiers::default();
    let start = input.pos();
    let mut parser = opt(parser);

    while let (i, Some(modifier)) = parser.parse(input)? {
        match modifier {
            Modifier::Wide => {
                if modifiers.wide {
                    return Err(modifiers_duplicated("wide", input.pos(), i));
                }
                modifiers.wide = true;
            }
            Modifier::Ascii => {
                if modifiers.ascii {
                    return Err(modifiers_duplicated("ascii", input.pos(), i));
                }
                modifiers.ascii = true;
            }
            Modifier::Nocase => {
                if modifiers.nocase {
                    return Err(modifiers_duplicated("nocase", input.pos(), i));
                }
                modifiers.nocase = true;
            }
            Modifier::Fullword => {
                if modifiers.fullword {
                    return Err(modifiers_duplicated("fullword", input.pos(), i));
                }
                modifiers.fullword = true;
            }
            Modifier::Private => {
                if modifiers.private {
                    return Err(modifiers_duplicated("private", input.pos(), i));
                }
                modifiers.private = true;
            }
            Modifier::Xor(from, to) => {
                if modifiers.xor.is_some() {
                    return Err(modifiers_duplicated("xor", input.pos(), i));
                }
                modifiers.xor = Some((from, to));
            }
            Modifier::Base64 { wide, alphabet } => match &mut modifiers.base64 {
                Some(base64) => {
                    if wide && std::mem::replace(&mut base64.wide, true) {
                        return Err(modifiers_duplicated("base64wide", input.pos(), i));
                    } else if !wide && std::mem::replace(&mut base64.ascii, true) {
                        return Err(modifiers_duplicated("base64", input.pos(), i));
                    } else if alphabet != base64.alphabet {
                        return Err(nom::Err::Failure(Error::new(
                            i.get_span_from(input.pos()),
                            ErrorKind::Base64AlphabetIncompatible,
                        )));
                    }
                    base64.alphabet = alphabet;
                }
                None => {
                    modifiers.base64 = Some(VariableModifierBase64 {
                        ascii: !wide,
                        wide,
                        alphabet,
                    });
                }
            },
        }
        input = i;
    }

    if let Err(kind) = validate_modifiers(&modifiers) {
        return Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            kind,
        )));
    }

    Ok((input, modifiers))
}

fn validate_modifiers(modifiers: &VariableModifiers) -> Result<(), ErrorKind> {
    if modifiers.xor.is_some() {
        if modifiers.nocase {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "xor".to_owned(),
                second_modifier_name: "nocase".to_owned(),
            });
        }
        if let Some(base64) = &modifiers.base64 {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: if base64.ascii { "base64" } else { "base64wide" }.to_owned(),
                second_modifier_name: "xor".to_owned(),
            });
        }
    }
    if modifiers.nocase {
        if let Some(base64) = &modifiers.base64 {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: if base64.ascii { "base64" } else { "base64wide" }.to_owned(),
                second_modifier_name: "nocase".to_owned(),
            });
        }
    }

    if modifiers.fullword {
        if let Some(base64) = &modifiers.base64 {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: if base64.ascii { "base64" } else { "base64wide" }.to_owned(),
                second_modifier_name: "fullword".to_owned(),
            });
        }
    }

    Ok(())
}

fn string_modifiers(input: Input) -> ParseResult<VariableModifiers> {
    accumulate_modifiers(string_modifier, input)
}

fn regex_modifiers(input: Input) -> ParseResult<VariableModifiers> {
    accumulate_modifiers(regex_modifier, input)
}

fn hex_string_modifiers(input: Input) -> ParseResult<VariableModifiers> {
    accumulate_modifiers(hex_string_modifier, input)
}

fn string_modifier(input: Input) -> ParseResult<Modifier> {
    alt((
        map(rtrim(ttag("wide")), |_| Modifier::Wide),
        map(rtrim(ttag("ascii")), |_| Modifier::Ascii),
        map(rtrim(ttag("nocase")), |_| Modifier::Nocase),
        map(rtrim(ttag("fullword")), |_| Modifier::Fullword),
        map(rtrim(ttag("private")), |_| Modifier::Private),
        xor_modifier,
        base64_modifier,
    ))
    .parse(input)
}

fn regex_modifier(input: Input) -> ParseResult<Modifier> {
    rtrim(alt((
        map(ttag("wide"), |_| Modifier::Wide),
        map(ttag("ascii"), |_| Modifier::Ascii),
        map(ttag("nocase"), |_| Modifier::Nocase),
        map(ttag("fullword"), |_| Modifier::Fullword),
        map(ttag("private"), |_| Modifier::Private),
    )))
    .parse(input)
}

fn hex_string_modifier(input: Input) -> ParseResult<Modifier> {
    map(rtrim(ttag("private")), |_| Modifier::Private).parse(input)
}

/// Parse a XOR modifier, ie:
/// - `'xor'`
/// - `'xor' '(' number ')'`
/// - `'xor' '(' number '-' number ')'`
fn xor_modifier(input: Input) -> ParseResult<Modifier> {
    let (input, _) = rtrim(ttag("xor")).parse(input)?;

    let start = input.pos();
    let (input, open_paren) = opt(rtrim(char('('))).parse(input)?;
    if open_paren.is_none() {
        return Ok((input, Modifier::Xor(0, 255)));
    }

    let (input, from) = cut(map_res(number::number, number_to_u8)).parse(input)?;

    let (input, to) = match rtrim(char('-')).parse(input) {
        Ok((input, _)) => cut(map_res(number::number, number_to_u8)).parse(input)?,
        Err(_) => (input, from),
    };

    let (input, _) = cut(rtrim(char(')'))).parse(input)?;

    if to < from {
        Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            ErrorKind::XorRangeInvalid { from, to },
        )))
    } else {
        Ok((input, Modifier::Xor(from, to)))
    }
}

/// Parse a base64 modifier, ie:
/// - `'base64(wide)'`
/// - `'base64(wide)' '(' string ')'`
fn base64_modifier(input: Input) -> ParseResult<Modifier> {
    let (input, wide) = rtrim(alt((
        map(ttag("base64"), |_| false),
        map(ttag("base64wide"), |_| true),
    )))
    .parse(input)?;

    let (mut input, open_paren) = opt(rtrim(char('('))).parse(input)?;

    let mut alphabet: Option<[u8; 64]> = None;
    if open_paren.is_some() {
        let start = input.pos();
        let (input2, val) = cut(string::quoted).parse(input)?;
        let length = val.len();
        match val.try_into() {
            Ok(v) => alphabet = Some(v),
            Err(_) => {
                return Err(nom::Err::Failure(Error::new(
                    input2.get_span_from(start),
                    ErrorKind::Base64AlphabetInvalidLength { length },
                )));
            }
        }
        let (input2, _) = cut(rtrim(char(')'))).parse(input2)?;
        input = input2;
    }

    Ok((input, Modifier::Base64 { wide, alphabet }))
}

fn number_to_u8(value: i64) -> Result<u8, ErrorKind> {
    u8::try_from(value).map_err(|_| ErrorKind::XorRangeInvalidValue { value })
}

/// Parse a condition
///
/// Related to the `condition` pattern in `grammar.y` in libyara.
fn condition(input: Input) -> ParseResult<Expression> {
    let (input, _) = rtrim(ttag("condition")).parse(input)?;
    cut(preceded(rtrim(char(':')), expression::expression)).parse(input)
}

#[cfg(test)]
mod tests {
    use crate::expression::{ExpressionKind, ForSelection, VariableSet};
    use crate::hex_string::{Mask, Token};
    use crate::regex::Literal;
    use crate::test_helpers::test_public_type;

    use super::super::test_helpers::{parse, parse_err};
    use super::*;

    #[test]
    fn parse_tags() {
        parse(
            tags,
            ": a _ a8 {",
            "{",
            vec![
                RuleTag {
                    tag: "a".to_owned(),
                    span: 2..3,
                },
                RuleTag {
                    tag: "_".to_owned(),
                    span: 4..5,
                },
                RuleTag {
                    tag: "a8".to_owned(),
                    span: 6..8,
                },
            ],
        );
        parse(
            tags,
            ": b 8",
            "8",
            vec![RuleTag {
                tag: "b".to_owned(),
                span: 2..3,
            }],
        );

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
                    value: MetadataValue::Integer(3),
                },
                Metadata {
                    name: "b".to_owned(),
                    value: MetadataValue::Integer(-4),
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
                    value: MetadataValue::Bytes(b" a\rb ".to_vec()),
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
        parse(
            meta,
            "meta: a = \"\" d",
            "d",
            vec![Metadata {
                name: "a".to_owned(),
                value: MetadataValue::Bytes(Vec::new()),
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
            "private wide ascii xor Xor",
            "Xor",
            VariableModifiers {
                wide: true,
                ascii: true,
                nocase: false,
                fullword: false,
                private: true,
                xor: Some((0, 255)),
                base64: None,
            },
        );
        parse(
            string_modifiers,
            "nocase fullword",
            "",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: true,
                fullword: true,
                private: false,
                xor: None,
                base64: None,
            },
        );
        parse(
            string_modifiers,
            "base64wide ascii",
            "",
            VariableModifiers {
                wide: false,
                ascii: true,
                nocase: false,
                fullword: false,
                private: false,
                xor: None,
                base64: Some(VariableModifierBase64 {
                    wide: true,
                    ascii: false,
                    alphabet: None,
                }),
            },
        );

        parse(
            string_modifiers,
            "xor ( 15 )",
            "",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: false,
                fullword: false,
                private: false,
                xor: Some((15, 15)),
                base64: None,
            },
        );
        parse(
            string_modifiers,
            "xor (50 - 120) private",
            "",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: false,
                fullword: false,
                private: true,
                xor: Some((50, 120)),
                base64: None,
            },
        );

        let alphabet = "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu";
        let alphabet_array: [u8; 64] = alphabet.as_bytes().try_into().unwrap();
        parse(
            string_modifiers,
            &format!("base64( \"{alphabet}\" )"),
            "",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: false,
                fullword: false,
                private: false,
                xor: None,
                base64: Some(VariableModifierBase64 {
                    wide: false,
                    ascii: true,
                    alphabet: Some(alphabet_array),
                }),
            },
        );
        parse(
            string_modifiers,
            &format!("base64wide ( \"{alphabet}\" ) private"),
            "",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: false,
                fullword: false,
                private: true,
                xor: None,
                base64: Some(VariableModifierBase64 {
                    wide: true,
                    ascii: false,
                    alphabet: Some(alphabet_array),
                }),
            },
        );
        parse(
            string_modifiers,
            &format!("base64wide ( \"{alphabet}\" ) base64 (\"{alphabet}\")"),
            "",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: false,
                fullword: false,
                private: false,
                xor: None,
                base64: Some(VariableModifierBase64 {
                    wide: true,
                    ascii: true,
                    alphabet: Some(alphabet_array),
                }),
            },
        );

        parse(
            regex_modifiers,
            "private wide ascii nocase fullword base64",
            "base64",
            VariableModifiers {
                wide: true,
                ascii: true,
                nocase: true,
                fullword: true,
                private: true,
                xor: None,
                base64: None,
            },
        );

        parse(
            hex_string_modifiers,
            "private wide",
            "wide",
            VariableModifiers {
                wide: false,
                ascii: false,
                nocase: false,
                fullword: false,
                private: true,
                xor: None,
                base64: None,
            },
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
    fn test_flags_validation() {
        parse_err(string_modifiers, "xor nocase");
        parse_err(string_modifiers, "base64 nocase");
        parse_err(string_modifiers, "nocase base64wide");
        parse_err(string_modifiers, "fullword base64");
        parse_err(string_modifiers, "base64wide fullword");
        parse_err(string_modifiers, "xor xor");
        parse_err(string_modifiers, "xor(300)");
        parse_err(string_modifiers, "xor base64");
        parse_err(string_modifiers, "xor base64wide");
    }

    #[test]
    fn test_err_accumulate_modifiers() {
        let alphabet = "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu";
        let alphabet2 = "!@#$%^&*(){}[].,|BADCFEHGJI\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu";

        parse_err(string_modifiers, "xor xor");
        parse_err(string_modifiers, "base64 base64");
        parse_err(string_modifiers, "base64wide base64wide");
        parse_err(string_modifiers, "fullword fullword");
        parse_err(string_modifiers, "private private");
        parse_err(string_modifiers, "wide wide");
        parse_err(string_modifiers, "ascii ascii");
        parse_err(string_modifiers, "nocase nocase");

        parse_err(regex_modifiers, "fullword fullword");
        parse_err(regex_modifiers, "private private");
        parse_err(regex_modifiers, "wide wide");
        parse_err(regex_modifiers, "ascii ascii");
        parse_err(regex_modifiers, "nocase nocase");

        parse_err(hex_string_modifiers, "private private");

        parse_err(
            string_modifiers,
            &format!(r#"base64 base64wide("{alphabet}")"#),
        );
        parse_err(
            string_modifiers,
            &format!(r#"base64("{alphabet}") base64wide"#),
        );
        parse_err(
            string_modifiers,
            &format!(r#"base64wide("{alphabet}") base64"#),
        );
        parse_err(
            string_modifiers,
            &format!(r#"base64("{alphabet}") base64wide("{alphabet2}")"#),
        );
    }

    #[test]
    fn parse_strings() {
        parse(
            strings,
            "strings : $a = \"b\td\" xor ascii \n  $b= /a?b/  $= { ?B} private d",
            "d",
            [
                VariableDeclaration {
                    name: "a".to_owned(),
                    value: VariableDeclarationValue::Bytes(b"b\td".to_vec()),
                    modifiers: VariableModifiers {
                        ascii: true,
                        xor: Some((0, 255)),
                        ..VariableModifiers::default()
                    },
                    span: 10..30,
                },
                VariableDeclaration {
                    name: "b".to_owned(),
                    value: VariableDeclarationValue::Regex(Regex {
                        ast: regex::Node::Concat(vec![
                            regex::Node::Repetition {
                                node: Box::new(regex::Node::Literal(Literal {
                                    byte: b'a',
                                    span: 39..40,
                                    escaped: false,
                                })),
                                kind: regex::RepetitionKind::ZeroOrOne,
                                greedy: true,
                            },
                            regex::Node::Literal(Literal {
                                byte: b'b',
                                span: 41..42,
                                escaped: false,
                            }),
                        ]),
                        case_insensitive: false,
                        dot_all: false,
                        span: 38..43,
                    }),
                    modifiers: VariableModifiers {
                        ..VariableModifiers::default()
                    },
                    span: 34..43,
                },
                VariableDeclaration {
                    name: String::new(),
                    value: VariableDeclarationValue::HexString(vec![Token::MaskedByte(
                        0x0B,
                        Mask::Left,
                    )]),
                    modifiers: VariableModifiers {
                        private: true,
                        ..VariableModifiers::default()
                    },
                    span: 45..61,
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
                name_span: 5..6,
                condition: Expression {
                    expr: ExpressionKind::Boolean(false),
                    span: 20..25,
                },
                tags: Vec::new(),
                metadatas: Vec::new(),
                variables: Vec::new(),
                is_private: false,
                is_global: false,
            },
        );
        parse(
            rule,
            "private global rule b : tag1 tag2 { meta: a = true strings: $b = \"t\" condition: all of them }",
            "",
            Rule {
                name: "b".to_owned(),
                name_span: 20..21,
                tags: vec![RuleTag { tag: "tag1".to_owned(), span: 24..28 }, RuleTag { tag: "tag2".to_owned(), span: 29..33 }],
                metadatas: vec![
                    Metadata { name: "a".to_owned(), value: MetadataValue::Boolean(true) }
                ],
                variables: vec![
                    VariableDeclaration {
                        name: "b".to_owned(),
                        value: VariableDeclarationValue::Bytes(b"t".to_vec()),
                        modifiers: VariableModifiers::default(),
                        span: 60..68,
                    }
                ],
                condition: Expression {
                    expr: ExpressionKind::For {
                        selection: ForSelection::All,
                        set: VariableSet { elements: vec![] },
                        body: None,
                    },
                    span: 80..91
                },
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
                name_span: 20..21,
                condition: Expression {
                    expr: ExpressionKind::Boolean(false),
                    span: 35..40,
                },
                tags: Vec::new(),
                metadatas: Vec::new(),
                variables: Vec::new(),
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
                name_span: 13..14,
                condition: Expression {
                    expr: ExpressionKind::Boolean(false),
                    span: 28..33,
                },
                tags: Vec::new(),
                metadatas: Vec::new(),
                variables: Vec::new(),
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
                name_span: 12..13,
                condition: Expression {
                    expr: ExpressionKind::Boolean(false),
                    span: 27..32,
                },
                tags: Vec::new(),
                metadatas: Vec::new(),
                variables: Vec::new(),
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

    #[test]
    fn parse_xor_modifier() {
        parse(xor_modifier, "xor a", "a", Modifier::Xor(0, 255));
        parse(xor_modifier, "xor(23)", "", Modifier::Xor(23, 23));
        parse(xor_modifier, "xor ( 12 -15 )b", "b", Modifier::Xor(12, 15));

        parse_err(xor_modifier, "");
        parse_err(xor_modifier, "xora");
        parse_err(xor_modifier, "xor(");
        parse_err(xor_modifier, "xor(//");
        parse_err(xor_modifier, "xor(13");
        parse_err(xor_modifier, "xor()");
        parse_err(xor_modifier, "xor(-1)");
        parse_err(xor_modifier, "xor(256)");
        parse_err(xor_modifier, "xor(50-4)");
        parse_err(xor_modifier, "xor(0-256)");
    }

    #[test]
    fn parse_base64_modifier() {
        let alphabet = "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu";
        let alphabet_array: [u8; 64] = alphabet.as_bytes().try_into().unwrap();

        parse(
            base64_modifier,
            "base64 a",
            "a",
            Modifier::Base64 {
                wide: false,
                alphabet: None,
            },
        );
        parse(
            base64_modifier,
            "base64wide a",
            "a",
            Modifier::Base64 {
                wide: true,
                alphabet: None,
            },
        );
        parse(
            base64_modifier,
            &format!(r#"base64("{alphabet}")"#),
            "",
            Modifier::Base64 {
                wide: false,
                alphabet: Some(alphabet_array),
            },
        );
        parse(
            base64_modifier,
            &format!(r#"base64wide ( "{alphabet}")b"#),
            "b",
            Modifier::Base64 {
                wide: true,
                alphabet: Some(alphabet_array),
            },
        );

        parse_err(base64_modifier, "");
        parse_err(base64_modifier, "base64a");
        parse_err(base64_modifier, "base64widea");
        parse_err(base64_modifier, "base64(");
        parse_err(base64_modifier, "base64wide(");
        parse_err(base64_modifier, "base64wide(//");
        parse_err(base64_modifier, &format!(r#"base64("{alphabet}""#));
        parse_err(base64_modifier, "base64(\"123\")");
        parse_err(base64_modifier, "base64wide(15)");
    }

    #[test]
    fn test_public_types() {
        test_public_type(
            rule(Input::new(
                r#"private rule a : tag {
    meta:
        a = "a"
        b = 2
        c = true
    strings:
        $a = { 01 }
        $b = "02" xor(15-30)
        $c = "02" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
        $d = /ab/ wide
    condition:
      any of them
}
"#,
            ))
            .unwrap(),
        );

        test_public_type(string_modifier(Input::new("wide")).unwrap());
    }
}
