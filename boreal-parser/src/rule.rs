//! Parse yara rules.
use std::ops::Range;

use bitflags::bitflags;
use nom::{
    branch::alt,
    character::complete::char,
    combinator::{cut, map, opt},
    multi::many1,
    sequence::{delimited, pair, preceded, separated_pair, tuple},
};

use super::{
    error::{Error, ErrorKind},
    expression::{self, Expression},
    hex_string,
    nom_recipes::{map_res, rtrim, textual_tag as ttag},
    number, regex, string,
    types::{Input, ParseResult},
    Regex,
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
    Bytes(Vec<u8>),
    Integer(i64),
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

bitflags! {
    /// Modifier flags, see [`VariableModifiers`].
    #[derive(Default)]
    pub struct VariableFlags: u32 {
        /// Wide modifier
        const WIDE = 0b0000_0001;
        /// Ascii modifier
        const ASCII = 0b000_0010;
        /// Nocase modifier
        const NOCASE = 0b0000_0100;
        /// Fullword modifier
        const FULLWORD = 0b0000_1000;
        /// Private modifier
        const PRIVATE = 0b0001_0000;
        /// Xor modifier, related to [`VariableModifiers::xor_range`]
        const XOR = 0b0010_0000;
        /// base64 modifier, related to [`VariableModifiers::base64_alphabet`]
        const BASE64 = 0b0100_0000;
        /// base64wide modifier, related to [`VariableModifiers::base64_alphabet`]
        const BASE64WIDE = 0b1000_0000;
    }
}

/// Value for a string associated with a rule.
#[derive(Clone, Debug, PartialEq)]
pub enum VariableDeclarationValue {
    /// A raw byte string.
    Bytes(Vec<u8>),
    /// A regular expression.
    Regex(Regex),
    /// A hex string.
    HexString(Vec<hex_string::HexToken>),
}

/// Modifiers applicable on a string.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct VariableModifiers {
    /// Bitflags of possibles flags modifying the string.
    pub flags: VariableFlags,
    /// Xor range.
    ///
    /// This is only applicable if `flags` contains [`VariableFlags::XOR`].
    pub xor_range: (u8, u8),
    /// Base64 alphabet.
    ///
    /// This is only applicable if `flags` contains [`VariableFlags::BASE64`]
    /// or [`VariableFlags::BASE64WIDE`].
    pub base64_alphabet: Option<[u8; 64]>,
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
pub fn rule(mut input: Input) -> ParseResult<Rule> {
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
            rule_name,
            opt(tags),
            delimited(
                rtrim(char('{')),
                tuple((opt(meta), opt(strings), condition)),
                rtrim(char('}')),
            ),
        )),
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
    )(input)
}

fn rule_name(input: Input) -> ParseResult<(String, Range<usize>)> {
    let start = input;
    let (input, name) = string::identifier(input)?;

    Ok((input, (name, input.get_span_from(start))))
}

/// Parse a list of tags
///
/// This roughly parses `: identifier1 identifier2 ...`
/// and returns a list of the identifiers.
fn tags(input: Input) -> ParseResult<Vec<RuleTag>> {
    let (input, _) = rtrim(char(':'))(input)?;

    cut(many1(tag))(input)
}

fn tag(input: Input) -> ParseResult<RuleTag> {
    let start = input;
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
    )(input)
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
    )(input)
}

/// Parse the "strings:" section
///
/// Related to the `strings` and `strings_declarations` pattern
/// in `grammar.y` in libyara.
fn strings(input: Input) -> ParseResult<Vec<VariableDeclaration>> {
    let (input, _) = pair(rtrim(ttag("strings")), rtrim(char(':')))(input)?;
    cut(many1(string_declaration))(input)
}

/// Parse a single string declaration.
///
/// Related to the `string_declaration` pattern in `grammar.y` in libyara.
fn string_declaration(input: Input) -> ParseResult<VariableDeclaration> {
    let start = input;

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
    )(input)?;
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
    // Must not use this enum value for the flags XOR and BASE64(WIDE).
    // Instead, use the other enum values to ensure the associated data
    // is properly set.
    Flag(VariableFlags),
    Xor(u8, u8),
    Base64(Option<[u8; 64]>),
    Base64Wide(Option<[u8; 64]>),
}

fn accumulate_modifiers<F>(parser: F, mut input: Input) -> ParseResult<VariableModifiers>
where
    F: Fn(Input) -> ParseResult<Modifier>,
{
    let add_flag =
        |modifiers: &mut VariableModifiers, start: Input, input: Input, flag: VariableFlags| {
            if modifiers.flags.contains(flag) {
                return Err(nom::Err::Failure(Error::new(
                    input.get_span_from(start),
                    ErrorKind::ModifiersDuplicated {
                        modifier_name: format!("{:?}", flag),
                    },
                )));
            }
            modifiers.flags |= flag;
            Ok(())
        };

    let mut modifiers = VariableModifiers::default();
    let start = input;
    let mut parser = opt(parser);

    while let (i, Some(modifier)) = parser(input)? {
        match modifier {
            Modifier::Flag(flag) => {
                add_flag(&mut modifiers, input, i, flag)?;
            }
            Modifier::Xor(from, to) => {
                add_flag(&mut modifiers, input, i, VariableFlags::XOR)?;
                modifiers.xor_range = (from, to);
            }
            Modifier::Base64(alphabet) => {
                if modifiers.flags.contains(VariableFlags::BASE64WIDE)
                    && modifiers.base64_alphabet != alphabet
                {
                    return Err(nom::Err::Failure(Error::new(
                        i.get_span_from(input),
                        ErrorKind::Base64AlphabetIncompatible,
                    )));
                }
                add_flag(&mut modifiers, input, i, VariableFlags::BASE64)?;
                modifiers.base64_alphabet = alphabet;
            }
            Modifier::Base64Wide(alphabet) => {
                if modifiers.flags.contains(VariableFlags::BASE64)
                    && modifiers.base64_alphabet != alphabet
                {
                    return Err(nom::Err::Failure(Error::new(
                        i.get_span_from(input),
                        ErrorKind::Base64AlphabetIncompatible,
                    )));
                }
                add_flag(&mut modifiers, input, i, VariableFlags::BASE64WIDE)?;
                modifiers.base64_alphabet = alphabet;
            }
        }
        input = i;
    }

    if let Err(kind) = validate_flags(modifiers.flags) {
        return Err(nom::Err::Failure(Error::new(
            input.get_span_from(start),
            kind,
        )));
    }

    Ok((input, modifiers))
}

fn validate_flags(flags: VariableFlags) -> Result<(), ErrorKind> {
    if flags.contains(VariableFlags::XOR) {
        if flags.contains(VariableFlags::NOCASE) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "xor".to_owned(),
                second_modifier_name: "nocase".to_owned(),
            });
        }
        if flags.contains(VariableFlags::BASE64) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "base64".to_owned(),
                second_modifier_name: "xor".to_owned(),
            });
        }
        if flags.contains(VariableFlags::BASE64WIDE) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "base64wide".to_owned(),
                second_modifier_name: "xor".to_owned(),
            });
        }
    }
    if flags.contains(VariableFlags::NOCASE) {
        if flags.contains(VariableFlags::BASE64) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "base64".to_owned(),
                second_modifier_name: "nocase".to_owned(),
            });
        }
        if flags.contains(VariableFlags::BASE64WIDE) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "base64wide".to_owned(),
                second_modifier_name: "nocase".to_owned(),
            });
        }
    }

    if flags.contains(VariableFlags::FULLWORD) {
        if flags.contains(VariableFlags::BASE64) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "base64".to_owned(),
                second_modifier_name: "fullword".to_owned(),
            });
        }
        if flags.contains(VariableFlags::BASE64WIDE) {
            return Err(ErrorKind::ModifiersIncompatible {
                first_modifier_name: "base64wide".to_owned(),
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
        map(rtrim(ttag("wide")), |_| Modifier::Flag(VariableFlags::WIDE)),
        map(rtrim(ttag("ascii")), |_| {
            Modifier::Flag(VariableFlags::ASCII)
        }),
        map(rtrim(ttag("nocase")), |_| {
            Modifier::Flag(VariableFlags::NOCASE)
        }),
        map(rtrim(ttag("fullword")), |_| {
            Modifier::Flag(VariableFlags::FULLWORD)
        }),
        map(rtrim(ttag("private")), |_| {
            Modifier::Flag(VariableFlags::PRIVATE)
        }),
        xor_modifier,
        base64_modifier,
    ))(input)
}

fn regex_modifier(input: Input) -> ParseResult<Modifier> {
    rtrim(alt((
        map(ttag("wide"), |_| Modifier::Flag(VariableFlags::WIDE)),
        map(ttag("ascii"), |_| Modifier::Flag(VariableFlags::ASCII)),
        map(ttag("nocase"), |_| Modifier::Flag(VariableFlags::NOCASE)),
        map(ttag("fullword"), |_| {
            Modifier::Flag(VariableFlags::FULLWORD)
        }),
        map(ttag("private"), |_| Modifier::Flag(VariableFlags::PRIVATE)),
    )))(input)
}

fn hex_string_modifier(input: Input) -> ParseResult<Modifier> {
    map(rtrim(ttag("private")), |_| {
        Modifier::Flag(VariableFlags::PRIVATE)
    })(input)
}

/// Parse a XOR modifier, ie:
/// - `'xor'`
/// - `'xor' '(' number ')'`
/// - `'xor' '(' number '-' number ')'`
fn xor_modifier(input: Input) -> ParseResult<Modifier> {
    let (input, _) = rtrim(ttag("xor"))(input)?;

    let start = input;
    let (input, open_paren) = opt(rtrim(char('(')))(input)?;
    if open_paren.is_none() {
        return Ok((input, Modifier::Xor(0, 255)));
    }

    let (input, from) = cut(map_res(number::number, number_to_u8))(input)?;

    let (input, to) = match rtrim(char('-'))(input) {
        Ok((input, _)) => cut(map_res(number::number, number_to_u8))(input)?,
        Err(_) => (input, from),
    };

    let (input, _) = cut(rtrim(char(')')))(input)?;

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
    let (input, is_wide) = rtrim(alt((
        map(ttag("base64"), |_| false),
        map(ttag("base64wide"), |_| true),
    )))(input)?;

    let (mut input, open_paren) = opt(rtrim(char('(')))(input)?;

    let mut alphabet: Option<[u8; 64]> = None;
    if open_paren.is_some() {
        let start = input;
        let (input2, val) = cut(string::quoted)(input)?;
        let length = val.len();
        match val.try_into() {
            Ok(v) => alphabet = Some(v),
            Err(_) => {
                return Err(nom::Err::Failure(Error::new(
                    input2.get_span_from(start),
                    ErrorKind::Base64AlphabetInvalidLength { length },
                )));
            }
        };
        let (input2, _) = cut(rtrim(char(')')))(input2)?;
        input = input2;
    }

    Ok((
        input,
        if is_wide {
            Modifier::Base64Wide(alphabet)
        } else {
            Modifier::Base64(alphabet)
        },
    ))
}

fn number_to_u8(value: i64) -> Result<u8, ErrorKind> {
    u8::try_from(value).map_err(|_| ErrorKind::XorRangeInvalidValue { value })
}

/// Parse a condition
///
/// Related to the `condition` pattern in `grammar.y` in libyara.
fn condition(input: Input) -> ParseResult<Expression> {
    let (input, _) = rtrim(ttag("condition"))(input)?;
    cut(preceded(rtrim(char(':')), expression::expression))(input)
}

#[cfg(test)]
mod tests {
    use crate::expression::{Expression, ExpressionKind, ForSelection, VariableSet};
    use crate::hex_string::{HexToken, Mask};
    use crate::test_helpers::test_public_type;
    use crate::Regex;

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
                flags: VariableFlags::PRIVATE
                    | VariableFlags::WIDE
                    | VariableFlags::ASCII
                    | VariableFlags::XOR,
                xor_range: (0, 255),
                base64_alphabet: None,
            },
        );
        parse(
            string_modifiers,
            "nocase fullword",
            "",
            VariableModifiers {
                flags: VariableFlags::NOCASE | VariableFlags::FULLWORD,
                xor_range: (0, 0),
                base64_alphabet: None,
            },
        );
        parse(
            string_modifiers,
            "base64wide ascii",
            "",
            VariableModifiers {
                flags: VariableFlags::BASE64WIDE | VariableFlags::ASCII,
                xor_range: (0, 0),
                base64_alphabet: None,
            },
        );

        parse(
            string_modifiers,
            "xor ( 15 )",
            "",
            VariableModifiers {
                flags: VariableFlags::XOR,
                xor_range: (15, 15),
                base64_alphabet: None,
            },
        );
        parse(
            string_modifiers,
            "xor (50 - 120) private",
            "",
            VariableModifiers {
                flags: VariableFlags::XOR | VariableFlags::PRIVATE,
                xor_range: (50, 120),
                base64_alphabet: None,
            },
        );

        let alphabet = "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu";
        let alphabet_array: [u8; 64] = alphabet.as_bytes().try_into().unwrap();
        parse(
            string_modifiers,
            &format!("base64( \"{}\" )", alphabet),
            "",
            VariableModifiers {
                flags: VariableFlags::BASE64,
                xor_range: (0, 0),
                base64_alphabet: Some(alphabet_array),
            },
        );
        parse(
            string_modifiers,
            &format!("base64wide ( \"{}\" ) private", alphabet),
            "",
            VariableModifiers {
                flags: VariableFlags::BASE64WIDE | VariableFlags::PRIVATE,
                xor_range: (0, 0),
                base64_alphabet: Some(alphabet_array),
            },
        );
        parse(
            string_modifiers,
            &format!("base64wide ( \"{}\" ) base64 (\"{}\")", alphabet, alphabet),
            "",
            VariableModifiers {
                flags: VariableFlags::BASE64WIDE | VariableFlags::BASE64,
                xor_range: (0, 0),
                base64_alphabet: Some(alphabet_array),
            },
        );

        parse(
            regex_modifiers,
            "private wide ascii nocase fullword base64",
            "base64",
            VariableModifiers {
                flags: VariableFlags::PRIVATE
                    | VariableFlags::WIDE
                    | VariableFlags::ASCII
                    | VariableFlags::NOCASE
                    | VariableFlags::FULLWORD,
                ..VariableModifiers::default()
            },
        );

        parse(
            hex_string_modifiers,
            "private wide",
            "wide",
            VariableModifiers {
                flags: VariableFlags::PRIVATE,
                ..VariableModifiers::default()
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
            &format!(r#"base64 base64wide("{}")"#, alphabet),
        );
        parse_err(
            string_modifiers,
            &format!(r#"base64("{}") base64wide"#, alphabet),
        );
        parse_err(
            string_modifiers,
            &format!(r#"base64wide("{}") base64"#, alphabet),
        );
        parse_err(
            string_modifiers,
            &format!(r#"base64("{}") base64wide("{}")"#, alphabet, alphabet2),
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
                        flags: VariableFlags::XOR | VariableFlags::ASCII,
                        xor_range: (0, 255),
                        ..VariableModifiers::default()
                    },
                    span: 10..30,
                },
                VariableDeclaration {
                    name: "b".to_owned(),
                    value: VariableDeclarationValue::Regex(Regex {
                        ast: regex::Node::Concat(vec![
                            regex::Node::Repetition {
                                node: Box::new(regex::Node::Literal(b'a')),
                                kind: regex::RepetitionKind::ZeroOrOne,
                                greedy: true,
                            },
                            regex::Node::Literal(b'b'),
                        ]),
                        case_insensitive: false,
                        dot_all: false,
                        span: 38..43,
                    }),
                    modifiers: VariableModifiers {
                        flags: VariableFlags::empty(),
                        ..VariableModifiers::default()
                    },
                    span: 34..43,
                },
                VariableDeclaration {
                    name: "".to_owned(),
                    value: VariableDeclarationValue::HexString(vec![HexToken::MaskedByte(
                        0x0B,
                        Mask::Left,
                    )]),
                    modifiers: VariableModifiers {
                        flags: VariableFlags::PRIVATE,
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
                        modifiers: VariableModifiers {
                            flags: VariableFlags::empty(),
                            ..VariableModifiers::default()
                        },
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

        parse(base64_modifier, "base64 a", "a", Modifier::Base64(None));
        parse(
            base64_modifier,
            "base64wide a",
            "a",
            Modifier::Base64Wide(None),
        );
        parse(
            base64_modifier,
            &format!(r#"base64("{}")"#, alphabet),
            "",
            Modifier::Base64(Some(alphabet_array)),
        );
        parse(
            base64_modifier,
            &format!(r#"base64wide ( "{}")b"#, alphabet),
            "b",
            Modifier::Base64Wide(Some(alphabet_array)),
        );

        parse_err(base64_modifier, "");
        parse_err(base64_modifier, "base64a");
        parse_err(base64_modifier, "base64widea");
        parse_err(base64_modifier, "base64(");
        parse_err(base64_modifier, "base64wide(");
        parse_err(base64_modifier, "base64wide(//");
        parse_err(base64_modifier, &format!(r#"base64("{}""#, alphabet));
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
