//! Parse yara rules.
use nom::{combinator::cut, sequence::preceded};

use crate::Rule;

use super::rule::rule;
use super::{
    nom_recipes::{ltrim, rtrim, textual_tag as ttag},
    string,
    types::{Input, ParseResult},
};

/// A parsed Yara file.
#[derive(Debug, PartialEq)]
pub struct YaraFile {
    /// List of components contained in the file.
    ///
    /// This enum form is required to keep the order in which rules and imports
    /// appear the file. This is needed to properly resolve symbols to a rule
    /// or a module, or to properly use included rules in wildcard use of rule
    /// names in conditions.
    pub components: Vec<YaraFileComponent>,
}

/// A top-level component of a Yara file.
#[derive(Debug, PartialEq)]
pub enum YaraFileComponent {
    /// A Yara rule
    Rule(Box<Rule>),
    /// A module import
    Import(String),
    /// An include of another file
    Include(String),
}

/// Parse a full YARA file.
///
/// # Errors
///
/// If the input cannot be parsed properly and entirely as a list
/// of yara rules, an error is returned.
pub fn parse_yara_file(input: Input) -> ParseResult<YaraFile> {
    let (mut input, _) = ltrim(input)?;

    let mut file = YaraFile {
        components: Vec::new(),
    };
    while !input.is_empty() {
        if let Ok((i, v)) = include_file(input) {
            file.components.push(YaraFileComponent::Include(v));
            input = i;
        } else if let Ok((i, v)) = import(input) {
            file.components.push(YaraFileComponent::Import(v));
            input = i;
        } else {
            let (i, rule) = rule(input)?;
            file.components
                .push(YaraFileComponent::Rule(Box::new(rule)));
            input = i;
        }
    }

    Ok((input, file))
}

/// Parse an include declaration
fn include_file(input: Input) -> ParseResult<String> {
    preceded(rtrim(ttag("include")), cut(string::quoted))(input)
}

/// Parse an import declaration
fn import(input: Input) -> ParseResult<String> {
    preceded(rtrim(ttag("import")), cut(string::quoted))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tests::{parse, parse_err},
        Expression, ExpressionKind,
    };

    #[test]
    fn test_parse_yara_file() {
        parse(
            parse_yara_file,
            "  global rule c { condition: false }",
            "",
            YaraFile {
                components: vec![YaraFileComponent::Rule(Box::new(Rule {
                    name: "c".to_owned(),
                    condition: Expression {
                        expr: ExpressionKind::Boolean(false),
                        span: 29..34,
                    },
                    tags: Vec::new(),
                    metadatas: Vec::new(),
                    variables: Vec::new(),
                    is_private: false,
                    is_global: true,
                }))],
            },
        );

        parse(
            parse_yara_file,
            r#" import "pe"
                global rule c { condition: false }
                import "foo"
                import "quux"
                rule d { condition: true }
                "#,
            "",
            YaraFile {
                components: vec![
                    YaraFileComponent::Import("pe".to_owned()),
                    YaraFileComponent::Rule(Box::new(Rule {
                        name: "c".to_owned(),
                        condition: Expression {
                            expr: ExpressionKind::Boolean(false),
                            span: 56..61,
                        },
                        tags: Vec::new(),
                        metadatas: Vec::new(),
                        variables: Vec::new(),
                        is_private: false,
                        is_global: true,
                    })),
                    YaraFileComponent::Import("foo".to_owned()),
                    YaraFileComponent::Import("quux".to_owned()),
                    YaraFileComponent::Rule(Box::new(Rule {
                        name: "d".to_owned(),
                        condition: Expression {
                            expr: ExpressionKind::Boolean(true),
                            span: 159..163,
                        },
                        tags: Vec::new(),
                        metadatas: Vec::new(),
                        variables: Vec::new(),
                        is_private: false,
                        is_global: false,
                    })),
                ],
            },
        );
        parse(parse_yara_file, "", "", YaraFile { components: vec![] });
        parse(
            parse_yara_file,
            " /* removed */ ",
            "",
            YaraFile { components: vec![] },
        );
        parse(
            parse_yara_file,
            "include \"v\"\ninclude\"i\"",
            "",
            YaraFile {
                components: vec![
                    YaraFileComponent::Include("v".to_owned()),
                    YaraFileComponent::Include("i".to_owned()),
                ],
            },
        );

        parse_err(parse_yara_file, "rule");
        parse_err(parse_yara_file, "rule a { condition: true } b");
    }
}
