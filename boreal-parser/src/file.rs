//! Types related to YARA files.
use std::ops::Range;

use nom::branch::alt;
use nom::bytes::complete::take_till1;
use nom::character::complete::char;
use nom::combinator::map;
use nom::sequence::delimited;
use nom::Parser;
use nom::{combinator::cut, sequence::preceded};

use crate::rule::Rule;

use super::rule::rule;
use super::{
    nom_recipes::{ltrim, rtrim, textual_tag as ttag},
    types::{Input, ParseResult},
};

/// A parsed Yara file.
#[derive(Clone, Debug, PartialEq)]
pub struct YaraFile {
    /// List of components contained in the file.
    ///
    /// This enum form is required to keep the order in which rules and imports
    /// appear in the file. This is needed to properly resolve symbols to a rule
    /// or a module, or to properly use rules included by wildcard use of rule
    /// names in conditions.
    pub components: Vec<YaraFileComponent>,
}

/// A top-level component of a Yara file.
#[derive(Clone, Debug, PartialEq)]
pub enum YaraFileComponent {
    /// A Yara rule
    Rule(Box<Rule>),
    /// A module import
    Import(Import),
    /// An include of another file
    Include(Include),
}

/// An import inside a Yara file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// The name being imported
    pub name: String,
    /// The span covering the whole import, ie `import "foo"`
    pub span: Range<usize>,
}

/// An import inside a Yara file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Include {
    /// Path to the file being included
    pub path: String,
    /// The span covering the whole include, ie `include "./bar.yar"`
    pub span: Range<usize>,
}

/// Parse a full YARA file.
///
/// # Errors
///
/// If the input cannot be parsed properly and entirely as a list
/// of yara rules, an error is returned.
pub(crate) fn parse_yara_file(input: Input) -> ParseResult<YaraFile> {
    let (mut input, ()) = ltrim(input)?;

    let mut file = YaraFile {
        components: Vec::new(),
    };
    while !input.is_empty() {
        let (i, component) = alt((
            map(include_file, YaraFileComponent::Include),
            map(import, YaraFileComponent::Import),
            map(rule, |r| YaraFileComponent::Rule(Box::new(r))),
        ))
        .parse(input)?;
        file.components.push(component);
        input = i;
    }

    Ok((input, file))
}

/// Parse an include declaration
fn include_file(input: Input) -> ParseResult<Include> {
    let start = input.pos();

    let (input, path) = rtrim(preceded(
        rtrim(ttag("include")),
        cut(delimited(
            char('"'),
            map(take_till1(|c| c == '"'), |v: Input| v.to_string()),
            char('"'),
        )),
    ))(input)?;

    Ok((
        input,
        Include {
            path,
            span: input.get_span_from(start),
        },
    ))
}

/// Parse an import declaration
fn import(input: Input) -> ParseResult<Import> {
    let start = input.pos();

    let (input, name) = rtrim(preceded(
        rtrim(ttag("import")),
        cut(delimited(
            char('"'),
            map(take_till1(|c| c == '"'), |v: Input| v.to_string()),
            char('"'),
        )),
    ))(input)?;

    Ok((
        input,
        Import {
            name,
            span: input.get_span_from(start),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::{Expression, ExpressionKind};
    use crate::test_helpers::{parse, parse_err, test_public_type};

    #[test]
    fn test_parse_yara_file() {
        parse(
            parse_yara_file,
            "  global rule c { condition: false }",
            "",
            YaraFile {
                components: vec![YaraFileComponent::Rule(Box::new(Rule {
                    name: "c".to_owned(),
                    name_span: 14..15,
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
                    YaraFileComponent::Import(Import {
                        name: "pe".to_owned(),
                        span: 1..12,
                    }),
                    YaraFileComponent::Rule(Box::new(Rule {
                        name: "c".to_owned(),
                        name_span: 41..42,
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
                    YaraFileComponent::Import(Import {
                        name: "foo".to_owned(),
                        span: 80..92,
                    }),
                    YaraFileComponent::Import(Import {
                        name: "quux".to_owned(),
                        span: 109..122,
                    }),
                    YaraFileComponent::Rule(Box::new(Rule {
                        name: "d".to_owned(),
                        name_span: 144..145,
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
                    YaraFileComponent::Include(Include {
                        path: "v".to_owned(),
                        span: 0..11,
                    }),
                    YaraFileComponent::Include(Include {
                        path: "i".to_owned(),
                        span: 12..22,
                    }),
                ],
            },
        );

        parse_err(parse_yara_file, "rule");
        parse_err(parse_yara_file, "rule a { condition: true } b");
        parse_err(parse_yara_file, " /*");
    }

    #[test]
    fn test_public_types() {
        test_public_type(
            parse_yara_file(Input::new(
                r#"
import "a"
include "b"

rule a { condition: true }
"#,
            ))
            .unwrap(),
        );
    }
}
