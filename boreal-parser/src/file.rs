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
    /// List of rules contained in the file.
    pub rules: Vec<Rule>,

    /// List of imports in the file.
    pub imports: Vec<String>,

    /// List of includes in the file.
    pub includes: Vec<String>,
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
        rules: Vec::new(),
        imports: Vec::new(),
        includes: Vec::new(),
    };
    while !input.is_empty() {
        if let Ok((i, v)) = include_file(input) {
            file.includes.push(v);
            input = i;
        } else if let Ok((i, v)) = import(input) {
            file.imports.push(v);
            input = i;
        } else {
            let (i, rule) = rule(input)?;
            file.rules.push(rule);
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
                rules: vec![Rule {
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
                }],
                imports: vec![],
                includes: vec![],
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
                rules: vec![
                    Rule {
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
                    },
                    Rule {
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
                    },
                ],
                imports: vec!["pe".to_owned(), "foo".to_owned(), "quux".to_owned()],
                includes: vec![],
            },
        );
        parse(
            parse_yara_file,
            "",
            "",
            YaraFile {
                rules: Vec::new(),
                imports: Vec::new(),
                includes: vec![],
            },
        );
        parse(
            parse_yara_file,
            " /* removed */ ",
            "",
            YaraFile {
                rules: Vec::new(),
                imports: Vec::new(),
                includes: vec![],
            },
        );
        parse(
            parse_yara_file,
            "include \"v\"\ninclude\"i\"",
            "",
            YaraFile {
                rules: Vec::new(),
                imports: Vec::new(),
                includes: vec!["v".to_owned(), "i".to_owned()],
            },
        );

        parse_err(parse_yara_file, "rule");
        parse_err(parse_yara_file, "rule a { condition: true } b");
    }
}