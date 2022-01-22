//! Parsers for everything related to 'for' expressions
//!
//! For expressions are anything that iterates on a number of expression:
//! - X of Y
//! - for X of Y
//! - ...
use nom::{
    branch::alt,
    character::complete::char,
    combinator::{cut, map, opt},
    multi::separated_list1,
    sequence::{delimited, preceded},
    IResult,
};

use crate::parser::{
    nom_recipes::{rtrim, textual_tag as ttag},
    string::string_identifier_with_wildcard,
};

use super::{
    common::range, primary_expression::primary_expression, Expression, ForSelection, ParsedExpr,
    VariableSet,
};

/// Parse for expressions without any for keyword or body content.
///
/// This parses:
/// - `selection 'of' set`
/// - `selection 'of' set 'in' range`
fn for_expression_abbrev(input: &str) -> IResult<&str, ParsedExpr> {
    let (input, selection) = for_selection(input)?;
    let (input, set) = cut(preceded(rtrim(ttag("of")), string_set))(input)?;
    let (input, range) = opt(preceded(rtrim(ttag("in")), cut(range)))(input)?;

    let expr = match range {
        None => Expression::For { selection, set },
        Some((from, to)) => Expression::ForIn {
            selection,
            set,
            from,
            to,
        },
    };
    Ok((input, ParsedExpr { expr }))
}

/// Parse the variable selection for a 'for' expression.
///
/// Equivalent to the `for_expression` pattern in grammar.y in libyara.
fn for_selection(input: &str) -> IResult<&str, ForSelection> {
    alt((
        map(rtrim(ttag("any")), |_| ForSelection::Any),
        map(rtrim(ttag("all")), |_| ForSelection::All),
        map(rtrim(ttag("none")), |_| ForSelection::None),
        map(primary_expression, |expr| {
            ForSelection::Expr(Box::new(expr))
        }),
    ))(input)
}

/// Parse a set of variables.
///
/// Equivalent to the `string_set` pattern in grammar.y in libyara.
fn string_set(input: &str) -> IResult<&str, VariableSet> {
    alt((
        map(rtrim(ttag("them")), |_| VariableSet { elements: vec![] }),
        map(
            delimited(
                rtrim(char('(')),
                cut(string_enumeration),
                cut(rtrim(char(')'))),
            ),
            |elements| VariableSet { elements },
        ),
    ))(input)
}

/// Parse an enumeration of variables.
///
/// Equivalent to the `string_enumeration` pattern in grammar.y in libyara.
fn string_enumeration(input: &str) -> IResult<&str, Vec<(String, bool)>> {
    separated_list1(rtrim(char(',')), string_identifier_with_wildcard)(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expression::{Expression, Identifier};
    use crate::parser::test_utils::{parse, parse_err};

    #[test]
    fn test_for_selection() {
        parse(for_selection, "any a", "a", ForSelection::Any);
        parse(for_selection, "all a", "a", ForSelection::All);
        parse(for_selection, "none a", "a", ForSelection::None);
        parse(
            for_selection,
            "1a",
            "a",
            ForSelection::Expr(Box::new(ParsedExpr {
                expr: Expression::Number(1),
            })),
        );

        parse(
            for_selection,
            "anya",
            "",
            ForSelection::Expr(Box::new(ParsedExpr {
                expr: Expression::Identifier(Identifier::Raw("anya".to_owned())),
            })),
        );

        parse_err(for_selection, "");
    }

    #[test]
    fn test_string_enumeration() {
        parse(string_enumeration, "$a", "", vec![("a".to_owned(), false)]);
        parse(
            string_enumeration,
            "$a, $b* $c",
            "$c",
            vec![("a".to_owned(), false), ("b".to_owned(), true)],
        );
        parse(
            string_enumeration,
            "$a*,b",
            ",b",
            vec![("a".to_owned(), true)],
        );
        parse(
            string_enumeration,
            "$foo*,$ , $bar)",
            ")",
            vec![
                ("foo".to_owned(), true),
                ("".to_owned(), false),
                ("bar".to_owned(), false),
            ],
        );

        parse_err(string_enumeration, "");
        parse_err(string_enumeration, ",");
    }

    #[test]
    fn test_string_set() {
        parse(string_set, "them a", "a", VariableSet { elements: vec![] });
        parse(
            string_set,
            "( $a*, $foo* , $c ) d",
            "d",
            VariableSet {
                elements: vec![
                    ("a".to_owned(), true),
                    ("foo".to_owned(), true),
                    ("c".to_owned(), false),
                ],
            },
        );
        parse(
            string_set,
            "($)",
            "",
            VariableSet {
                elements: vec![("".to_owned(), false)],
            },
        );

        parse_err(string_enumeration, "");
        parse_err(string_enumeration, "thema");
        parse_err(string_enumeration, "(");
        parse_err(string_enumeration, ")");
        parse_err(string_enumeration, "()");
        parse_err(string_enumeration, "($a,a)");
    }

    #[test]
    fn test_for_expression_abbrev() {
        parse(
            for_expression_abbrev,
            "any of them a",
            "a",
            ParsedExpr {
                expr: Expression::For {
                    selection: ForSelection::Any,
                    set: VariableSet { elements: vec![] },
                },
            },
        );
        parse(
            for_expression_abbrev,
            "5 of ($a, $b*) in (100..entrypoint)",
            "",
            ParsedExpr {
                expr: Expression::ForIn {
                    selection: ForSelection::Expr(Box::new(ParsedExpr {
                        expr: Expression::Number(5),
                    })),
                    set: VariableSet {
                        elements: vec![("a".to_owned(), false), ("b".to_owned(), true)],
                    },
                    from: Box::new(ParsedExpr {
                        expr: Expression::Number(100),
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Entrypoint,
                    }),
                },
            },
        );

        parse_err(for_expression_abbrev, "");
        parse_err(for_expression_abbrev, "any");
        parse_err(for_expression_abbrev, "any of");
        parse_err(for_expression_abbrev, "any of thema");
        parse_err(for_expression_abbrev, "all of them in");
        parse_err(for_expression_abbrev, "all of them in ()");
    }
}
