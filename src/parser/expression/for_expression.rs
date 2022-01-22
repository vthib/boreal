//! Parsers for everything related to 'for' expressions
//!
//! For expressions are anything that iterates on a number of expression:
//! - X of Y
//! - for X of Y
//! - ...
use nom::{
    branch::alt,
    character::complete::char,
    combinator::{cut, map},
    multi::separated_list1,
    sequence::delimited,
    IResult,
};

use crate::parser::{
    nom_recipes::{rtrim, textual_tag as ttag},
    string::string_identifier_with_wildcard,
};

use super::{primary_expression::primary_expression, ParsedExpr};

/// Selection of variables in a 'for' expression.
///
/// This indicates how many variables must match the for condition
/// for it to be considered true.
#[derive(Debug, PartialEq)]
enum ForSelection {
    /// Any variable in the set must match the condition.
    Any,
    /// All of the variables in the set must match the condition.
    All,
    /// None of the variables in the set must match the condition.
    None,
    /// Expression that should evaluate to a number, indicating
    /// how many variables in the set must match the condition.
    ///
    /// Usually, a simple number.
    Expr(Box<ParsedExpr>),
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

/// Set of multiple variables.
#[derive(Debug, PartialEq)]
struct VariableSet {
    /// Names of the variables in the set.
    ///
    /// If empty, the set is considered as containing *all* variables.
    /// The associated boolean indicates if the name has a trailing
    /// wildcard.
    elements: Vec<(String, bool)>,
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
}
