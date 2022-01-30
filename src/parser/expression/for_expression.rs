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
    sequence::{delimited, pair, preceded, terminated},
};

use crate::parser::{
    nom_recipes::{rtrim, textual_tag as ttag},
    string::string_identifier_with_wildcard,
    types::{Input, ParseResult},
};

use super::{
    common::range, expression, identifier::identifier, primary_expression::primary_expression,
    Expression, ForIterator, ForSelection, ParsedExpr, VariableSet,
};

/// Parse all variantes of for expressions.
pub fn for_expression(input: Input) -> ParseResult<ParsedExpr> {
    alt((for_expression_full, for_expression_abbrev))(input)
}

/// Parse for expressions without any for keyword or body content.
///
/// This parses:
/// - `selection 'of' set`
/// - `selection 'of' set 'in' range`
fn for_expression_abbrev(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, selection) = for_selection(input)?;
    let (input, set) = preceded(rtrim(ttag("of")), cut(string_set))(input)?;
    let (input, range) = opt(preceded(rtrim(ttag("in")), cut(range)))(input)?;

    let expr = match range {
        None => Expression::For {
            selection,
            set,
            body: None,
        },
        Some((from, to)) => Expression::ForIn {
            selection,
            set,
            from,
            to,
        },
    };

    Ok((
        input,
        ParsedExpr {
            expr,
            span: input.get_span_from(start),
        },
    ))
}

/// Parse a full fledge for expression:
///
/// This parses:
/// - 'for' selection 'of' set ':' '(' body ')'
/// - 'for' selection identifier 'of' iterator ':' '(' body ')'
fn for_expression_full(input: Input) -> ParseResult<ParsedExpr> {
    let start = input;
    let (input, selection) = preceded(rtrim(ttag("for")), cut(for_selection))(input)?;
    let (i2, has_of) = opt(rtrim(ttag("of")))(input)?;

    if has_of.is_some() {
        let (input, set) = cut(terminated(string_set, rtrim(char(':'))))(i2)?;
        let (input, body) = cut(delimited(rtrim(char('(')), expression, rtrim(char(')'))))(input)?;

        Ok((
            input,
            ParsedExpr {
                expr: Expression::For {
                    selection,
                    set,
                    body: Some(Box::new(body)),
                },
                span: input.get_span_from(start),
            },
        ))
    } else {
        let (input, identifiers) = cut(terminated(for_variables, rtrim(ttag("of"))))(input)?;
        let (input, iterator) = cut(terminated(iterator, rtrim(char(':'))))(input)?;
        let (input, body) = cut(delimited(rtrim(char('(')), expression, rtrim(char(')'))))(input)?;

        Ok((
            input,
            ParsedExpr {
                expr: Expression::ForIdentifiers {
                    selection,
                    identifiers,
                    iterator,
                    body: Box::new(body),
                },
                span: input.get_span_from(start),
            },
        ))
    }
}

/// Parse the variable selection for a 'for' expression.
///
/// Equivalent to the `for_expression` pattern in grammar.y in libyara.
fn for_selection(input: Input) -> ParseResult<ForSelection> {
    alt((
        map(rtrim(ttag("any")), |_| ForSelection::Any),
        map(rtrim(ttag("all")), |_| ForSelection::All),
        map(rtrim(ttag("none")), |_| ForSelection::None),
        map(
            pair(primary_expression, opt(rtrim(char('%')))),
            |(expr, percent)| ForSelection::Expr {
                expr: Box::new(expr),
                as_percent: percent.is_some(),
            },
        ),
    ))(input)
}

/// Parse a set of variables.
///
/// Equivalent to the `string_set` pattern in grammar.y in libyara.
fn string_set(input: Input) -> ParseResult<VariableSet> {
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
fn string_enumeration(input: Input) -> ParseResult<Vec<(String, bool)>> {
    separated_list1(rtrim(char(',')), string_identifier_with_wildcard)(input)
}

/// Parse a list of identifiers to bind for a for expression.
///
/// Equivalent to the `for_variables` pattern in grammar.y in libyara.
fn for_variables(input: Input) -> ParseResult<Vec<String>> {
    separated_list1(rtrim(char(',')), crate::parser::string::identifier)(input)
}

/// Parse an iterator for a for over an identifier.
///
/// Equivalent to the `iterator` pattern in grammar.y in libyara.
fn iterator(input: Input) -> ParseResult<ForIterator> {
    alt((
        map(identifier, ForIterator::Identifier),
        map(
            delimited(
                rtrim(char('(')),
                separated_list1(rtrim(char(',')), primary_expression),
                rtrim(char(')')),
            ),
            ForIterator::List,
        ),
        map(range, |(from, to)| ForIterator::Range { from, to }),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{
        expression::{Expression, Identifier},
        tests::{parse, parse_err},
    };

    #[test]
    fn test_for_selection() {
        parse(for_selection, "any a", "a", ForSelection::Any);
        parse(for_selection, "all a", "a", ForSelection::All);
        parse(for_selection, "none a", "a", ForSelection::None);
        parse(
            for_selection,
            "1a",
            "a",
            ForSelection::Expr {
                expr: Box::new(ParsedExpr {
                    expr: Expression::Number(1),
                    span: 0..1,
                }),
                as_percent: false,
            },
        );
        parse(
            for_selection,
            "50% of",
            "of",
            ForSelection::Expr {
                expr: Box::new(ParsedExpr {
                    expr: Expression::Number(50),
                    span: 0..2,
                }),
                as_percent: true,
            },
        );

        parse(
            for_selection,
            "anya",
            "",
            ForSelection::Expr {
                expr: Box::new(ParsedExpr {
                    expr: Expression::Identifier(Identifier::Raw("anya".to_owned())),
                    span: 0..4,
                }),
                as_percent: false,
            },
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
                    body: None,
                },
                span: 0..11,
            },
        );
        parse(
            for_expression_abbrev,
            "50% of them",
            "",
            ParsedExpr {
                expr: Expression::For {
                    selection: ForSelection::Expr {
                        expr: Box::new(ParsedExpr {
                            expr: Expression::Number(50),
                            span: 0..2,
                        }),
                        as_percent: true,
                    },
                    set: VariableSet { elements: vec![] },
                    body: None,
                },
                span: 0..11,
            },
        );
        parse(
            for_expression_abbrev,
            "5 of ($a, $b*) in (100..entrypoint)",
            "",
            ParsedExpr {
                expr: Expression::ForIn {
                    selection: ForSelection::Expr {
                        expr: Box::new(ParsedExpr {
                            expr: Expression::Number(5),
                            span: 0..1,
                        }),
                        as_percent: false,
                    },
                    set: VariableSet {
                        elements: vec![("a".to_owned(), false), ("b".to_owned(), true)],
                    },
                    from: Box::new(ParsedExpr {
                        expr: Expression::Number(100),
                        span: 19..22,
                    }),
                    to: Box::new(ParsedExpr {
                        expr: Expression::Entrypoint,
                        span: 24..34,
                    }),
                },
                span: 0..35,
            },
        );

        parse_err(for_expression_abbrev, "");
        parse_err(for_expression_abbrev, "any");
        parse_err(for_expression_abbrev, "any of");
        parse_err(for_expression_abbrev, "any of thema");
        parse_err(for_expression_abbrev, "all of them in");
        parse_err(for_expression_abbrev, "all of them in ()");
    }

    #[test]
    fn test_for_expression_full() {
        parse(
            for_expression_full,
            "for 25% of ($foo*) : ($)",
            "",
            ParsedExpr {
                expr: Expression::For {
                    selection: ForSelection::Expr {
                        expr: Box::new(ParsedExpr {
                            expr: Expression::Number(25),
                            span: 4..6,
                        }),
                        as_percent: true,
                    },
                    set: VariableSet {
                        elements: vec![("foo".to_owned(), true)],
                    },
                    body: Some(Box::new(ParsedExpr {
                        expr: Expression::Variable("".to_owned()),
                        span: 22..23,
                    })),
                },
                span: 0..24,
            },
        );
        parse(
            for_expression_full,
            "for all i of (1 ,3) : ( false )",
            "",
            ParsedExpr {
                expr: Expression::ForIdentifiers {
                    selection: ForSelection::All,
                    identifiers: vec!["i".to_owned()],
                    iterator: ForIterator::List(vec![
                        ParsedExpr {
                            expr: Expression::Number(1),
                            span: 14..15,
                        },
                        ParsedExpr {
                            expr: Expression::Number(3),
                            span: 17..18,
                        },
                    ]),
                    body: Box::new(ParsedExpr {
                        expr: Expression::Boolean(false),
                        span: 24..29,
                    }),
                },
                span: 0..31,
            },
        );
        parse(
            for_expression_full,
            "for any a,b,c of toto:(false) b",
            "b",
            ParsedExpr {
                expr: Expression::ForIdentifiers {
                    selection: ForSelection::Any,
                    identifiers: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
                    iterator: ForIterator::Identifier(Identifier::Raw("toto".to_owned())),
                    body: Box::new(ParsedExpr {
                        expr: Expression::Boolean(false),
                        span: 23..28,
                    }),
                },
                span: 0..29,
            },
        );

        parse_err(for_expression_full, "");
        parse_err(for_expression_full, "for");
        parse_err(for_expression_full, "for all");
        parse_err(for_expression_full, "for all of");
        parse_err(for_expression_full, "for all of them");
        parse_err(for_expression_full, "for 5% of them :");
        parse_err(for_expression_full, "for 5% of them: (");
        parse_err(for_expression_full, "for 5% of them: (");
        parse_err(for_expression_full, "for 5% of them: ()");
        parse_err(for_expression_full, "for 5% of them :)");
        parse_err(for_expression_full, "for 5% of them :(");

        parse_err(for_expression_full, "for all i");
        parse_err(for_expression_full, "for all i of");
        parse_err(for_expression_full, "for all i of (1)");
        parse_err(for_expression_full, "for all i of (1) :");
        parse_err(for_expression_full, "for all i of (1) : (");
        parse_err(for_expression_full, "for all i of (1) : )");
        parse_err(for_expression_full, "for all i of (1) : ())");
    }

    #[test]
    fn test_for_variables() {
        parse(for_variables, "i a", "a", vec!["i".to_owned()]);
        parse(
            for_variables,
            "i, ae ,t b",
            "b",
            vec!["i".to_owned(), "ae".to_owned(), "t".to_owned()],
        );

        parse_err(for_variables, "");
        parse_err(for_variables, "5");
    }

    #[test]
    fn test_iterator() {
        parse(
            iterator,
            "i.b a",
            "a",
            ForIterator::Identifier(Identifier::Subfield {
                identifier: Box::new(Identifier::Raw("i".to_owned())),
                subfield: "b".to_owned(),
            }),
        );
        parse(
            iterator,
            "(1)b",
            "b",
            ForIterator::List(vec![ParsedExpr {
                expr: Expression::Number(1),
                span: 1..2,
            }]),
        );
        parse(
            iterator,
            "(1, 2,#a)b",
            "b",
            ForIterator::List(vec![
                ParsedExpr {
                    expr: Expression::Number(1),
                    span: 1..2,
                },
                ParsedExpr {
                    expr: Expression::Number(2),
                    span: 4..5,
                },
                ParsedExpr {
                    expr: Expression::Count("a".to_owned()),
                    span: 6..8,
                },
            ]),
        );
        parse(
            iterator,
            "(1..#t) b",
            "b",
            ForIterator::Range {
                from: Box::new(ParsedExpr {
                    expr: Expression::Number(1),
                    span: 1..2,
                }),
                to: Box::new(ParsedExpr {
                    expr: Expression::Count("t".to_owned()),
                    span: 4..6,
                }),
            },
        );

        parse_err(iterator, "");
        parse_err(iterator, "(");
        parse_err(iterator, "()");
        parse_err(iterator, ")");
        parse_err(iterator, "(1,2");
        parse_err(iterator, "(1..2");
    }
}
