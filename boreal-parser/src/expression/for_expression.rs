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
    sequence::{delimited, preceded, terminated},
};

use crate::{
    nom_recipes::{rtrim, textual_tag as ttag},
    string::string_identifier_with_wildcard,
    types::{Input, ParseResult},
};

use super::{
    boolean_expression::boolean_expression, common::range, identifier::identifier,
    primary_expression::primary_expression, Expression, ExpressionKind, ForIterator, ForSelection,
    VariableSet,
};

// There is a very ugly hack in this file.
//
// Instead of having a single entrypoint, `for_expression`, there are two:
// - `for_expression_non_ambiguous`, to parse all variants that can be
//   recognized on the first token.
// - `for_expression_with_expr_selection`, to parse the 'expr(%) of ...'
//   variant.
//
// This is done in order to avoid this very inefficient parsing scenario:
// - as part of boolean_expression parsing, call 'for_expression'
// - parse a primary_expression
// - try to parse 'of', this fail, rollback
// - as part of boolean_expression parsing, then parse
//   primary_expression again.
//
// In addition to inefficient parsing, this prevents properly unwrapping
// the ParsedExpr with the correct type when generating a ForSelection.

/// Parse all variants of for expressions that are non ambiguous
///
/// Those are all the variants but for the 'expr ('%') of ...', which
/// binds a primary expression as its first element, conflicting
/// with the "just one primary expression" possibility.
pub(super) fn for_expression_non_ambiguous(input: Input) -> ParseResult<Expression> {
    alt((for_expression_full, for_expression_abbrev))(input)
}

/// Parse for expressions without any for keyword or body content.
///
/// This parses:
/// - `selection 'of' set`
/// - `selection 'of' set 'in' range`
///
/// But with 'selection' not being an expression.
fn for_expression_abbrev(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (input, selection) = for_selection_simple(input)?;
    for_expression_with_selection(selection, start, input)
}

/// This parses a for expression abbrev version, but as if the first
/// token was already parsed as a primary expression.
///
/// XXX: this is a different function than the other parser. If an
/// 'of' token is not detected, the expr is returned as is in an Ok
/// result, so as to return the moved value without needing duplication.
pub(super) fn for_expression_with_expr_selection<'a>(
    expr: Expression,
    start: Input<'a>,
    input: Input<'a>,
) -> ParseResult<'a, Expression> {
    let (input, percent) = opt(rtrim(char('%')))(input)?;
    if ttag("of")(input).is_err() {
        return Ok((input, expr));
    }

    let selection = ForSelection::Expr {
        expr: Box::new(expr),
        as_percent: percent.is_some(),
    };
    for_expression_with_selection(selection, start, input)
}

fn for_expression_with_selection<'a>(
    selection: ForSelection,
    start: Input<'a>,
    input: Input<'a>,
) -> ParseResult<'a, Expression> {
    let (input, set) = preceded(rtrim(ttag("of")), cut(string_set))(input)?;
    let (input, range) = opt(preceded(rtrim(ttag("in")), cut(range)))(input)?;

    let expr = match range {
        None => ExpressionKind::For {
            selection,
            set,
            body: None,
        },
        Some((from, to)) => ExpressionKind::ForIn {
            selection,
            set,
            from,
            to,
        },
    };

    Ok((
        input,
        Expression {
            expr,
            span: input.get_span_from(start),
        },
    ))
}

/// Parse a full fledge for expression:
///
/// This parses:
/// - 'for' selection 'of' set ':' '(' body ')'
/// - 'for' selection identifier 'in' iterator ':' '(' body ')'
fn for_expression_full(input: Input) -> ParseResult<Expression> {
    let start = input;
    let (input, selection) = preceded(rtrim(ttag("for")), cut(for_selection_full))(input)?;
    let (i2, has_of) = opt(rtrim(ttag("of")))(input)?;

    if has_of.is_some() {
        let (input, set) = cut(terminated(string_set, rtrim(char(':'))))(i2)?;
        let (input, body) = cut(delimited(
            rtrim(char('(')),
            boolean_expression,
            rtrim(char(')')),
        ))(input)?;

        Ok((
            input,
            Expression {
                expr: ExpressionKind::For {
                    selection,
                    set,
                    body: Some(Box::new(body)),
                },
                span: input.get_span_from(start),
            },
        ))
    } else {
        let (input, identifiers) = cut(terminated(for_variables, rtrim(ttag("in"))))(input)?;
        let (input, iterator) = cut(terminated(iterator, rtrim(char(':'))))(input)?;
        let (input, body) = cut(delimited(
            rtrim(char('(')),
            boolean_expression,
            rtrim(char(')')),
        ))(input)?;

        Ok((
            input,
            Expression {
                expr: ExpressionKind::ForIdentifiers {
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
fn for_selection_simple(input: Input) -> ParseResult<ForSelection> {
    alt((
        map(rtrim(ttag("any")), |_| ForSelection::Any),
        map(rtrim(ttag("all")), |_| ForSelection::All),
        map(rtrim(ttag("none")), |_| ForSelection::None),
    ))(input)
}

fn for_selection_expr(input: Input) -> ParseResult<ForSelection> {
    let (input, expr) = primary_expression(input)?;
    let (input, percent) = opt(rtrim(char('%')))(input)?;

    Ok((
        input,
        ForSelection::Expr {
            expr: Box::new(expr),
            as_percent: percent.is_some(),
        },
    ))
}

fn for_selection_full(input: Input) -> ParseResult<ForSelection> {
    alt((for_selection_simple, for_selection_expr))(input)
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
    separated_list1(rtrim(char(',')), crate::string::identifier)(input)
}

/// Parse an iterator for a for over an identifier.
///
/// Equivalent to the `iterator` pattern in grammar.y in libyara.
fn iterator(input: Input) -> ParseResult<ForIterator> {
    alt((
        map(identifier, ForIterator::Identifier),
        iterator_list,
        iterator_range,
    ))(input)
}

fn iterator_list(input: Input) -> ParseResult<ForIterator> {
    let (input, exprs) = delimited(
        rtrim(char('(')),
        separated_list1(rtrim(char(',')), primary_expression),
        rtrim(char(')')),
    )(input)?;

    Ok((input, ForIterator::List(exprs)))
}

fn iterator_range(input: Input) -> ParseResult<ForIterator> {
    let (input, (from, to)) = range(input)?;
    Ok((input, ForIterator::Range { from, to }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::{ExpressionKind, Identifier},
        tests::{parse, parse_err},
    };

    #[test]
    fn test_for_selection() {
        parse(for_selection_full, "any a", "a", ForSelection::Any);
        parse(for_selection_full, "all a", "a", ForSelection::All);
        parse(for_selection_full, "none a", "a", ForSelection::None);
        parse(for_selection_simple, "any a", "a", ForSelection::Any);
        parse(for_selection_simple, "all a", "a", ForSelection::All);
        parse(for_selection_simple, "none a", "a", ForSelection::None);
        parse(
            for_selection_full,
            "1a",
            "a",
            ForSelection::Expr {
                expr: Box::new(Expression {
                    expr: ExpressionKind::Number(1),
                    span: 0..1,
                }),
                as_percent: false,
            },
        );
        parse(
            for_selection_full,
            "50% of",
            "of",
            ForSelection::Expr {
                expr: Box::new(Expression {
                    expr: ExpressionKind::Number(50),
                    span: 0..2,
                }),
                as_percent: true,
            },
        );

        parse(
            for_selection_full,
            "anya",
            "",
            ForSelection::Expr {
                expr: Box::new(Expression {
                    expr: ExpressionKind::Identifier(Identifier::Raw("anya".to_owned())),
                    span: 0..4,
                }),
                as_percent: false,
            },
        );

        parse_err(for_selection_full, "");
        parse_err(for_selection_simple, "1a");
        parse_err(for_selection_simple, "50%");
        parse_err(for_selection_simple, "anya");
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
    fn test_expression() {
        parse(
            boolean_expression,
            "any of them a",
            "a",
            Expression {
                expr: ExpressionKind::For {
                    selection: ForSelection::Any,
                    set: VariableSet { elements: vec![] },
                    body: None,
                },
                span: 0..11,
            },
        );
        parse(
            boolean_expression,
            "50% of them",
            "",
            Expression {
                expr: ExpressionKind::For {
                    selection: ForSelection::Expr {
                        expr: Box::new(Expression {
                            expr: ExpressionKind::Number(50),
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
            boolean_expression,
            "5 of ($a, $b*) in (100..entrypoint)",
            "",
            Expression {
                expr: ExpressionKind::ForIn {
                    selection: ForSelection::Expr {
                        expr: Box::new(Expression {
                            expr: ExpressionKind::Number(5),
                            span: 0..1,
                        }),
                        as_percent: false,
                    },
                    set: VariableSet {
                        elements: vec![("a".to_owned(), false), ("b".to_owned(), true)],
                    },
                    from: Box::new(Expression {
                        expr: ExpressionKind::Number(100),
                        span: 19..22,
                    }),
                    to: Box::new(Expression {
                        expr: ExpressionKind::Entrypoint,
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
    fn test_for_expression_full_of() {
        parse(
            for_expression_full,
            "for 25% of ($foo*) : ($)",
            "",
            Expression {
                expr: ExpressionKind::For {
                    selection: ForSelection::Expr {
                        expr: Box::new(Expression {
                            expr: ExpressionKind::Number(25),
                            span: 4..6,
                        }),
                        as_percent: true,
                    },
                    set: VariableSet {
                        elements: vec![("foo".to_owned(), true)],
                    },
                    body: Some(Box::new(Expression {
                        expr: ExpressionKind::Variable("".to_owned()),
                        span: 22..23,
                    })),
                },
                span: 0..24,
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
    }

    #[test]
    fn test_for_expression_identifier() {
        parse(
            for_expression_full,
            "for all i in (1 ,3) : ( false )",
            "",
            Expression {
                expr: ExpressionKind::ForIdentifiers {
                    selection: ForSelection::All,
                    identifiers: vec!["i".to_owned()],
                    iterator: ForIterator::List(vec![
                        Expression {
                            expr: ExpressionKind::Number(1),
                            span: 14..15,
                        },
                        Expression {
                            expr: ExpressionKind::Number(3),
                            span: 17..18,
                        },
                    ]),
                    body: Box::new(Expression {
                        expr: ExpressionKind::Boolean(false),
                        span: 24..29,
                    }),
                },
                span: 0..31,
            },
        );
        parse(
            for_expression_full,
            "for any s in (0..5 - 1) : ( false )",
            "",
            Expression {
                expr: ExpressionKind::ForIdentifiers {
                    selection: ForSelection::Any,
                    identifiers: vec!["s".to_owned()],
                    iterator: ForIterator::Range {
                        from: Box::new(Expression {
                            expr: ExpressionKind::Number(0),
                            span: 14..15,
                        }),
                        to: Box::new(Expression {
                            expr: ExpressionKind::Sub(
                                Box::new(Expression {
                                    expr: ExpressionKind::Number(5),
                                    span: 17..18,
                                }),
                                Box::new(Expression {
                                    expr: ExpressionKind::Number(1),
                                    span: 21..22,
                                }),
                            ),
                            span: 17..22,
                        }),
                    },
                    body: Box::new(Expression {
                        expr: ExpressionKind::Boolean(false),
                        span: 28..33,
                    }),
                },
                span: 0..35,
            },
        );
        parse(
            for_expression_full,
            "for any a,b,c in toto:(false) b",
            "b",
            Expression {
                expr: ExpressionKind::ForIdentifiers {
                    selection: ForSelection::Any,
                    identifiers: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
                    iterator: ForIterator::Identifier(Identifier::Raw("toto".to_owned())),
                    body: Box::new(Expression {
                        expr: ExpressionKind::Boolean(false),
                        span: 23..28,
                    }),
                },
                span: 0..29,
            },
        );

        parse_err(for_expression_full, "for all i");
        parse_err(for_expression_full, "for all i in");
        parse_err(for_expression_full, "for all i in (1)");
        parse_err(for_expression_full, "for all i in (1) :");
        parse_err(for_expression_full, "for all i in (1) : (");
        parse_err(for_expression_full, "for all i in (1) : )");
        parse_err(for_expression_full, "for all i in (1) : ())");
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
            ForIterator::List(vec![Expression {
                expr: ExpressionKind::Number(1),
                span: 1..2,
            }]),
        );
        parse(
            iterator,
            "(1, 2,#a)b",
            "b",
            ForIterator::List(vec![
                Expression {
                    expr: ExpressionKind::Number(1),
                    span: 1..2,
                },
                Expression {
                    expr: ExpressionKind::Number(2),
                    span: 4..5,
                },
                Expression {
                    expr: ExpressionKind::Count("a".to_owned()),
                    span: 6..8,
                },
            ]),
        );
        parse(
            iterator,
            "(1..#t) b",
            "b",
            ForIterator::Range {
                from: Box::new(Expression {
                    expr: ExpressionKind::Number(1),
                    span: 1..2,
                }),
                to: Box::new(Expression {
                    expr: ExpressionKind::Count("t".to_owned()),
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
