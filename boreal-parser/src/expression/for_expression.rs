//! Parsers for everything related to 'for' expressions
//!
//! For expressions are anything that iterates on a number of expression:
//! - X of Y
//! - for X of Y
//! - ...
use std::ops::Range;

use nom::branch::alt;
use nom::character::complete::char;
use nom::combinator::{cut, map, opt, success};
use nom::multi::separated_list1;
use nom::sequence::{delimited, preceded, terminated};
use nom::Parser;

use crate::expression::boolean_expression::boolean_expression;
use crate::expression::common::range;
use crate::expression::identifier::identifier;
use crate::expression::primary_expression::primary_expression;
use crate::expression::{
    Expression, ExpressionKind, ForIterator, ForSelection, RuleSet, SetElement, VariableSet,
};
use crate::nom_recipes::{rtrim, textual_tag as ttag};
use crate::string::{self, string_identifier_with_wildcard};
use crate::types::{Input, ParseResult, Position};

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
    alt((for_expression_full, for_expression_abbrev)).parse(input)
}

/// Parse for expressions without any for keyword or body content.
///
/// This parses:
/// - `selection 'of' set`
/// - `selection 'of' set 'in' range`
/// - `selection 'of' set 'at' expr`
///
/// But with 'selection' not being an expression.
fn for_expression_abbrev(input: Input) -> ParseResult<Expression> {
    let start = input.pos();
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
    start: Position<'a>,
    input: Input<'a>,
) -> ParseResult<'a, Expression> {
    let (input, percent) = opt(rtrim(char('%'))).parse(input)?;
    if ttag("of").parse(input).is_err() {
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
    start: Position<'a>,
    input: Input<'a>,
) -> ParseResult<'a, Expression> {
    let (input, _) = rtrim(ttag("of")).parse(input)?;

    let (input, expr) = match rule_set(input) {
        Ok((input, set)) => (input, ExpressionKind::ForRules { selection, set }),
        Err(_) => {
            let (input, set) = cut(string_set).parse(input)?;
            let (input, kind) = for_expression_kind(input)?;
            (
                input,
                match kind {
                    ForExprKind::None => ExpressionKind::For {
                        selection,
                        set,
                        body: None,
                    },
                    ForExprKind::In(from, to) => ExpressionKind::ForIn {
                        selection,
                        set,
                        from,
                        to,
                    },
                    ForExprKind::At(offset) => ExpressionKind::ForAt {
                        selection,
                        set,
                        offset,
                    },
                },
            )
        }
    };

    Ok((
        input,
        Expression {
            expr,
            span: input.get_span_from(start),
        },
    ))
}

enum ForExprKind {
    None,
    In(Box<Expression>, Box<Expression>),
    At(Box<Expression>),
}

fn for_expression_kind(input: Input) -> ParseResult<ForExprKind> {
    alt((
        map(preceded(rtrim(ttag("in")), cut(range)), |(a, b)| {
            ForExprKind::In(a, b)
        }),
        map(
            preceded(rtrim(ttag("at")), cut(primary_expression)),
            |expr| ForExprKind::At(Box::new(expr)),
        ),
        map(success(()), |()| ForExprKind::None),
    ))
    .parse(input)
}

/// Parse a full fledge for expression:
///
/// This parses:
/// - 'for' selection 'of' set ':' '(' body ')'
/// - 'for' selection identifier 'in' iterator ':' '(' body ')'
fn for_expression_full(input: Input) -> ParseResult<Expression> {
    let start = input.pos();
    let (input, selection) = preceded(rtrim(ttag("for")), cut(for_selection_full)).parse(input)?;
    let (i2, has_of) = opt(rtrim(ttag("of"))).parse(input)?;

    if has_of.is_some() {
        let (input, set) = cut(terminated(string_set, rtrim(char(':')))).parse(i2)?;
        let (input, body) = cut(delimited(
            rtrim(char('(')),
            boolean_expression,
            rtrim(char(')')),
        ))
        .parse(input)?;

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
        let (input, (identifiers, identifiers_span)) =
            cut(terminated(for_variables, rtrim(ttag("in")))).parse(input)?;

        let (input, (iterator, iterator_span)) =
            cut(terminated(iterator, rtrim(char(':')))).parse(input)?;

        let (input, body) = cut(delimited(
            rtrim(char('(')),
            boolean_expression,
            rtrim(char(')')),
        ))
        .parse(input)?;

        Ok((
            input,
            Expression {
                expr: ExpressionKind::ForIdentifiers {
                    selection,
                    identifiers,
                    identifiers_span,
                    iterator,
                    iterator_span,
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
    ))
    .parse(input)
}

fn for_selection_expr(input: Input) -> ParseResult<ForSelection> {
    let (input, expr) = primary_expression(input)?;
    let (input, percent) = opt(rtrim(char('%'))).parse(input)?;

    Ok((
        input,
        ForSelection::Expr {
            expr: Box::new(expr),
            as_percent: percent.is_some(),
        },
    ))
}

fn for_selection_full(input: Input) -> ParseResult<ForSelection> {
    alt((for_selection_simple, for_selection_expr)).parse(input)
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
    ))
    .parse(input)
}

/// Parse an enumeration of variables.
///
/// Equivalent to the `string_enumeration` pattern in grammar.y in libyara.
fn string_enumeration(input: Input) -> ParseResult<Vec<SetElement>> {
    separated_list1(rtrim(char(',')), string_enum_element).parse(input)
}

fn string_enum_element(input: Input) -> ParseResult<SetElement> {
    let start = input.pos();
    let (input, (name, is_wildcard)) = string_identifier_with_wildcard(input)?;

    Ok((
        input,
        SetElement {
            name,
            is_wildcard,
            span: input.get_span_from(start),
        },
    ))
}

/// Parse a list of identifiers to bind for a for expression.
///
/// Equivalent to the `for_variables` pattern in grammar.y in libyara.
fn for_variables(input: Input) -> ParseResult<(Vec<String>, Range<usize>)> {
    let start = input.pos();
    let (input, identifiers) =
        separated_list1(rtrim(char(',')), string::identifier).parse(input)?;
    Ok((input, (identifiers, input.get_span_from(start))))
}

/// Parse an iterator for a for over an identifier.
///
/// Equivalent to the `iterator` pattern in grammar.y in libyara.
fn iterator(input: Input) -> ParseResult<(ForIterator, Range<usize>)> {
    let start = input.pos();
    let (input, iterator) = alt((
        map(identifier, ForIterator::Identifier),
        iterator_list,
        iterator_range,
    ))
    .parse(input)?;
    Ok((input, (iterator, input.get_span_from(start))))
}

fn iterator_list(input: Input) -> ParseResult<ForIterator> {
    let (input, exprs) = delimited(
        rtrim(char('(')),
        separated_list1(rtrim(char(',')), primary_expression),
        rtrim(char(')')),
    )
    .parse(input)?;

    Ok((input, ForIterator::List(exprs)))
}

fn iterator_range(input: Input) -> ParseResult<ForIterator> {
    let (input, (from, to)) = range(input)?;
    Ok((input, ForIterator::Range { from, to }))
}

/// Parse a set of rules.
///
/// Equivalent to the `rule_set` pattern in grammar.y in libyara.
fn rule_set(input: Input) -> ParseResult<RuleSet> {
    map(
        delimited(rtrim(char('(')), rule_enumeration, rtrim(char(')'))),
        |elements| RuleSet { elements },
    )
    .parse(input)
}

/// Parse an enumeration of rules.
///
/// Equivalent to the `rule_enumeration` pattern in grammar.y in libyara.
fn rule_enumeration(input: Input) -> ParseResult<Vec<SetElement>> {
    separated_list1(rtrim(char(',')), rule_enum_element).parse(input)
}

fn rule_enum_element(input: Input) -> ParseResult<SetElement> {
    let start = input.pos();
    let (input, name) = string::identifier(input)?;
    let (input, is_wildcard) = map(opt(rtrim(char('*'))), |v| v.is_some()).parse(input)?;

    Ok((
        input,
        SetElement {
            name,
            is_wildcard,
            span: input.get_span_from(start),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::{Identifier, IdentifierOperation, IdentifierOperationType};
    use crate::test_helpers::{parse, parse_err, test_public_type};

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
                    expr: ExpressionKind::Integer(1),
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
                    expr: ExpressionKind::Integer(50),
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
                    expr: ExpressionKind::Identifier(Identifier {
                        name: "anya".to_owned(),
                        name_span: 0..4,
                        operations: vec![],
                    }),
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
        parse(
            string_enumeration,
            "$a",
            "",
            vec![SetElement {
                name: "a".to_owned(),
                is_wildcard: false,
                span: 0..2,
            }],
        );
        parse(
            string_enumeration,
            "$a, $b* $c",
            "$c",
            vec![
                SetElement {
                    name: "a".to_owned(),
                    is_wildcard: false,
                    span: 0..2,
                },
                SetElement {
                    name: "b".to_owned(),
                    is_wildcard: true,
                    span: 4..7,
                },
            ],
        );
        parse(
            string_enumeration,
            "$a*,b",
            ",b",
            vec![SetElement {
                name: "a".to_owned(),
                is_wildcard: true,
                span: 0..3,
            }],
        );
        parse(
            string_enumeration,
            "$foo*,$ , $bar)",
            ")",
            vec![
                SetElement {
                    name: "foo".to_owned(),
                    is_wildcard: true,
                    span: 0..5,
                },
                SetElement {
                    name: String::new(),
                    is_wildcard: false,
                    span: 6..7,
                },
                SetElement {
                    name: "bar".to_owned(),
                    is_wildcard: false,
                    span: 10..14,
                },
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
                    SetElement {
                        name: "a".to_owned(),
                        is_wildcard: true,
                        span: 2..5,
                    },
                    SetElement {
                        name: "foo".to_owned(),
                        is_wildcard: true,
                        span: 7..12,
                    },
                    SetElement {
                        name: "c".to_owned(),
                        is_wildcard: false,
                        span: 15..17,
                    },
                ],
            },
        );
        parse(
            string_set,
            "($)",
            "",
            VariableSet {
                elements: vec![SetElement {
                    name: String::new(),
                    is_wildcard: false,
                    span: 1..2,
                }],
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
                            expr: ExpressionKind::Integer(50),
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
                            expr: ExpressionKind::Integer(5),
                            span: 0..1,
                        }),
                        as_percent: false,
                    },
                    set: VariableSet {
                        elements: vec![
                            SetElement {
                                name: "a".to_owned(),
                                is_wildcard: false,
                                span: 6..8,
                            },
                            SetElement {
                                name: "b".to_owned(),
                                is_wildcard: true,
                                span: 10..13,
                            },
                        ],
                    },
                    from: Box::new(Expression {
                        expr: ExpressionKind::Integer(100),
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
        parse(
            boolean_expression,
            "2% of (a, b*)",
            "",
            Expression {
                expr: ExpressionKind::ForRules {
                    selection: ForSelection::Expr {
                        expr: Box::new(Expression {
                            expr: ExpressionKind::Integer(2),
                            span: 0..1,
                        }),
                        as_percent: true,
                    },
                    set: RuleSet {
                        elements: vec![
                            SetElement {
                                name: "a".to_owned(),
                                is_wildcard: false,
                                span: 7..8,
                            },
                            SetElement {
                                name: "b".to_owned(),
                                is_wildcard: true,
                                span: 10..12,
                            },
                        ],
                    },
                },
                span: 0..13,
            },
        );
        parse(
            boolean_expression,
            "5 of ($a, $b*) at f.b",
            "",
            Expression {
                expr: ExpressionKind::ForAt {
                    selection: ForSelection::Expr {
                        expr: Box::new(Expression {
                            expr: ExpressionKind::Integer(5),
                            span: 0..1,
                        }),
                        as_percent: false,
                    },
                    set: VariableSet {
                        elements: vec![
                            SetElement {
                                name: "a".to_owned(),
                                is_wildcard: false,
                                span: 6..8,
                            },
                            SetElement {
                                name: "b".to_owned(),
                                is_wildcard: true,
                                span: 10..13,
                            },
                        ],
                    },
                    offset: Box::new(Expression {
                        expr: ExpressionKind::Identifier(Identifier {
                            name: "f".to_owned(),
                            name_span: 18..19,
                            operations: vec![IdentifierOperation {
                                op: IdentifierOperationType::Subfield("b".to_owned()),
                                span: 19..21,
                            }],
                        }),
                        span: 18..21,
                    }),
                },
                span: 0..21,
            },
        );

        parse_err(boolean_expression, "for true");
        parse_err(boolean_expression, "2% /*");
        parse_err(boolean_expression, "2% of (a* /*");

        parse_err(for_expression_abbrev, "");
        parse_err(for_expression_abbrev, "any");
        parse_err(for_expression_abbrev, "any of");
        parse_err(for_expression_abbrev, "any of thema");
        parse_err(for_expression_abbrev, "all of them in");
        parse_err(for_expression_abbrev, "all of them in ()");
        parse_err(for_expression_abbrev, "all of them at");
        parse_err(for_expression_abbrev, "all of them at ()");
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
                            expr: ExpressionKind::Integer(25),
                            span: 4..6,
                        }),
                        as_percent: true,
                    },
                    set: VariableSet {
                        elements: vec![SetElement {
                            name: "foo".to_owned(),
                            is_wildcard: true,
                            span: 12..17,
                        }],
                    },
                    body: Some(Box::new(Expression {
                        expr: ExpressionKind::Variable(String::new()),
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
        parse_err(for_expression_full, "for any of /*");
        parse_err(for_expression_full, "for all of them");
        parse_err(for_expression_full, "for 5% //");
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
                    identifiers_span: 8..9,
                    iterator: ForIterator::List(vec![
                        Expression {
                            expr: ExpressionKind::Integer(1),
                            span: 14..15,
                        },
                        Expression {
                            expr: ExpressionKind::Integer(3),
                            span: 17..18,
                        },
                    ]),
                    iterator_span: 13..19,
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
            "for any s in (a.b..5 - 1) : ( false )",
            "",
            Expression {
                expr: ExpressionKind::ForIdentifiers {
                    selection: ForSelection::Any,
                    identifiers: vec!["s".to_owned()],
                    identifiers_span: 8..9,
                    iterator: ForIterator::Range {
                        from: Box::new(Expression {
                            expr: ExpressionKind::Identifier(Identifier {
                                name: "a".to_string(),
                                name_span: 14..15,
                                operations: vec![IdentifierOperation {
                                    op: IdentifierOperationType::Subfield("b".to_string()),
                                    span: 15..17,
                                }],
                            }),
                            span: 14..17,
                        }),
                        to: Box::new(Expression {
                            expr: ExpressionKind::Sub(
                                Box::new(Expression {
                                    expr: ExpressionKind::Integer(5),
                                    span: 19..20,
                                }),
                                Box::new(Expression {
                                    expr: ExpressionKind::Integer(1),
                                    span: 23..24,
                                }),
                            ),
                            span: 19..24,
                        }),
                    },
                    iterator_span: 13..25,
                    body: Box::new(Expression {
                        expr: ExpressionKind::Boolean(false),
                        span: 30..35,
                    }),
                },
                span: 0..37,
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
                    identifiers_span: 8..13,
                    iterator: ForIterator::Identifier(Identifier {
                        name: "toto".to_owned(),
                        name_span: 17..21,
                        operations: vec![],
                    }),
                    iterator_span: 17..21,
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
        parse(for_variables, "i a", "a", (vec!["i".to_owned()], 0..1));
        parse(
            for_variables,
            "i, ae ,t b",
            "b",
            (vec!["i".to_owned(), "ae".to_owned(), "t".to_owned()], 0..8),
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
            (
                ForIterator::Identifier(Identifier {
                    name: "i".to_owned(),
                    name_span: 0..1,
                    operations: vec![IdentifierOperation {
                        op: IdentifierOperationType::Subfield("b".to_owned()),
                        span: 1..3,
                    }],
                }),
                0..3,
            ),
        );
        parse(
            iterator,
            "(1)b",
            "b",
            (
                ForIterator::List(vec![Expression {
                    expr: ExpressionKind::Integer(1),
                    span: 1..2,
                }]),
                0..3,
            ),
        );
        parse(
            iterator,
            "(1, 2,#a)b",
            "b",
            (
                ForIterator::List(vec![
                    Expression {
                        expr: ExpressionKind::Integer(1),
                        span: 1..2,
                    },
                    Expression {
                        expr: ExpressionKind::Integer(2),
                        span: 4..5,
                    },
                    Expression {
                        expr: ExpressionKind::Count("a".to_owned()),
                        span: 6..8,
                    },
                ]),
                0..9,
            ),
        );
        parse(
            iterator,
            "(1..#t) b",
            "b",
            (
                ForIterator::Range {
                    from: Box::new(Expression {
                        expr: ExpressionKind::Integer(1),
                        span: 1..2,
                    }),
                    to: Box::new(Expression {
                        expr: ExpressionKind::Count("t".to_owned()),
                        span: 4..6,
                    }),
                },
                0..7,
            ),
        );

        parse_err(iterator, "");
        parse_err(iterator, "(");
        parse_err(iterator, "()");
        parse_err(iterator, ")");
        parse_err(iterator, "(1,2");
        parse_err(iterator, "(1..2");
    }

    #[test]
    fn test_public_types() {
        test_public_type(iterator(Input::new("a.b")).unwrap());
        test_public_type(iterator(Input::new("(1..2)")).unwrap());
        test_public_type(iterator(Input::new("(1, 2)")).unwrap());

        test_public_type(for_selection_full(Input::new("any")).unwrap());
        test_public_type(for_selection_full(Input::new("foo")).unwrap());

        test_public_type(string_set(Input::new("($a*, $c)")).unwrap());
        test_public_type(rule_set(Input::new("(a*, c)")).unwrap());
    }
}
