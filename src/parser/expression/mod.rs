use nom::error::{Error, ErrorKind, FromExternalError};

use crate::expression::Expression;

mod boolean_expression;
mod primary_expression;

// TODO: not quite happy about how operator precedence has been implemented.
// Maybe implementing Shunting-Yard would be better, to bench and test.

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Type {
    Integer,
    Float,
    String,
    Regex,
    Boolean,
}

impl std::fmt::Display for Type {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(match self {
            Self::Integer => "integer",
            Self::Float => "floating-point number",
            Self::String => "string",
            Self::Regex => "regex",
            Self::Boolean => "boolean",
        })
    }
}

#[derive(PartialEq, Debug)]
pub struct ParsedExpr {
    pub expr: Expression,
    ty: Type,
}

fn nom_err_invalid_expression_type<'a>(
    input: &'a str,
    expr: &ParsedExpr,
    expected_type: Type,
) -> nom::Err<Error<&'a str>> {
    nom::Err::Failure(Error::from_external_error(
        input,
        ErrorKind::Verify,
        format!("{} expression expected, found {}", expected_type, expr.ty),
    ))
}

impl ParsedExpr {
    fn try_unwrap(
        self,
        input: &str,
        expected_type: Type,
    ) -> Result<Box<Expression>, nom::Err<Error<&str>>> {
        if self.ty == expected_type {
            Ok(Box::new(self.expr))
        } else {
            Err(nom_err_invalid_expression_type(input, &self, expected_type))
        }
    }
}
