use super::{Expression, Identifier, ParsedExpr};

/// Type of a parsed expression
///
/// This is useful to know the type of a parsed expression, and reject
/// during parsing expressions which are incompatible.
#[derive(Copy, Clone, PartialEq, Debug)]
enum Type {
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

/// A validated expression, ensured to be well-formed.
struct ValidatedExpression {
    /// Well-formed expression.
    expression: crate::expression::Expression,
    /// Type of the expression.
    ty: Type,
}

impl ValidatedExpression {
    fn check_type(&self, expected_type: Type) -> Result<(), String> {
        if self.ty != expected_type {
            return Err(format!(
                "{} expression expected, found {}",
                expected_type, self.ty
            ));
        }
        Ok(())
    }

    fn unwrap_expr(
        self,
        expected_type: Type,
    ) -> Result<Box<crate::expression::Expression>, String> {
        match self.check_type(expected_type) {
            Err(e) => Err(e),
            Ok(()) => Ok(Box::new(self.expression)),
        }
    }
}

/// Validate a parsed identifier, and return a
/// [`crate::expression::Identifier`].
///
/// This applies checks to ensure that the identifier is well
/// formed.
fn validate_identifier(ident: Identifier) -> Result<crate::expression::Identifier, String> {
    use crate::expression::Identifier as I;

    match ident {
        Identifier::Raw(v) => Ok(I::Raw(v)),
        Identifier::Subscript {
            identifier,
            subscript,
        } => {
            let identifier = validate_identifier(*identifier)?;
            let subscript = validate_expr(*subscript)?;

            Ok(I::Subscript {
                identifier: Box::new(identifier),
                subscript: Box::new(subscript.expression),
            })
        }
        Identifier::Subfield {
            identifier,
            subfield,
        } => {
            let identifier = validate_identifier(*identifier)?;

            Ok(I::Subfield {
                identifier: Box::new(identifier),
                subfield,
            })
        }
        Identifier::FunctionCall {
            identifier,
            arguments,
        } => {
            let identifier = validate_identifier(*identifier)?;
            let mut args = Vec::new();
            for arg in arguments {
                let arg = validate_expr(arg)?;
                args.push(arg.expression);
            }

            Ok(I::FunctionCall {
                identifier: Box::new(identifier),
                arguments: args,
            })
        }
    }
}

/// Validate a boolean parsed expression.
///
/// Ensure the expression is well-formed, and returns a boolean.
pub fn validate_boolean_expression(
    expr: ParsedExpr,
) -> Result<crate::expression::Expression, String> {
    let validated_expr = validate_expr(expr)?;
    validated_expr.check_type(Type::Boolean)?;
    Ok(validated_expr.expression)
}

/// Validate a parsed expression, and return a
/// [`crate::expression::Expression`] with related metadata.
///
/// This applies checks to ensure that the parsed expression is well
/// formed.
#[allow(clippy::too_many_lines)]
fn validate_expr(expr: ParsedExpr) -> Result<ValidatedExpression, String> {
    use crate::expression::Expression as E;

    match expr.expr {
        Expression::Filesize => Ok(ValidatedExpression {
            expression: E::Filesize,
            ty: Type::Integer,
        }),
        Expression::Entrypoint => Ok(ValidatedExpression {
            expression: E::Entrypoint,
            ty: Type::Integer,
        }),
        Expression::ReadInteger {
            size,
            unsigned,
            big_endian,
            addr,
        } => {
            let addr = validate_expr(*addr)?;

            Ok(ValidatedExpression {
                expression: E::ReadInteger {
                    size,
                    unsigned,
                    big_endian,
                    addr: addr.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
            })
        }
        Expression::Number(v) => Ok(ValidatedExpression {
            expression: E::Number(v),
            ty: Type::Integer,
        }),
        Expression::Double(v) => Ok(ValidatedExpression {
            expression: E::Double(v),
            ty: Type::Float,
        }),
        Expression::CountInRange {
            identifier,
            from,
            to,
        } => {
            let from = validate_expr(*from)?;
            let to = validate_expr(*to)?;

            Ok(ValidatedExpression {
                expression: E::CountInRange {
                    identifier,
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
            })
        }
        Expression::Count(v) => Ok(ValidatedExpression {
            expression: E::Count(v),
            ty: Type::Integer,
        }),
        Expression::Offset {
            identifier,
            occurence_number,
        } => {
            let on = validate_expr(*occurence_number)?;

            Ok(ValidatedExpression {
                expression: E::Offset {
                    identifier,
                    occurence_number: on.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
            })
        }
        Expression::Length {
            identifier,
            occurence_number,
        } => {
            let on = validate_expr(*occurence_number)?;

            Ok(ValidatedExpression {
                expression: E::Length {
                    identifier,
                    occurence_number: on.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Integer,
            })
        }
        Expression::Neg(v) => {
            let v = validate_expr(*v)?;

            if v.ty == Type::Float {
                Ok(ValidatedExpression {
                    expression: E::Neg(Box::new(v.expression)),
                    ty: Type::Float,
                })
            } else {
                Ok(ValidatedExpression {
                    expression: E::Neg(v.unwrap_expr(Type::Integer)?),
                    ty: Type::Integer,
                })
            }
        }
        Expression::Add(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            let (a, b, ty) = check_numeric_op(a, b)?;

            Ok(ValidatedExpression {
                expression: E::Add(a, b),
                ty,
            })
        }
        Expression::Sub(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            let (a, b, ty) = check_numeric_op(a, b)?;

            Ok(ValidatedExpression {
                expression: E::Sub(a, b),
                ty,
            })
        }
        Expression::Mul(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            let (a, b, ty) = check_numeric_op(a, b)?;

            Ok(ValidatedExpression {
                expression: E::Mul(a, b),
                ty,
            })
        }
        Expression::Div(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            let (a, b, ty) = check_numeric_op(a, b)?;

            Ok(ValidatedExpression {
                expression: E::Div(a, b),
                ty,
            })
        }
        Expression::Mod(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::Mod(a.unwrap_expr(Type::Integer)?, b.unwrap_expr(Type::Integer)?),
                ty: Type::Integer,
            })
        }
        Expression::BitwiseXor(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::BitwiseXor(
                    a.unwrap_expr(Type::Integer)?,
                    b.unwrap_expr(Type::Integer)?,
                ),
                ty: Type::Integer,
            })
        }
        Expression::BitwiseAnd(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::BitwiseAnd(
                    a.unwrap_expr(Type::Integer)?,
                    b.unwrap_expr(Type::Integer)?,
                ),
                ty: Type::Integer,
            })
        }
        Expression::BitwiseOr(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::BitwiseOr(
                    a.unwrap_expr(Type::Integer)?,
                    b.unwrap_expr(Type::Integer)?,
                ),
                ty: Type::Integer,
            })
        }
        Expression::BitwiseNot(a) => {
            let a = validate_expr(*a)?;
            Ok(ValidatedExpression {
                expression: E::BitwiseNot(a.unwrap_expr(Type::Integer)?),
                ty: Type::Integer,
            })
        }
        Expression::ShiftLeft(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::ShiftLeft(
                    a.unwrap_expr(Type::Integer)?,
                    b.unwrap_expr(Type::Integer)?,
                ),
                ty: Type::Integer,
            })
        }
        Expression::ShiftRight(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::ShiftRight(
                    a.unwrap_expr(Type::Integer)?,
                    b.unwrap_expr(Type::Integer)?,
                ),
                ty: Type::Integer,
            })
        }
        Expression::And(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::And(a.unwrap_expr(Type::Boolean)?, b.unwrap_expr(Type::Boolean)?),
                ty: Type::Integer,
            })
        }
        Expression::Or(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::Or(a.unwrap_expr(Type::Boolean)?, b.unwrap_expr(Type::Boolean)?),
                ty: Type::Integer,
            })
        }
        Expression::Cmp {
            left,
            right,
            less_than,
            can_be_equal,
        } => {
            let left = validate_expr(*left)?;
            let right = validate_expr(*right)?;
            Ok(ValidatedExpression {
                expression: E::Cmp {
                    left: Box::new(left.expression),
                    right: Box::new(right.expression),
                    less_than,
                    can_be_equal,
                },
                ty: Type::Integer,
            })
        }
        Expression::Eq(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::Eq(Box::new(a.expression), Box::new(b.expression)),
                ty: Type::Integer,
            })
        }
        Expression::Contains {
            haystack,
            needle,
            case_insensitive,
        } => {
            let haystack = validate_expr(*haystack)?;
            let needle = validate_expr(*needle)?;
            Ok(ValidatedExpression {
                expression: E::Contains {
                    haystack: haystack.unwrap_expr(Type::String)?,
                    needle: needle.unwrap_expr(Type::String)?,
                    case_insensitive,
                },
                ty: Type::Boolean,
            })
        }
        Expression::StartsWith {
            expr,
            prefix,
            case_insensitive,
        } => {
            let expr = validate_expr(*expr)?;
            let prefix = validate_expr(*prefix)?;
            Ok(ValidatedExpression {
                expression: E::StartsWith {
                    expr: expr.unwrap_expr(Type::String)?,
                    prefix: prefix.unwrap_expr(Type::String)?,
                    case_insensitive,
                },
                ty: Type::Boolean,
            })
        }
        Expression::EndsWith {
            expr,
            suffix,
            case_insensitive,
        } => {
            let expr = validate_expr(*expr)?;
            let suffix = validate_expr(*suffix)?;
            Ok(ValidatedExpression {
                expression: E::EndsWith {
                    expr: expr.unwrap_expr(Type::String)?,
                    suffix: suffix.unwrap_expr(Type::String)?,
                    case_insensitive,
                },
                ty: Type::Boolean,
            })
        }
        Expression::IEquals(a, b) => {
            let a = validate_expr(*a)?;
            let b = validate_expr(*b)?;
            Ok(ValidatedExpression {
                expression: E::IEquals(a.unwrap_expr(Type::String)?, b.unwrap_expr(Type::String)?),
                ty: Type::Boolean,
            })
        }
        Expression::Matches(a, regexp) => {
            let a = validate_expr(*a)?;
            Ok(ValidatedExpression {
                expression: E::Matches(a.unwrap_expr(Type::String)?, regexp),
                ty: Type::Boolean,
            })
        }
        Expression::Defined(a) => {
            let a = validate_expr(*a)?;
            Ok(ValidatedExpression {
                expression: E::Defined(Box::new(a.expression)),
                ty: Type::Boolean,
            })
        }
        Expression::Not(a) => {
            let a = validate_expr(*a)?;
            Ok(ValidatedExpression {
                expression: E::Not(a.unwrap_expr(Type::Boolean)?),
                ty: Type::Boolean,
            })
        }
        Expression::Boolean(a) => Ok(ValidatedExpression {
            expression: E::Boolean(a),
            ty: Type::Boolean,
        }),
        Expression::Variable(a) => Ok(ValidatedExpression {
            expression: E::Variable(a),
            ty: Type::Boolean,
        }),
        Expression::VariableAt(a, expr) => {
            let expr = validate_expr(*expr)?;

            Ok(ValidatedExpression {
                expression: E::VariableAt(a, expr.unwrap_expr(Type::Integer)?),
                ty: Type::Boolean,
            })
        }
        Expression::VariableIn { variable, from, to } => {
            let from = validate_expr(*from)?;
            let to = validate_expr(*to)?;

            Ok(ValidatedExpression {
                expression: E::VariableIn {
                    variable,
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                },
                ty: Type::Boolean,
            })
        }
        Expression::Identifier(ident) => {
            let identifier = validate_identifier(ident)?;
            Ok(ValidatedExpression {
                expression: E::Identifier(identifier),
                // TODO: typing identifiers
                ty: Type::Boolean,
            })
        }
        Expression::String(v) => Ok(ValidatedExpression {
            expression: E::String(v),
            ty: Type::String,
        }),
        Expression::Regex(v) => Ok(ValidatedExpression {
            expression: E::Regex(v),
            ty: Type::Regex,
        }),
    }
}

fn check_numeric_op(
    a: ValidatedExpression,
    b: ValidatedExpression,
) -> Result<
    (
        Box<crate::expression::Expression>,
        Box<crate::expression::Expression>,
        Type,
    ),
    String,
> {
    match (a.ty, b.ty) {
        (Type::Integer, Type::Integer) => Ok((
            Box::new(a.expression),
            Box::new(b.expression),
            Type::Integer,
        )),
        (Type::Float | Type::Integer, Type::Integer | Type::Float) => {
            Ok((Box::new(a.expression), Box::new(b.expression), Type::Float))
        }
        _ => Err(format!(
            "integer or float expression expected, found {}",
            a.ty
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::expression::expression;

    #[track_caller]
    fn test_validation_err(expression_str: &str) {
        let (_, expr) = expression(expression_str).unwrap();
        assert!(super::validate_expr(expr).is_err());
    }

    #[test]
    fn test_primary_expression_types() {
        test_validation_err("uint8(/a/)");

        test_validation_err("1 | /a/");
        test_validation_err("/a/ | 1");
        test_validation_err("1 ^ /a/");
        test_validation_err("/a/ ^ 1");
        test_validation_err("1 & /a/");
        test_validation_err("/a/ & 1");
        test_validation_err("1.2 << 1");
        test_validation_err("1 << 1.2");
        test_validation_err("1.2 >> 1");
        test_validation_err("1 >> 1.2");

        test_validation_err("1 + /a/");
        test_validation_err("\"a\" + 1");
        test_validation_err("1 - /a/");
        test_validation_err("\"a\" - 1");

        test_validation_err("1 * /a/");
        test_validation_err("\"a\" * 1");

        test_validation_err("1 \\ /a/");
        test_validation_err("\"a\" \\ 1");

        test_validation_err("1 % 1.2");
        test_validation_err("1.2 % 1");

        test_validation_err("~1.2");
        test_validation_err("-/a/");
    }

    #[test]
    fn test_expression_types() {
        test_validation_err("1 contains \"a\"");
        test_validation_err("\"a\" contains 1");

        test_validation_err("1 icontains \"a\"");
        test_validation_err("\"a\" icontains 1");

        test_validation_err("1 startswith \"a\"");
        test_validation_err("\"a\" startswith 1");

        test_validation_err("1 istartswith \"a\"");
        test_validation_err("\"a\" istartswith 1");

        test_validation_err("1 endswith \"a\"");
        test_validation_err("\"a\" endswith 1");

        test_validation_err("1 iendswith \"a\"");
        test_validation_err("\"a\" iendswith 1");

        test_validation_err("1 iequals \"a\"");
        test_validation_err("\"a\" iequals 1");

        test_validation_err("1 matches /a/");

        test_validation_err("true and 1");
        test_validation_err("1 and true");

        test_validation_err("true or 1");
        test_validation_err("1 or true");

        test_validation_err("not 1");

        test_validation_err("$a at 1.2");

        test_validation_err("$a in (1..\"a\")");
        test_validation_err("$a in (/a/ .. 1)");

        test_validation_err("!foo [ 1.2 ]");
        test_validation_err("!foo[/a/]");
        test_validation_err("#foo in (0../a/)");
        test_validation_err("#foo in (1.2 .. 3)");
    }
}
