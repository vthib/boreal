use super::{Expression, ForIterator, ForSelection, Identifier, ParsedExpr};
use crate::expression::Expression as EExpr;

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

/// Validates parsed structs, and generates well-formed equivalents.
pub struct Validator {}

impl Validator {
    /// Validate a parsed identifier, and return a
    /// [`crate::expression::Identifier`].
    ///
    /// This applies checks to ensure that the identifier is well
    /// formed.
    fn validate_identifier(
        &self,
        ident: Identifier,
    ) -> Result<crate::expression::Identifier, String> {
        use crate::expression::Identifier as I;

        match ident {
            Identifier::Raw(v) => Ok(I::Raw(v)),
            Identifier::Subscript {
                identifier,
                subscript,
            } => {
                let identifier = self.validate_identifier(*identifier)?;
                let subscript = self.validate_expr(*subscript)?;

                Ok(I::Subscript {
                    identifier: Box::new(identifier),
                    subscript: Box::new(subscript.expression),
                })
            }
            Identifier::Subfield {
                identifier,
                subfield,
            } => {
                let identifier = self.validate_identifier(*identifier)?;

                Ok(I::Subfield {
                    identifier: Box::new(identifier),
                    subfield,
                })
            }
            Identifier::FunctionCall {
                identifier,
                arguments,
            } => {
                let identifier = self.validate_identifier(*identifier)?;
                let args: Result<Vec<_>, _> = arguments
                    .into_iter()
                    .map(|v| self.validate_expr(v).map(|v| v.expression))
                    .collect();

                Ok(I::FunctionCall {
                    identifier: Box::new(identifier),
                    arguments: args?,
                })
            }
        }
    }

    /// Validate a boolean parsed expression.
    ///
    /// Ensure the expression is well-formed, and returns a boolean.
    pub fn validate_boolean_expression(
        &self,
        expr: ParsedExpr,
    ) -> Result<crate::expression::Expression, String> {
        let validated_expr = self.validate_expr(expr)?;
        validated_expr.check_type(Type::Boolean)?;
        Ok(validated_expr.expression)
    }

    /// Validate a parsed expression, and return a
    /// [`crate::expression::Expression`] with related metadata.
    ///
    /// This applies checks to ensure that the parsed expression is well
    /// formed.
    #[allow(clippy::too_many_lines)]
    fn validate_expr(&self, expr: ParsedExpr) -> Result<ValidatedExpression, String> {
        match expr.expr {
            Expression::Filesize => Ok(ValidatedExpression {
                expression: EExpr::Filesize,
                ty: Type::Integer,
            }),
            Expression::Entrypoint => Ok(ValidatedExpression {
                expression: EExpr::Entrypoint,
                ty: Type::Integer,
            }),
            Expression::ReadInteger {
                size,
                unsigned,
                big_endian,
                addr,
            } => {
                let addr = self.validate_expr(*addr)?;

                Ok(ValidatedExpression {
                    expression: EExpr::ReadInteger {
                        size,
                        unsigned,
                        big_endian,
                        addr: addr.unwrap_expr(Type::Integer)?,
                    },
                    ty: Type::Integer,
                })
            }
            Expression::Number(v) => Ok(ValidatedExpression {
                expression: EExpr::Number(v),
                ty: Type::Integer,
            }),
            Expression::Double(v) => Ok(ValidatedExpression {
                expression: EExpr::Double(v),
                ty: Type::Float,
            }),
            Expression::CountInRange {
                identifier,
                from,
                to,
            } => {
                let from = self.validate_expr(*from)?;
                let to = self.validate_expr(*to)?;

                Ok(ValidatedExpression {
                    expression: EExpr::CountInRange {
                        identifier,
                        from: from.unwrap_expr(Type::Integer)?,
                        to: to.unwrap_expr(Type::Integer)?,
                    },
                    ty: Type::Integer,
                })
            }
            Expression::Count(v) => Ok(ValidatedExpression {
                expression: EExpr::Count(v),
                ty: Type::Integer,
            }),
            Expression::Offset {
                identifier,
                occurence_number,
            } => {
                let on = self.validate_expr(*occurence_number)?;

                Ok(ValidatedExpression {
                    expression: EExpr::Offset {
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
                let on = self.validate_expr(*occurence_number)?;

                Ok(ValidatedExpression {
                    expression: EExpr::Length {
                        identifier,
                        occurence_number: on.unwrap_expr(Type::Integer)?,
                    },
                    ty: Type::Integer,
                })
            }
            Expression::Neg(v) => {
                let v = self.validate_expr(*v)?;

                if v.ty == Type::Float {
                    Ok(ValidatedExpression {
                        expression: EExpr::Neg(Box::new(v.expression)),
                        ty: Type::Float,
                    })
                } else {
                    Ok(ValidatedExpression {
                        expression: EExpr::Neg(v.unwrap_expr(Type::Integer)?),
                        ty: Type::Integer,
                    })
                }
            }
            Expression::Add(a, b) => self.validate_primary_op(*a, *b, "+", EExpr::Add, false),
            Expression::Sub(a, b) => self.validate_primary_op(*a, *b, "-", EExpr::Sub, false),
            Expression::Mul(a, b) => self.validate_primary_op(*a, *b, "*", EExpr::Mul, false),
            Expression::Div(a, b) => self.validate_primary_op(*a, *b, "\\", EExpr::Div, false),
            Expression::Mod(a, b) => {
                self.validate_binary_op(*a, *b, Type::Integer, Type::Integer, EExpr::Mod)
            }
            Expression::BitwiseXor(a, b) => {
                self.validate_binary_op(*a, *b, Type::Integer, Type::Integer, EExpr::BitwiseXor)
            }
            Expression::BitwiseAnd(a, b) => {
                self.validate_binary_op(*a, *b, Type::Integer, Type::Integer, EExpr::BitwiseAnd)
            }
            Expression::BitwiseOr(a, b) => {
                self.validate_binary_op(*a, *b, Type::Integer, Type::Integer, EExpr::BitwiseOr)
            }
            Expression::BitwiseNot(a) => {
                let a = self.validate_expr(*a)?;
                Ok(ValidatedExpression {
                    expression: EExpr::BitwiseNot(a.unwrap_expr(Type::Integer)?),
                    ty: Type::Integer,
                })
            }
            Expression::ShiftLeft(a, b) => {
                self.validate_binary_op(*a, *b, Type::Integer, Type::Integer, EExpr::ShiftLeft)
            }
            Expression::ShiftRight(a, b) => {
                self.validate_binary_op(*a, *b, Type::Integer, Type::Integer, EExpr::ShiftRight)
            }
            Expression::And(a, b) => {
                self.validate_binary_op(*a, *b, Type::Boolean, Type::Boolean, EExpr::And)
            }
            Expression::Or(a, b) => {
                self.validate_binary_op(*a, *b, Type::Boolean, Type::Boolean, EExpr::Or)
            }
            Expression::Cmp {
                left,
                right,
                less_than,
                can_be_equal,
            } => {
                let left = self.validate_expr(*left)?;
                let right = self.validate_expr(*right)?;
                Validator::validate_comparison(&left, &right)?;

                Ok(ValidatedExpression {
                    expression: EExpr::Cmp {
                        left: Box::new(left.expression),
                        right: Box::new(right.expression),
                        less_than,
                        can_be_equal,
                    },
                    ty: Type::Boolean,
                })
            }
            Expression::Eq(a, b) => {
                let a = self.validate_expr(*a)?;
                let b = self.validate_expr(*b)?;
                Validator::validate_comparison(&a, &b)?;

                Ok(ValidatedExpression {
                    expression: EExpr::Eq(Box::new(a.expression), Box::new(b.expression)),
                    ty: Type::Boolean,
                })
            }
            Expression::Contains {
                haystack,
                needle,
                case_insensitive,
            } => {
                let haystack = self.validate_expr(*haystack)?;
                let needle = self.validate_expr(*needle)?;
                Ok(ValidatedExpression {
                    expression: EExpr::Contains {
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
                let expr = self.validate_expr(*expr)?;
                let prefix = self.validate_expr(*prefix)?;
                Ok(ValidatedExpression {
                    expression: EExpr::StartsWith {
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
                let expr = self.validate_expr(*expr)?;
                let suffix = self.validate_expr(*suffix)?;
                Ok(ValidatedExpression {
                    expression: EExpr::EndsWith {
                        expr: expr.unwrap_expr(Type::String)?,
                        suffix: suffix.unwrap_expr(Type::String)?,
                        case_insensitive,
                    },
                    ty: Type::Boolean,
                })
            }
            Expression::IEquals(a, b) => {
                self.validate_binary_op(*a, *b, Type::String, Type::Boolean, EExpr::IEquals)
            }
            Expression::Matches(a, regexp) => {
                let a = self.validate_expr(*a)?;
                Ok(ValidatedExpression {
                    expression: EExpr::Matches(a.unwrap_expr(Type::String)?, regexp),
                    ty: Type::Boolean,
                })
            }
            Expression::Defined(a) => {
                let a = self.validate_expr(*a)?;
                Ok(ValidatedExpression {
                    expression: EExpr::Defined(Box::new(a.expression)),
                    ty: Type::Boolean,
                })
            }
            Expression::Not(a) => {
                let a = self.validate_expr(*a)?;
                Ok(ValidatedExpression {
                    expression: EExpr::Not(a.unwrap_expr(Type::Boolean)?),
                    ty: Type::Boolean,
                })
            }
            Expression::Boolean(a) => Ok(ValidatedExpression {
                expression: EExpr::Boolean(a),
                ty: Type::Boolean,
            }),
            Expression::Variable(a) => Ok(ValidatedExpression {
                expression: EExpr::Variable(a),
                ty: Type::Boolean,
            }),
            Expression::VariableAt(a, expr) => {
                let expr = self.validate_expr(*expr)?;

                Ok(ValidatedExpression {
                    expression: EExpr::VariableAt(a, expr.unwrap_expr(Type::Integer)?),
                    ty: Type::Boolean,
                })
            }
            Expression::VariableIn { variable, from, to } => {
                let from = self.validate_expr(*from)?;
                let to = self.validate_expr(*to)?;

                Ok(ValidatedExpression {
                    expression: EExpr::VariableIn {
                        variable,
                        from: from.unwrap_expr(Type::Integer)?,
                        to: to.unwrap_expr(Type::Integer)?,
                    },
                    ty: Type::Boolean,
                })
            }
            Expression::Identifier(ident) => {
                let identifier = self.validate_identifier(ident)?;
                Ok(ValidatedExpression {
                    expression: EExpr::Identifier(identifier),
                    // TODO: typing identifiers
                    ty: Type::Boolean,
                })
            }
            Expression::String(v) => Ok(ValidatedExpression {
                expression: EExpr::String(v),
                ty: Type::String,
            }),
            Expression::Regex(v) => Ok(ValidatedExpression {
                expression: EExpr::Regex(v),
                ty: Type::Regex,
            }),

            Expression::For {
                selection,
                set,
                body,
            } => {
                let condition = match body {
                    None => None,
                    Some(body) => {
                        let body = self.validate_expr(*body)?;

                        Some(body.unwrap_expr(Type::Boolean)?)
                    }
                };
                let selection = self.validate_for_selection(selection)?;
                // TODO: validate set with list of variables
                let set = set.elements.into_iter().map(|a| a.0).collect();

                Ok(ValidatedExpression {
                    expression: EExpr::For {
                        selection,
                        set,
                        condition,
                    },
                    ty: Type::Boolean,
                })
            }

            Expression::ForIn {
                selection,
                set,
                from,
                to,
            } => {
                let from = self.validate_expr(*from)?;
                let to = self.validate_expr(*to)?;

                // convert the ForIn expression to a simple for, with
                // a condition '$ in range'.
                let condition = EExpr::VariableIn {
                    variable: String::new(),
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                };
                let selection = self.validate_for_selection(selection)?;
                // TODO: validate set with list of variables
                let set = set.elements.into_iter().map(|a| a.0).collect();

                Ok(ValidatedExpression {
                    expression: EExpr::For {
                        selection,
                        set,
                        condition: Some(Box::new(condition)),
                    },
                    ty: Type::Boolean,
                })
            }

            Expression::ForIdentifiers {
                selection,
                identifiers,
                iterator,
                body,
            } => {
                let body = self.validate_expr(*body)?;
                let selection = self.validate_for_selection(selection)?;
                let iterator = self.validate_for_iterator(iterator)?;

                Ok(ValidatedExpression {
                    expression: EExpr::ForIdentifiers {
                        selection,
                        identifiers,
                        iterator,
                        condition: body.unwrap_expr(Type::Boolean)?,
                    },
                    ty: Type::Boolean,
                })
            }
        }
    }

    fn validate_primary_op<F>(
        &self,
        a: ParsedExpr,
        b: ParsedExpr,
        operator: &str,
        constructor: F,
        string_allowed: bool,
    ) -> Result<ValidatedExpression, String>
    where
        F: Fn(Box<EExpr>, Box<EExpr>) -> EExpr,
    {
        let a = self.validate_expr(a)?;
        let b = self.validate_expr(b)?;

        let ty = match (a.ty, b.ty) {
            (Type::Integer, Type::Integer) => Type::Integer,
            (Type::Float | Type::Integer, Type::Integer | Type::Float) => Type::Float,
            (Type::String, Type::String) if string_allowed => Type::String,
            _ => {
                return Err(format!(
                    "invalid type of expressions used with operator {}",
                    operator
                ))
            }
        };

        Ok(ValidatedExpression {
            expression: constructor(Box::new(a.expression), Box::new(b.expression)),
            ty,
        })
    }

    fn validate_binary_op<F>(
        &self,
        a: ParsedExpr,
        b: ParsedExpr,
        type_wanted: Type,
        type_result: Type,
        constructor: F,
    ) -> Result<ValidatedExpression, String>
    where
        F: Fn(Box<EExpr>, Box<EExpr>) -> EExpr,
    {
        let a = self.validate_expr(a)?;
        let b = self.validate_expr(b)?;

        Ok(ValidatedExpression {
            expression: constructor(a.unwrap_expr(type_wanted)?, b.unwrap_expr(type_wanted)?),
            ty: type_result,
        })
    }

    fn validate_comparison(a: &ValidatedExpression, b: &ValidatedExpression) -> Result<(), String> {
        match (a.ty, b.ty) {
            (Type::String, Type::String)
            | (Type::Integer | Type::Float, Type::Integer | Type::Float) => Ok(()),
            _ => Err(format!(
                "incompatible types for comparison: {} and {}",
                a.ty, b.ty
            )),
        }
    }

    fn validate_for_selection(
        &self,
        selection: ForSelection,
    ) -> Result<crate::expression::ForSelection, String> {
        use crate::expression::ForSelection as FS;

        Ok(match selection {
            ForSelection::Any => FS::Any,
            ForSelection::All => FS::All,
            ForSelection::None => FS::None,
            ForSelection::Expr { expr, as_percent } => {
                let expr = self.validate_expr(*expr)?;
                let expr = expr.unwrap_expr(Type::Integer)?;

                FS::Expr { expr, as_percent }
            }
        })
    }

    fn validate_for_iterator(
        &self,
        iterator: ForIterator,
    ) -> Result<crate::expression::ForIterator, String> {
        use crate::expression::ForIterator as FI;

        Ok(match iterator {
            ForIterator::Identifier(ident) => {
                let ident = self.validate_identifier(ident)?;
                FI::Identifier(ident)
            }
            ForIterator::Range { from, to } => {
                let from = self.validate_expr(*from)?;
                let to = self.validate_expr(*to)?;

                FI::Range {
                    from: from.unwrap_expr(Type::Integer)?,
                    to: to.unwrap_expr(Type::Integer)?,
                }
            }
            ForIterator::List(values) => {
                let values: Result<Vec<_>, _> = values
                    .into_iter()
                    .map(|v| self.validate_expr(v).map(|v| v.expression))
                    .collect();

                FI::List(values?)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expression::expression;

    #[track_caller]
    fn test_validation(expression_str: &str, expected_type: Type) {
        let validator = Validator {};
        let (_, expr) = expression(expression_str).unwrap();
        assert_eq!(validator.validate_expr(expr).unwrap().ty, expected_type);
    }

    #[track_caller]
    fn test_validation_err(expression_str: &str) {
        let validator = Validator {};
        let (_, expr) = expression(expression_str).unwrap();
        assert!(validator.validate_expr(expr).is_err());
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

    #[test]
    fn test_validation_cmp() {
        test_validation("1 < 2", Type::Boolean);
        test_validation("1 <= 2.2", Type::Boolean);
        test_validation("1.1 > 2", Type::Boolean);
        test_validation("1.1 >= 2.2", Type::Boolean);

        test_validation("\"a\" > \"b\"", Type::Boolean);
        test_validation("\"a\" == \"b\"", Type::Boolean);
        test_validation("\"a\" != \"b\"", Type::Boolean);

        test_validation_err("\"a\" < 1");
        test_validation_err("2 == a");
        test_validation_err("/a/ != 1");
    }

    #[test]
    fn test_validation_for_expression() {
        test_validation("any of them", Type::Boolean);
        test_validation("all of ($a, $b*)", Type::Boolean);
        test_validation("all of them in (1..3)", Type::Boolean);
        test_validation("for any of them: (true)", Type::Boolean);
        test_validation("for all i of (1, 2): (true)", Type::Boolean);

        test_validation_err("for any of them: (1)");
        test_validation_err("/a/ of them");
        test_validation_err("1.2% of them");
        test_validation_err("1.2% of them");
        test_validation_err("any of them in (1../a/)");
        test_validation_err("any of them in (/a/..2)");
        test_validation_err("for any i of (1../a/): (true)");
        test_validation_err("for any i of (/a/..1): (true)");
    }

    // TODO: add tests to check the "ty" field in ValidatedExpression
}
