//! Provides methods to evaluate expressions.

use crate::{expression::Expression, regex::Regex, rule::VariableDeclaration};

#[derive(Debug)]
enum Value<'a> {
    Number(i64),
    Float(f64),
    String(&'a str),
    Regex(&'a Regex),
    Boolean(bool),
}

impl Value<'_> {
    fn to_bool(&self) -> bool {
        match self {
            Self::Boolean(b) => *b,
            Self::String(s) => !s.is_empty(),
            Self::Float(a) => *a != 0.0,
            Self::Number(n) => *n != 0,
            Self::Regex(_) => true,
        }
    }

    fn unwrap_number(&self) -> Result<i64, String> {
        match self {
            Self::Number(v) => Ok(*v),
            _ => Err(format!(
                "expression should be a number, {:?} returned",
                &self
            )),
        }
    }

    fn unwrap_string(&self) -> Result<&str, String> {
        match self {
            Self::String(v) => Ok(*v),
            _ => Err(format!(
                "expression should be a string, {:?} returned",
                &self
            )),
        }
    }
}

/// Evaluates an expression on a given byte slice.
///
/// Returns true if the expression (with the associated variables) matches on the given
/// byte slice, false otherwise.
///
/// # Errors
///
/// An error is returned if the expression is malformed, and some sub-expressions do not
/// return the right type of value.
pub fn evaluate(
    expr: &Expression,
    variables: &[VariableDeclaration],
    mem: &[u8],
) -> Result<bool, String> {
    let evaluator = Evaluator {
        _variables: variables,
        _mem: mem,
    };
    evaluator.evaluate_expr(expr).map(|v| v.to_bool())
}

struct Evaluator<'a> {
    _variables: &'a [VariableDeclaration],
    _mem: &'a [u8],
}

macro_rules! arith_op {
    ($self:expr, $left:expr, $right:expr, $op:tt) => {
        Ok(Value::Number(
            $self.evaluate_expr($left)?.unwrap_number()?
            $op $self.evaluate_expr($right)?.unwrap_number()?
        ))
    }
}

macro_rules! string_op {
    ($self:expr, $left:expr, $right:expr, $case_insensitive:expr, $method:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let left = left.unwrap_string()?;
        let right = $self.evaluate_expr($right)?;
        let right = right.unwrap_string()?;

        if $case_insensitive {
            let left = left.to_lowercase();
            let right = right.to_lowercase();
            Ok(Value::Boolean(left.$method(&right)))
        } else {
            Ok(Value::Boolean(left.$method(right)))
        }
    }};
}

macro_rules! arith_op_num_and_float {
    ($self:expr, $left:expr, $right:expr, $op:tt) => {{
        let left = $self.evaluate_expr($left)?;
        let right = $self.evaluate_expr($right)?;
        match (left, right) {
            (Value::Number(n), Value::Number(m)) => {
                // FIXME: handle overflow
                Ok(Value::Number(n $op m))
            }
            (Value::Float(a), Value::Number(n)) | (Value::Number(n), Value::Float(a)) => {
                Ok(Value::Float(a $op (n as f64)))
            }
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a $op b)),
            _ => todo!(),
        }
    }}
}

macro_rules! apply_cmp_op {
    ($left:expr, $right:expr, $op:tt) => {
        match ($left, $right) {
            (Value::Number(n), Value::Number(m)) => n $op m,
            (Value::Float(a), Value::Float(b)) => a $op b,
            (Value::Number(n), Value::Float(b)) => (n as f64) $op b,
            (Value::Float(a), Value::Number(m)) => a $op (m as f64),
            (Value::String(a), Value::String(b)) => a $op b,
            _ => todo!(),
        }
    }
}

impl Evaluator<'_> {
    #[allow(clippy::too_many_lines)]
    fn evaluate_expr<'b>(&self, expr: &'b Expression) -> Result<Value<'b>, String> {
        match expr {
            Expression::Filesize => todo!(),
            Expression::Entrypoint => todo!(),
            Expression::ReadInteger { .. } => todo!(),
            Expression::CountInRange { .. } => todo!(),
            Expression::Count(..) => todo!(),
            Expression::Offset { .. } => todo!(),
            Expression::Length { .. } => todo!(),
            Expression::Neg(expr) => {
                let v = self.evaluate_expr(expr)?;

                match v {
                    Value::Number(n) => Ok(Value::Number(-n)),
                    Value::Float(a) => Ok(Value::Float(-a)),
                    _ => todo!(),
                }
            }
            Expression::Add(left, right) => {
                arith_op_num_and_float!(self, left, right, +)
            }
            Expression::Sub(left, right) => {
                arith_op_num_and_float!(self, left, right, -)
            }
            Expression::Mul(left, right) => {
                arith_op_num_and_float!(self, left, right, %)
            }
            Expression::Div(left, right) => {
                // FIXME: handle div by zero
                arith_op_num_and_float!(self, left, right, /)
            }
            Expression::Mod(left, right) => {
                arith_op!(self, left, right, %)
            }

            Expression::BitwiseXor(left, right) => {
                arith_op!(self, left, right, ^)
            }
            Expression::BitwiseAnd(left, right) => {
                arith_op!(self, left, right, &)
            }
            Expression::BitwiseOr(left, right) => {
                arith_op!(self, left, right, |)
            }
            Expression::BitwiseNot(expr) => {
                let v = self.evaluate_expr(expr)?.unwrap_number()?;
                Ok(Value::Number(!v))
            }
            Expression::ShiftLeft(left, right) => {
                arith_op!(self, left, right, <<)
            }
            Expression::ShiftRight(left, right) => {
                arith_op!(self, left, right, >>)
            }

            Expression::And(left, right) => {
                let left = self.evaluate_expr(left)?.to_bool();
                let right = self.evaluate_expr(right)?.to_bool();
                Ok(Value::Boolean(left && right))
            }
            Expression::Or(left, right) => {
                let left = self.evaluate_expr(left)?.to_bool();
                let right = self.evaluate_expr(right)?.to_bool();
                Ok(Value::Boolean(left || right))
            }
            Expression::Cmp {
                left,
                right,
                less_than,
                can_be_equal,
            } => {
                let left = self.evaluate_expr(left)?;
                let right = self.evaluate_expr(right)?;
                let res = match (less_than, can_be_equal) {
                    (false, false) => apply_cmp_op!(left, right, >),
                    (false, true) => apply_cmp_op!(left, right, >=),
                    (true, false) => apply_cmp_op!(left, right, <),
                    (true, true) => apply_cmp_op!(left, right, <=),
                };
                Ok(Value::Boolean(res))
            }
            Expression::Eq(left, right) => {
                let left = self.evaluate_expr(left)?;
                let right = self.evaluate_expr(right)?;
                let res = match (left, right) {
                    (Value::Number(n), Value::Number(m)) => n == m,
                    (Value::Float(a), Value::Float(b)) => (a - b).abs() < f64::EPSILON,
                    #[allow(clippy::cast_precision_loss)]
                    (Value::Number(n), Value::Float(a)) | (Value::Float(a), Value::Number(n)) => {
                        (a - (n as f64)).abs() < f64::EPSILON
                    }
                    (Value::String(a), Value::String(b)) => a == b,
                    (Value::Boolean(a), Value::Boolean(b)) => a == b,
                    _ => todo!(),
                };
                Ok(Value::Boolean(res))
            }
            Expression::Contains {
                haystack,
                needle,
                case_insensitive,
            } => {
                string_op!(self, haystack, needle, *case_insensitive, contains)
            }
            Expression::StartsWith {
                expr,
                prefix,
                case_insensitive,
            } => {
                string_op!(self, expr, prefix, *case_insensitive, starts_with)
            }
            Expression::EndsWith {
                expr,
                suffix,
                case_insensitive,
            } => {
                string_op!(self, expr, suffix, *case_insensitive, ends_with)
            }
            Expression::IEquals(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_string()?.to_lowercase();
                let right = self.evaluate_expr(right)?.unwrap_string()?.to_lowercase();
                Ok(Value::Boolean(left == right))
            }
            Expression::Matches(..) => todo!(),
            Expression::Defined(..) => todo!(),
            Expression::Not(expr) => {
                // TODO: handle other types?
                let v = self.evaluate_expr(expr)?.to_bool();
                Ok(Value::Boolean(!v))
            }

            Expression::Variable(..) => todo!(),
            Expression::VariableAt(..) => todo!(),
            Expression::VariableIn { .. } => todo!(),
            Expression::For { .. } => todo!(),
            Expression::ForIdentifiers { .. } => todo!(),

            Expression::Identifier(_) => todo!(),

            Expression::Number(v) => Ok(Value::Number(*v)),
            Expression::Double(v) => Ok(Value::Float(*v)),
            Expression::String(v) => Ok(Value::String(v)),
            Expression::Regex(v) => Ok(Value::Regex(v)),
            Expression::Boolean(v) => Ok(Value::Boolean(*v)),
        }
    }
}
