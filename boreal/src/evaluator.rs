//! Provides methods to evaluate expressions.
use regex::Regex;

use crate::compiler::{Expression, Rule};
use crate::error::ScanError;
use crate::variable::Variable;

#[derive(Debug)]
enum Value<'a> {
    Number(i64),
    Float(f64),
    String(&'a str),
    Regex(&'a Regex),
    Boolean(bool),
}

impl Value<'_> {
    fn type_to_string(&self) -> &'static str {
        match self {
            Self::Number(_) => "number",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Regex(_) => "regex",
            Self::Boolean(_) => "boolean",
        }
    }
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

    fn unwrap_number(&self, operator: &str) -> Result<i64, ScanError> {
        match self {
            Self::Number(v) => Ok(*v),
            _ => Err(ScanError::InvalidType {
                typ: self.type_to_string().to_owned(),
                expected_type: "number".to_owned(),
                operator: operator.to_owned(),
            }),
        }
    }

    fn unwrap_string(&self, operator: &str) -> Result<&str, ScanError> {
        match self {
            Self::String(v) => Ok(*v),
            _ => Err(ScanError::InvalidType {
                typ: self.type_to_string().to_owned(),
                expected_type: "string".to_owned(),
                operator: operator.to_owned(),
            }),
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
pub fn evaluate_rule(rule: &Rule, mem: &[u8]) -> Result<bool, ScanError> {
    let evaluator = Evaluator {
        variables: &rule.variables,
        mem,
    };
    evaluator
        .evaluate_expr(&rule.condition)
        .map(|v| v.to_bool())
}

struct Evaluator<'a> {
    variables: &'a [Variable],
    mem: &'a [u8],
}

macro_rules! string_op {
    ($self:expr, $left:expr, $right:expr, $case_insensitive:expr, $method:ident, $op:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let left = left.unwrap_string($op)?;
        let right = $self.evaluate_expr($right)?;
        let right = right.unwrap_string($op)?;

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
    ($self:expr, $left:expr, $right:expr, $op:tt, $checked_op:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let right = $self.evaluate_expr($right)?;
        match (left, right) {
            (Value::Number(n), Value::Number(m)) => match n.$checked_op(m) {
                Some(v) => Ok(Value::Number(v)),
                None => Err(ScanError::Overflow {
                    left_value: n,
                    right_value: m,
                    operator: stringify!($op).to_owned(),
                }),
            },
            (Value::Float(a), Value::Number(n)) => {
                #[allow(clippy::cast_precision_loss)]
                Ok(Value::Float(a $op (n as f64)))
            },
            (Value::Number(n), Value::Float(a)) => {
                #[allow(clippy::cast_precision_loss)]
                Ok(Value::Float((n as f64) $op a))
            },
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a $op b)),
            (left, right) => Err(ScanError::IncompatibleTypes {
                left_type: left.type_to_string().to_owned(),
                right_type: Some(right.type_to_string().to_owned()),
                operator: stringify!($op).to_owned(),
            }),
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
    fn evaluate_expr<'b>(&self, expr: &'b Expression) -> Result<Value<'b>, ScanError> {
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
                arith_op_num_and_float!(self, left, right, +, checked_add)
            }
            Expression::Sub(left, right) => {
                arith_op_num_and_float!(self, left, right, -, checked_sub)
            }
            Expression::Mul(left, right) => {
                arith_op_num_and_float!(self, left, right, *, checked_mul)
            }
            Expression::Div(left, right) => {
                arith_op_num_and_float!(self, left, right, /, checked_div)
            }
            Expression::Mod(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number("%")?;
                let right = self.evaluate_expr(right)?.unwrap_number("%")?;
                Ok(Value::Number(left % right))
            }

            Expression::BitwiseXor(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number("^")?;
                let right = self.evaluate_expr(right)?.unwrap_number("^")?;
                Ok(Value::Number(left ^ right))
            }
            Expression::BitwiseAnd(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number("&")?;
                let right = self.evaluate_expr(right)?.unwrap_number("&")?;
                Ok(Value::Number(left & right))
            }
            Expression::BitwiseOr(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number("|")?;
                let right = self.evaluate_expr(right)?.unwrap_number("|")?;
                Ok(Value::Number(left | right))
            }
            Expression::BitwiseNot(expr) => {
                let v = self.evaluate_expr(expr)?.unwrap_number("~")?;
                Ok(Value::Number(!v))
            }
            Expression::ShiftLeft(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number("<<")?;
                let right = self.evaluate_expr(right)?.unwrap_number("<<")?;
                if right < 0 {
                    Err(ScanError::Overflow {
                        left_value: left,
                        right_value: right,
                        operator: "<<".to_owned(),
                    })
                } else if right >= 64 {
                    Ok(Value::Number(0))
                } else {
                    Ok(Value::Number(left << right))
                }
            }
            Expression::ShiftRight(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number(">>")?;
                let right = self.evaluate_expr(right)?.unwrap_number(">>")?;
                if right < 0 {
                    Err(ScanError::Overflow {
                        left_value: left,
                        right_value: right,
                        operator: ">>".to_owned(),
                    })
                } else if right >= 64 {
                    Ok(Value::Number(0))
                } else {
                    Ok(Value::Number(left >> right))
                }
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
                let op = if *case_insensitive {
                    "icontains"
                } else {
                    "contains"
                };
                string_op!(self, haystack, needle, *case_insensitive, contains, op)
            }
            Expression::StartsWith {
                expr,
                prefix,
                case_insensitive,
            } => {
                let op = if *case_insensitive {
                    "istartswith"
                } else {
                    "startswith"
                };
                string_op!(self, expr, prefix, *case_insensitive, starts_with, op)
            }
            Expression::EndsWith {
                expr,
                suffix,
                case_insensitive,
            } => {
                let op = if *case_insensitive {
                    "iendswith"
                } else {
                    "endswith"
                };
                string_op!(self, expr, suffix, *case_insensitive, ends_with, op)
            }
            Expression::IEquals(left, right) => {
                let left = self
                    .evaluate_expr(left)?
                    .unwrap_string("iequals")?
                    .to_lowercase();
                let right = self
                    .evaluate_expr(right)?
                    .unwrap_string("iequals")?
                    .to_lowercase();
                Ok(Value::Boolean(left == right))
            }
            Expression::Matches(..) => todo!(),
            Expression::Defined(..) => todo!(),
            Expression::Not(expr) => {
                // TODO: handle other types?
                let v = self.evaluate_expr(expr)?.to_bool();
                Ok(Value::Boolean(!v))
            }

            Expression::Variable(variable_name) => {
                let var = self.get_var(variable_name);
                // TODO: handle io error
                Ok(Value::Boolean(var.find(self.mem).unwrap()))
            }
            Expression::VariableAt(variable_name, offset_expr) => {
                let var = self.get_var(variable_name);
                let offset = self
                    .evaluate_expr(offset_expr)?
                    .unwrap_number("variable at")?;
                match usize::try_from(offset) {
                    Ok(offset) => Ok(Value::Boolean(var.find_at(self.mem, offset).unwrap())),
                    // TODO: return error?
                    Err(_) => Ok(Value::Boolean(false)),
                }
            }
            Expression::VariableIn {
                variable_name,
                from,
                to,
            } => {
                let var = self.get_var(variable_name);
                let from = self.evaluate_expr(from)?.unwrap_number("variable in")?;
                let to = self.evaluate_expr(to)?.unwrap_number("variable in")?;
                match (usize::try_from(from), usize::try_from(to)) {
                    (Ok(from), Ok(to)) if from <= to => {
                        Ok(Value::Boolean(var.find_in(self.mem, from, to).unwrap()))
                    }
                    // TODO: return error?
                    _ => Ok(Value::Boolean(false)),
                }
            }
            Expression::For { .. } => todo!(),
            Expression::ForIn { .. } => todo!(),
            Expression::ForIdentifiers { .. } => todo!(),

            Expression::Identifier(_) => todo!(),

            Expression::Number(v) => Ok(Value::Number(*v)),
            Expression::Double(v) => Ok(Value::Float(*v)),
            Expression::String(v) => Ok(Value::String(v)),
            Expression::Regex(v) => Ok(Value::Regex(v)),
            Expression::Boolean(v) => Ok(Value::Boolean(*v)),
        }
    }

    fn get_var(&self, variable_name: &str) -> &Variable {
        // TODO: improve variable name matching
        self.variables
            .iter()
            .find(|v| v.name == variable_name)
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::Scanner;

    use super::*;

    #[track_caller]
    #[allow(clippy::needless_pass_by_value)]
    fn test_eval(cond: &str, input: &[u8], expected_res: Result<bool, ScanError>) {
        let rule = format!("rule a {{ condition: {} }}", cond);
        let mut scanner = Scanner::new();
        scanner
            .add_rules_from_str(&rule)
            .unwrap_or_else(|err| panic!("parsing failed: {:?}", err));
        assert_eq!(evaluate_rule(&scanner.rules[0], input), expected_res);
    }

    #[test]
    fn test_eval_add() {
        test_eval("2 + 6 == 8", &[], Ok(true));
        test_eval("3 + 4.2 == 7.2", &[], Ok(true));
        test_eval("2.62 + 3 == 5.62", &[], Ok(true));
        test_eval("1.3 + 1.5 == 2.8", &[], Ok(true));
        test_eval(
            "0x7FFFFFFFFFFFFFFF + 1 > 0",
            &[],
            Err(ScanError::Overflow {
                left_value: 0x7FFF_FFFF_FFFF_FFFF,
                right_value: 1,
                operator: "+".to_owned(),
            }),
        );
        test_eval(
            "-2 + -0x7FFFFFFFFFFFFFFF < 0",
            &[],
            Err(ScanError::Overflow {
                left_value: -2,
                right_value: -0x7FFF_FFFF_FFFF_FFFF,
                operator: "+".to_owned(),
            }),
        );
    }

    #[test]
    fn test_eval_sub() {
        test_eval("2 - 6 == -4", &[], Ok(true));
        test_eval("3 - 4.5 == -1.5", &[], Ok(true));
        test_eval("2.62 - 3 == -0.38", &[], Ok(true));
        test_eval("1.3 - 1.5 == -0.2", &[], Ok(true));
        test_eval(
            "-0x7FFFFFFFFFFFFFFF - 2 < 0",
            &[],
            Err(ScanError::Overflow {
                left_value: -0x7FFF_FFFF_FFFF_FFFF,
                right_value: 2,
                operator: "-".to_owned(),
            }),
        );
        test_eval(
            "0x7FFFFFFFFFFFFFFF - -1 > 0",
            &[],
            Err(ScanError::Overflow {
                left_value: 0x7FFF_FFFF_FFFF_FFFF,
                right_value: -1,
                operator: "-".to_owned(),
            }),
        );
    }

    #[test]
    fn test_eval_mul() {
        test_eval("2 * 6 == 12", &[], Ok(true));
        test_eval("3 * 0.1 == 0.3", &[], Ok(true));
        test_eval("2.62 * 3 == 7.86", &[], Ok(true));
        test_eval("1.3 * 0.5 == 0.65", &[], Ok(true));
        test_eval(
            "-0x0FFFFFFFFFFFFFFF * 20 < 0",
            &[],
            Err(ScanError::Overflow {
                left_value: -0x0FFF_FFFF_FFFF_FFFF,
                right_value: 20,
                operator: "*".to_owned(),
            }),
        );
        test_eval(
            "0x1FFFFFFFFFFFFFFF * 10 > 0",
            &[],
            Err(ScanError::Overflow {
                left_value: 0x1FFF_FFFF_FFFF_FFFF,
                right_value: 10,
                operator: "*".to_owned(),
            }),
        );
    }

    #[test]
    fn test_eval_div() {
        test_eval("7 \\ 4 == 1", &[], Ok(true));
        test_eval("-7 \\ 4 == -1", &[], Ok(true));
        test_eval("7 \\ 4.0 == 1.75", &[], Ok(true));
        test_eval("7.0 \\ 4 == 1.75", &[], Ok(true));
        test_eval("2.3 \\ 4.6 == 0.5", &[], Ok(true));
        test_eval(
            "1 \\ 0 == 1",
            &[],
            Err(ScanError::Overflow {
                left_value: 1,
                right_value: 0,
                operator: "/".to_owned(),
            }),
        );
        test_eval(
            "-2 \\ -0 > 0",
            &[],
            Err(ScanError::Overflow {
                left_value: -2,
                right_value: 0,
                operator: "/".to_owned(),
            }),
        );
        test_eval(
            "(-0x7FFFFFFFFFFFFFFF - 1) \\ -1 > 0",
            &[],
            Err(ScanError::Overflow {
                left_value: i64::MIN,
                right_value: -1,
                operator: "/".to_owned(),
            }),
        );
    }

    #[test]
    fn test_eval_shl() {
        test_eval("15 << 2 == 60", &[], Ok(true));
        test_eval("0xDEADCAFE << 16 == 0xDEADCAFE0000", &[], Ok(true));
        test_eval("-8 << 1 == -16", &[], Ok(true));
        test_eval("0x7FFFFFFFFFFFFFFF << 4 == -16", &[], Ok(true));
        test_eval("0x7FFFFFFFFFFFFFFF << 1000 == 0", &[], Ok(true));
        test_eval("-0x7FFFFFFFFFFFFFFF << 1000 == 0", &[], Ok(true));
        test_eval(
            "12 << -2 == 0",
            &[],
            Err(ScanError::Overflow {
                left_value: 12,
                right_value: -2,
                operator: "<<".to_owned(),
            }),
        );
    }

    #[test]
    fn test_eval_shr() {
        test_eval("15 >> 2 == 3", &[], Ok(true));
        test_eval("0xDEADCAFE >> 16 == 0xDEAD", &[], Ok(true));
        test_eval("-8 >> 1 == -4", &[], Ok(true));
        test_eval("0x7FFFFFFFFFFFFFFF >> 62 == 0x1", &[], Ok(true));
        test_eval("0x7FFFFFFFFFFFFFFF >> 1000 == 0", &[], Ok(true));
        test_eval("-0x7FFFFFFFFFFFFFFF >> 1000 == 0", &[], Ok(true));
        test_eval(
            "12 >> -2 == 0",
            &[],
            Err(ScanError::Overflow {
                left_value: 12,
                right_value: -2,
                operator: ">>".to_owned(),
            }),
        );
    }
}
