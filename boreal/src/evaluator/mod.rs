//! Provides methods to evaluate expressions.
//!
//! Most evaluating methods return an `Option<Value>`. The `None` corresponds to the `Undefined`
//! value, as described in yara: this is used for all operations that cannot be evaluated:
//!
//! - Symbols that do not make sense, eg `pe.entrypoint` on a non PE scan.
//! - Occurences numbers not found, eg `#a[100]`.
//! - Arithmetic operations that do not make sense, eg `1 << -5`
//! - etc
//!
//! The use of an `Option` is useful to propagate this poison value easily.
use regex::Regex;

use crate::compiler::{Expression, ForSelection, Rule, VariableIndex};

mod variable;
use variable::VariableEvaluation;

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

    fn unwrap_number(&self) -> Option<i64> {
        match self {
            Self::Number(v) => Some(*v),
            _ => None,
        }
    }

    fn unwrap_string(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(*v),
            _ => None,
        }
    }
}

/// Evaluates an expression on a given byte slice.
///
/// Returns true if the expression (with the associated variables) matches on the given
/// byte slice, false otherwise.
pub fn evaluate_rule(rule: &Rule, mem: &[u8]) -> bool {
    let mut evaluator = Evaluator {
        variables: rule.variables.iter().map(VariableEvaluation::new).collect(),
        mem,
        currently_selected_variable_index: None,
    };
    evaluator
        .evaluate_expr(&rule.condition)
        .map(|v| v.to_bool())
        .unwrap_or(false)
}

struct Evaluator<'a> {
    variables: Vec<VariableEvaluation<'a>>,
    mem: &'a [u8],

    // Index of the currently selected variable.
    //
    // This is only set when in a for expression.
    currently_selected_variable_index: Option<usize>,
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
            Some(Value::Boolean(left.$method(&right)))
        } else {
            Some(Value::Boolean(left.$method(right)))
        }
    }};
}

macro_rules! arith_op_num_and_float {
    ($self:expr, $left:expr, $right:expr, $op:tt, $wrapping_op:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let right = $self.evaluate_expr($right)?;
        match (left, right) {
            (Value::Number(n), Value::Number(m)) => Some(Value::Number(n.$wrapping_op(m))),
            (Value::Float(a), Value::Number(n)) => {
                #[allow(clippy::cast_precision_loss)]
                Some(Value::Float(a $op (n as f64)))
            },
            (Value::Number(n), Value::Float(a)) => {
                #[allow(clippy::cast_precision_loss)]
                Some(Value::Float((n as f64) $op a))
            },
            (Value::Float(a), Value::Float(b)) => Some(Value::Float(a $op b)),
            (_, _) => None,
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
    fn get_variable_index(&self, var_index: VariableIndex) -> Option<usize> {
        var_index.0.or(self.currently_selected_variable_index)
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_expr<'b>(&mut self, expr: &'b Expression) -> Option<Value<'b>> {
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
                    Value::Number(n) => Some(Value::Number(-n)),
                    Value::Float(a) => Some(Value::Float(-a)),
                    _ => todo!(),
                }
            }
            Expression::Add(left, right) => {
                arith_op_num_and_float!(self, left, right, +, wrapping_add)
            }
            Expression::Sub(left, right) => {
                arith_op_num_and_float!(self, left, right, -, wrapping_sub)
            }
            Expression::Mul(left, right) => {
                arith_op_num_and_float!(self, left, right, *, wrapping_mul)
            }
            Expression::Div(left, right) => {
                let left = self.evaluate_expr(left)?;
                let right = self.evaluate_expr(right)?;
                match (left, right) {
                    (Value::Number(n), Value::Number(m)) => {
                        if m == 0 {
                            None
                        } else {
                            Some(Value::Number(n.wrapping_div(m)))
                        }
                    }
                    (Value::Float(a), Value::Number(n)) =>
                    {
                        #[allow(clippy::cast_precision_loss)]
                        Some(Value::Float(a / (n as f64)))
                    }
                    (Value::Number(n), Value::Float(a)) =>
                    {
                        #[allow(clippy::cast_precision_loss)]
                        Some(Value::Float((n as f64) / a))
                    }
                    (Value::Float(a), Value::Float(b)) => Some(Value::Float(a / b)),
                    (_, _) => None,
                }
            }
            Expression::Mod(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Number(left % right))
            }

            Expression::BitwiseXor(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Number(left ^ right))
            }
            Expression::BitwiseAnd(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Number(left & right))
            }
            Expression::BitwiseOr(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Number(left | right))
            }
            Expression::BitwiseNot(expr) => {
                let v = self.evaluate_expr(expr)?.unwrap_number()?;
                Some(Value::Number(!v))
            }
            Expression::ShiftLeft(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                if right < 0 {
                    None
                } else if right >= 64 {
                    Some(Value::Number(0))
                } else {
                    Some(Value::Number(left << right))
                }
            }
            Expression::ShiftRight(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                if right < 0 {
                    None
                } else if right >= 64 {
                    Some(Value::Number(0))
                } else {
                    Some(Value::Number(left >> right))
                }
            }

            Expression::And(left, right) => {
                // Do not rethrow None result for left & right => None is the "undefined" value,
                // and the AND and OR operations are the only one not propagating this poisoned
                // value, but forcing it to false.
                let left = self
                    .evaluate_expr(left)
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                let right = self
                    .evaluate_expr(right)
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Some(Value::Boolean(left && right))
            }
            Expression::Or(left, right) => {
                // Do not rethrow None result for left & right => None is the "undefined" value,
                // and the AND and OR operations are the only one not propagating this poisoned
                // value, but forcing it to false.
                let left = self
                    .evaluate_expr(left)
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                let right = self
                    .evaluate_expr(right)
                    .map(|v| v.to_bool())
                    .unwrap_or(false);
                Some(Value::Boolean(left || right))
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
                Some(Value::Boolean(res))
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
                Some(Value::Boolean(res))
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
                Some(Value::Boolean(left == right))
            }
            Expression::Matches(..) => todo!(),
            Expression::Defined(..) => todo!(),
            Expression::Not(expr) => {
                // TODO: handle other types?
                let v = self.evaluate_expr(expr)?.to_bool();
                Some(Value::Boolean(!v))
            }

            Expression::Variable(variable_index) => {
                let index = self.get_variable_index(*variable_index)?;
                // Safety: index has been either:
                // - generated during compilation and is thus valid.
                // - retrieve from the currently selected variable, and thus valid.
                let var = &mut self.variables[index];

                Some(Value::Boolean(var.find(self.mem)))
            }

            Expression::VariableAt {
                variable_index,
                offset,
            } => {
                // Safety: index has been generated during compilation and is valid.
                let offset = self.evaluate_expr(offset)?.unwrap_number()?;
                let index = self.get_variable_index(*variable_index)?;
                // Safety: index has been either:
                // - generated during compilation and is thus valid.
                // - retrieve from the currently selected variable, and thus valid.
                let var = &mut self.variables[index];

                match usize::try_from(offset) {
                    Ok(offset) => Some(Value::Boolean(var.find_at(self.mem, offset))),
                    Err(_) => todo!(),
                }
            }

            Expression::VariableIn {
                variable_index,
                from,
                to,
            } => {
                // Safety: index has been generated during compilation and is valid.
                let from = self.evaluate_expr(from)?.unwrap_number()?;
                let to = self.evaluate_expr(to)?.unwrap_number()?;
                let index = self.get_variable_index(*variable_index)?;
                // Safety: index has been either:
                // - generated during compilation and is thus valid.
                // - retrieve from the currently selected variable, and thus valid.
                let var = &mut self.variables[index];

                match (usize::try_from(from), usize::try_from(to)) {
                    (Ok(from), Ok(to)) if from <= to => {
                        Some(Value::Boolean(var.find_in(self.mem, from, to)))
                    }
                    _ => todo!(),
                }
            }

            Expression::For {
                selection,
                set,
                body,
            } => {
                let selection = match self.evaluate_for_selection(selection)? {
                    ForSelectionEvaluation::Evaluator(e) => e,
                    ForSelectionEvaluation::Value(v) => return Some(v),
                };

                let prev_selected_var_index = self.currently_selected_variable_index;

                let result = if set.elements.is_empty() {
                    self.evaluate_for_iterator(selection, body, 0..self.variables.len())
                } else {
                    self.evaluate_for_iterator(selection, body, set.elements.iter().copied())
                };

                self.currently_selected_variable_index = prev_selected_var_index;
                return result;
            }
            Expression::ForIdentifiers { .. } => todo!(),

            Expression::Identifier(_) => todo!(),

            Expression::Number(v) => Some(Value::Number(*v)),
            Expression::Double(v) => Some(Value::Float(*v)),
            Expression::String(v) => Some(Value::String(v)),
            Expression::Regex(v) => Some(Value::Regex(v)),
            Expression::Boolean(v) => Some(Value::Boolean(*v)),
        }
    }

    fn evaluate_for_selection<'b>(
        &mut self,
        selection: &'b ForSelection,
    ) -> Option<ForSelectionEvaluation<'b>> {
        use ForSelectionEvaluation as FSEvaluation;
        use ForSelectionEvaluator as FSEvaluator;

        match selection {
            ForSelection::Any => Some(FSEvaluation::Evaluator(FSEvaluator::Number(1))),
            ForSelection::All => Some(FSEvaluation::Evaluator(FSEvaluator::All)),
            ForSelection::None => Some(FSEvaluation::Evaluator(FSEvaluator::None)),
            ForSelection::Expr { expr, as_percent } => {
                let mut value = self.evaluate_expr(&expr)?.unwrap_number()?;
                if *as_percent {
                    let nb_variables = self.variables.len() as f64;

                    let v = value as f64 / 100. * nb_variables;
                    value = v.ceil() as i64
                }

                if value <= 0 {
                    Some(FSEvaluation::Value(Value::Boolean(true)))
                } else if value as usize > self.variables.len() {
                    Some(FSEvaluation::Value(Value::Boolean(false)))
                } else {
                    Some(FSEvaluation::Evaluator(FSEvaluator::Number(value as u64)))
                }
            }
        }
    }

    fn evaluate_for_iterator<'b, I>(
        &mut self,
        mut selection: ForSelectionEvaluator,
        body: &'b Expression,
        iter: I,
    ) -> Option<Value<'b>>
    where
        I: IntoIterator<Item = usize>,
    {
        for index in iter.into_iter() {
            self.currently_selected_variable_index = Some(index);
            // TODO: make sure this operation forces the undefined value to false.
            let v = self
                .evaluate_expr(body)
                .map(|v| v.to_bool())
                .unwrap_or(false);
            if let Some(result) = selection.add_result_and_check(v) {
                return Some(Value::Boolean(result));
            }
        }
        Some(Value::Boolean(selection.end()))
    }
}

/// Result of the evaluation of a for selection.
enum ForSelectionEvaluation<'a> {
    /// An evaluator that accumulates evaluations of each variable, and return a result as early
    /// as possible.
    Evaluator(ForSelectionEvaluator),

    /// Result of the for selection if available immediately, without needing any evaluation.
    Value(Value<'a>),
}

/// Evaluator of a for selection
enum ForSelectionEvaluator {
    /// All variables must match
    All,
    /// No variables must match
    None,
    /// A minimum number of variables must match
    Number(u64),
}

impl ForSelectionEvaluator {
    /// Add the result of the evaluation of the for expression body for a variable.
    ///
    /// Return Some(v) if the selection has a result, and no further matches are needed.
    /// Return None otherwise.
    fn add_result_and_check(&mut self, matched: bool) -> Option<bool> {
        match self {
            Self::All => {
                if !matched {
                    Some(false)
                } else {
                    None
                }
            }
            Self::None => {
                if matched {
                    Some(false)
                } else {
                    None
                }
            }
            Self::Number(v) if matched => {
                *v = v.saturating_sub(1);
                if *v == 0 {
                    Some(true)
                } else {
                    None
                }
            }
            Self::Number(_) => None,
        }
    }

    /// Return final value, no other matches can happen.
    fn end(self) -> bool {
        match self {
            Self::All | Self::None => true,
            Self::Number(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::Scanner;

    use super::*;

    #[track_caller]
    #[allow(clippy::needless_pass_by_value)]
    fn test_eval(cond: &str, input: &[u8], expected_res: bool) {
        let rule = format!("rule a {{ condition: {} }}", cond);
        let mut scanner = Scanner::new();
        scanner.add_rules_from_str(&rule).unwrap_or_else(|err| {
            panic!("parsing failed: {}", err.to_short_description("mem", &rule))
        });
        assert_eq!(evaluate_rule(&scanner.rules[0], input), expected_res);
    }

    #[test]
    fn test_eval_add() {
        test_eval("2 + 6 == 8", &[], true);
        test_eval("3 + 4.2 == 7.2", &[], true);
        test_eval("2.62 + 3 == 5.62", &[], true);
        test_eval("1.3 + 1.5 == 2.8", &[], true);
        test_eval("0x7FFFFFFFFFFFFFFF + 1 > 0", &[], false);
        test_eval("-2 + -0x7FFFFFFFFFFFFFFF < 0", &[], false);
    }

    #[test]
    fn test_eval_sub() {
        test_eval("2 - 6 == -4", &[], true);
        test_eval("3 - 4.5 == -1.5", &[], true);
        test_eval("2.62 - 3 == -0.38", &[], true);
        test_eval("1.3 - 1.5 == -0.2", &[], true);
        test_eval("-0x7FFFFFFFFFFFFFFF - 2 < 0", &[], false);
        test_eval("0x7FFFFFFFFFFFFFFF - -1 > 0", &[], false);
    }

    #[test]
    fn test_eval_mul() {
        test_eval("2 * 6 == 12", &[], true);
        test_eval("3 * 0.1 == 0.3", &[], true);
        test_eval("2.62 * 3 == 7.86", &[], true);
        test_eval("1.3 * 0.5 == 0.65", &[], true);
        test_eval("-0x0FFFFFFFFFFFFFFF * 10 < 0", &[], false);
        test_eval("0x1FFFFFFFFFFFFFFF * 5 > 0", &[], false);
    }

    #[test]
    fn test_eval_div() {
        test_eval("7 \\ 4 == 1", &[], true);
        test_eval("-7 \\ 4 == -1", &[], true);
        test_eval("7 \\ 4.0 == 1.75", &[], true);
        test_eval("7.0 \\ 4 == 1.75", &[], true);
        test_eval("2.3 \\ 4.6 == 0.5", &[], true);
        test_eval("1 \\ 0 == 1", &[], false);
        test_eval("-2 \\ -0 > 0", &[], false);
        test_eval("(-0x7FFFFFFFFFFFFFFF - 1) \\ -1 > 0", &[], false);
    }

    #[test]
    fn test_eval_shl() {
        test_eval("15 << 2 == 60", &[], true);
        test_eval("0xDEADCAFE << 16 == 0xDEADCAFE0000", &[], true);
        test_eval("-8 << 1 == -16", &[], true);
        test_eval("0x7FFFFFFFFFFFFFFF << 4 == -16", &[], true);
        test_eval("0x7FFFFFFFFFFFFFFF << 1000 == 0", &[], true);
        test_eval("-0x7FFFFFFFFFFFFFFF << 1000 == 0", &[], true);
        test_eval("12 << -2 == 0", &[], false);
    }

    #[test]
    fn test_eval_shr() {
        test_eval("15 >> 2 == 3", &[], true);
        test_eval("0xDEADCAFE >> 16 == 0xDEAD", &[], true);
        test_eval("-8 >> 1 == -4", &[], true);
        test_eval("0x7FFFFFFFFFFFFFFF >> 62 == 0x1", &[], true);
        test_eval("0x7FFFFFFFFFFFFFFF >> 1000 == 0", &[], true);
        test_eval("-0x7FFFFFFFFFFFFFFF >> 1000 == 0", &[], true);
        test_eval("12 >> -2 == 0", &[], false);
    }
}
