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
        .map_or(false, |v| v.to_bool())
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

            Expression::CountInRange {
                variable_index,
                from,
                to,
            } => {
                let from = self.evaluate_expr(from)?.unwrap_number()?;
                let to = self.evaluate_expr(to)?.unwrap_number()?;
                let index = self.get_variable_index(*variable_index)?;
                let var = &mut self.variables[index];

                match (usize::try_from(from), usize::try_from(to)) {
                    (Ok(from), Ok(to)) if from <= to => {
                        let count = var.count_matches_in(self.mem, from, to);

                        i64::try_from(count).ok().map(Value::Number)
                    }
                    _ => todo!(),
                }
            }
            Expression::Count(variable_index) => {
                let index = self.get_variable_index(*variable_index)?;
                let var = &mut self.variables[index];

                let count = var.count_matches(self.mem);
                i64::try_from(count).ok().map(Value::Number)
            }
            Expression::Offset {
                variable_index,
                occurence_number,
            } => {
                let occurence_number = self.evaluate_expr(occurence_number)?.unwrap_number()?;
                let index = self.get_variable_index(*variable_index)?;
                // Safety: index has been either:
                // - generated during compilation and is thus valid.
                // - retrieve from the currently selected variable, and thus valid.
                let var = &mut self.variables[index];

                match usize::try_from(occurence_number) {
                    Ok(v) if v != 0 => var
                        .find_match_occurence(self.mem, v - 1)
                        .map(|mat| Value::Number(mat.start as i64)),
                    Ok(_) | Err(_) => None,
                }
            }
            Expression::Length {
                variable_index,
                occurence_number,
            } => {
                let occurence_number = self.evaluate_expr(occurence_number)?.unwrap_number()?;
                let index = self.get_variable_index(*variable_index)?;
                // Safety: index has been either:
                // - generated during compilation and is thus valid.
                // - retrieve from the currently selected variable, and thus valid.
                let var = &mut self.variables[index];

                match usize::try_from(occurence_number) {
                    Ok(v) if v != 0 => var
                        .find_match_occurence(self.mem, v - 1)
                        .map(|mat| Value::Number(mat.len() as i64)),
                    Ok(_) | Err(_) => None,
                }
            }

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
                let left = self.evaluate_expr(left).map_or(false, |v| v.to_bool());
                let right = self.evaluate_expr(right).map_or(false, |v| v.to_bool());
                Some(Value::Boolean(left && right))
            }
            Expression::Or(left, right) => {
                // Do not rethrow None result for left & right => None is the "undefined" value,
                // and the AND and OR operations are the only one not propagating this poisoned
                // value, but forcing it to false.
                let left = self.evaluate_expr(left).map_or(false, |v| v.to_bool());
                let right = self.evaluate_expr(right).map_or(false, |v| v.to_bool());
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

                Some(Value::Boolean(var.find(self.mem).is_some()))
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
                Some(result)
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
                let mut value = self.evaluate_expr(expr)?.unwrap_number()?;
                #[allow(clippy::cast_precision_loss)]
                if *as_percent {
                    let nb_variables = self.variables.len() as f64;

                    let v = value as f64 / 100. * nb_variables;
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        value = v.ceil() as i64;
                    }
                }

                if value <= 0 {
                    Some(FSEvaluation::Value(Value::Boolean(true)))
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    let value = { value as u64 };

                    if value > self.variables.len() as u64 {
                        Some(FSEvaluation::Value(Value::Boolean(false)))
                    } else {
                        Some(FSEvaluation::Evaluator(FSEvaluator::Number(value)))
                    }
                }
            }
        }
    }

    fn evaluate_for_iterator<'b, I>(
        &mut self,
        mut selection: ForSelectionEvaluator,
        body: &'b Expression,
        iter: I,
    ) -> Value<'b>
    where
        I: IntoIterator<Item = usize>,
    {
        for index in iter {
            self.currently_selected_variable_index = Some(index);
            // TODO: check with libyara that this operation forces the undefined value to false.
            let v = self.evaluate_expr(body).map_or(false, |v| v.to_bool());
            if let Some(result) = selection.add_result_and_check(v) {
                return Value::Boolean(result);
            }
        }
        Value::Boolean(selection.end())
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
                if matched {
                    None
                } else {
                    Some(false)
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