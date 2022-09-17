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
use std::sync::Arc;

use crate::regex::Regex;
use memchr::memmem;

use crate::compiler::{Expression, ForIterator, ForSelection, Rule, VariableIndex};
use crate::module::{Module, ModuleDataMap, ScanContext, Value as ModuleValue};
use crate::variable_set::VariableSetMatches;

mod module;

#[cfg(feature = "object")]
mod entrypoint;

mod read_integer;
use read_integer::evaluate_read_integer;
mod variable;
pub(crate) use variable::VariableEvaluation;

#[derive(Clone, Debug)]
enum Value {
    Integer(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Regex(Regex),
    Boolean(bool),
}

impl Value {
    fn to_bool(&self) -> bool {
        match self {
            Self::Boolean(b) => *b,
            Self::Bytes(s) => !s.is_empty(),
            Self::Float(a) => *a != 0.0,
            Self::Integer(n) => *n != 0,
            Self::Regex(_) => true,
        }
    }

    fn unwrap_number(self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(v),
            _ => None,
        }
    }

    fn unwrap_bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(v) => Some(v),
            _ => None,
        }
    }
}

/// Data linked to the scan, shared by all rules.
#[derive(Debug)]
pub struct ScanData<'a> {
    mem: &'a [u8],

    // TODO: make this lazy?
    pub module_values: Vec<(&'static str, Arc<ModuleValue>)>,

    // List of "no match/has at least one match" results for all variables.
    variable_set_matches: VariableSetMatches,

    // Index offset into `variables_matches`.
    //
    // Context used when calling module functions
    module_ctx: ScanContext<'a>,
}

impl<'a> ScanData<'a> {
    pub(crate) fn new(
        mem: &'a [u8],
        variable_set_matches: VariableSetMatches,
        modules: &[Box<dyn Module>],
    ) -> Self {
        let mut module_ctx = ScanContext {
            mem,
            module_data: ModuleDataMap::default(),
        };

        Self {
            mem,
            module_values: modules
                .iter()
                .map(|module| {
                    (
                        module.get_name(),
                        Arc::new(crate::module::Value::Object(
                            module.get_dynamic_values(&mut module_ctx),
                        )),
                    )
                })
                .collect(),
            variable_set_matches,
            module_ctx,
        }
    }
}

/// Evaluates an expression on a given byte slice.
///
/// Returns true if the expression (with the associated variables) matches on the given
/// byte slice, false otherwise.
pub(crate) fn evaluate_rule<'scan, 'rule>(
    rule: &'rule Rule,
    scan_data: &'scan ScanData,
    set_index_offset: usize,
    previous_rules_results: &'scan [bool],
) -> (bool, Vec<VariableEvaluation<'rule>>) {
    let mut evaluator = Evaluator {
        variables: rule
            .variables
            .iter()
            .enumerate()
            .map(|(i, var)| {
                VariableEvaluation::new(
                    var,
                    &scan_data.variable_set_matches.matched(set_index_offset + i),
                    scan_data.mem,
                )
            })
            .collect(),
        mem: scan_data.mem,
        previous_rules_results,
        currently_selected_variable_index: None,
        bounded_identifiers_stack: Vec::new(),
        scan_data,
    };
    let res = evaluator
        .evaluate_expr(&rule.condition)
        .map_or(false, |v| v.to_bool());
    (res, evaluator.variables)
}

struct Evaluator<'scan, 'rule> {
    variables: Vec<VariableEvaluation<'rule>>,

    mem: &'scan [u8],

    // Array of previous rules results.
    //
    // This only stores results of rules that are depended upon, not all rules.
    previous_rules_results: &'scan [bool],

    // Index of the currently selected variable.
    //
    // This is only set when in a for expression.
    currently_selected_variable_index: Option<usize>,

    // Stack of bounded identifiers to their integer values.
    bounded_identifiers_stack: Vec<Arc<ModuleValue>>,

    // Data related only to the scan, independent of the rule.
    scan_data: &'scan ScanData<'scan>,
}

macro_rules! bytes_op {
    ($self:expr, $left:expr, $right:expr, $case_insensitive:expr, $method:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let mut left = left.unwrap_bytes()?;
        let right = $self.evaluate_expr($right)?;
        let mut right = right.unwrap_bytes()?;

        if $case_insensitive {
            left.make_ascii_lowercase();
            right.make_ascii_lowercase();
            Some(Value::Boolean(left.$method(&right)))
        } else {
            Some(Value::Boolean(left.$method(&right)))
        }
    }};
}

macro_rules! arith_op_num_and_float {
    ($self:expr, $left:expr, $right:expr, $op:tt, $wrapping_op:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let right = $self.evaluate_expr($right)?;
        match (left, right) {
            (Value::Integer(n), Value::Integer(m)) => Some(Value::Integer(n.$wrapping_op(m))),
            (Value::Float(a), Value::Integer(n)) => {
                #[allow(clippy::cast_precision_loss)]
                Some(Value::Float(a $op (n as f64)))
            },
            (Value::Integer(n), Value::Float(a)) => {
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
            (Value::Integer(n), Value::Integer(m)) => n $op m,
            (Value::Float(a), Value::Float(b)) => a $op b,
            (Value::Integer(n), Value::Float(b)) => (n as f64) $op b,
            (Value::Float(a), Value::Integer(m)) => a $op (m as f64),
            (Value::Bytes(a), Value::Bytes(b)) => a $op b,
            _ => return None,
        }
    }
}

impl Evaluator<'_, '_> {
    fn get_variable_index(&self, var_index: VariableIndex) -> Option<usize> {
        var_index.0.or(self.currently_selected_variable_index)
    }

    fn evaluate_expr(&mut self, expr: &Expression) -> Option<Value> {
        match expr {
            Expression::Filesize => Some(Value::Integer(self.mem.len() as i64)),

            #[cfg(feature = "object")]
            Expression::Entrypoint => entrypoint::get_pe_or_elf_entry_point(self.mem),
            #[cfg(not(feature = "object"))]
            Expression::Entrypoint => None,

            Expression::ReadInteger { addr, ty } => evaluate_read_integer(self, addr, *ty),

            Expression::CountInRange {
                variable_index,
                from,
                to,
            } => {
                let from = self.evaluate_expr(from)?.unwrap_number()?;
                let to = self.evaluate_expr(to)?.unwrap_number()?;

                match (usize::try_from(from), usize::try_from(to)) {
                    (Ok(from), Ok(to)) if from <= to => {
                        let index = self.get_variable_index(*variable_index)?;
                        let var = &mut self.variables[index];
                        let count = var.count_matches_in(self.mem, from, to);

                        i64::try_from(count).ok().map(Value::Integer)
                    }
                    _ => None,
                }
            }
            Expression::Count(variable_index) => {
                let index = self.get_variable_index(*variable_index)?;
                let var = &mut self.variables[index];
                let count = var.count_matches(self.mem);
                i64::try_from(count).ok().map(Value::Integer)
            }
            Expression::Offset {
                variable_index,
                occurence_number,
            } => {
                let occurence_number = self.evaluate_expr(occurence_number)?.unwrap_number()?;

                match usize::try_from(occurence_number) {
                    Ok(v) if v != 0 => {
                        let index = self.get_variable_index(*variable_index)?;
                        let var = &mut self.variables[index];
                        var.find_match_occurence(self.mem, v - 1)
                            .map(|mat| Value::Integer(mat.start as i64))
                    }
                    Ok(_) | Err(_) => None,
                }
            }
            Expression::Length {
                variable_index,
                occurence_number,
            } => {
                let occurence_number = self.evaluate_expr(occurence_number)?.unwrap_number()?;

                match usize::try_from(occurence_number) {
                    Ok(v) if v != 0 => {
                        let index = self.get_variable_index(*variable_index)?;
                        let var = &mut self.variables[index];
                        var.find_match_occurence(self.mem, v - 1)
                            .map(|mat| Value::Integer(mat.len() as i64))
                    }
                    Ok(_) | Err(_) => None,
                }
            }

            Expression::Neg(expr) => {
                let v = self.evaluate_expr(expr)?;

                match v {
                    Value::Integer(n) => Some(Value::Integer(-n)),
                    Value::Float(a) => Some(Value::Float(-a)),
                    _ => None,
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
                    (Value::Integer(n), Value::Integer(m)) => {
                        if m == 0 {
                            None
                        } else {
                            Some(Value::Integer(n.wrapping_div(m)))
                        }
                    }
                    (Value::Float(a), Value::Integer(n)) =>
                    {
                        #[allow(clippy::cast_precision_loss)]
                        Some(Value::Float(a / (n as f64)))
                    }
                    (Value::Integer(n), Value::Float(a)) =>
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
                Some(Value::Integer(left % right))
            }

            Expression::BitwiseXor(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Integer(left ^ right))
            }
            Expression::BitwiseAnd(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Integer(left & right))
            }
            Expression::BitwiseOr(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Some(Value::Integer(left | right))
            }
            Expression::BitwiseNot(expr) => {
                let v = self.evaluate_expr(expr)?.unwrap_number()?;
                Some(Value::Integer(!v))
            }
            Expression::ShiftLeft(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                if right < 0 {
                    None
                } else if right >= 64 {
                    Some(Value::Integer(0))
                } else {
                    Some(Value::Integer(left << right))
                }
            }
            Expression::ShiftRight(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                if right < 0 {
                    None
                } else if right >= 64 {
                    Some(Value::Integer(0))
                } else {
                    Some(Value::Integer(left >> right))
                }
            }

            Expression::And(ops) => {
                // Do not rethrow None result for left & right => None is the "undefined" value,
                // and the AND and OR operations are the only one not propagating this poisoned
                // value, but forcing it to false.
                for op in ops {
                    let res = self.evaluate_expr(op).map_or(false, |v| v.to_bool());
                    if !res {
                        return Some(Value::Boolean(false));
                    }
                }
                Some(Value::Boolean(true))
            }
            Expression::Or(ops) => {
                // Do not rethrow None result for left & right => None is the "undefined" value,
                // and the AND and OR operations are the only one not propagating this poisoned
                // value, but forcing it to false.
                for op in ops {
                    let res = self.evaluate_expr(op).map_or(false, |v| v.to_bool());
                    if res {
                        return Some(Value::Boolean(true));
                    }
                }
                Some(Value::Boolean(false))
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
                eval_eq_values(left, right).map(Value::Boolean)
            }
            Expression::NotEq(left, right) => {
                let left = self.evaluate_expr(left)?;
                let right = self.evaluate_expr(right)?;
                eval_eq_values(left, right).map(|v| Value::Boolean(!v))
            }

            Expression::Contains {
                haystack,
                needle,
                case_insensitive,
            } => {
                let left = self.evaluate_expr(haystack)?;
                let mut left = left.unwrap_bytes()?;
                let right = self.evaluate_expr(needle)?;
                let mut right = right.unwrap_bytes()?;

                if *case_insensitive {
                    left.make_ascii_lowercase();
                    right.make_ascii_lowercase();
                    Some(Value::Boolean(memmem::find(&left, &right).is_some()))
                } else {
                    Some(Value::Boolean(memmem::find(&left, &right).is_some()))
                }
            }
            Expression::StartsWith {
                expr,
                prefix,
                case_insensitive,
            } => {
                bytes_op!(self, expr, prefix, *case_insensitive, starts_with)
            }
            Expression::EndsWith {
                expr,
                suffix,
                case_insensitive,
            } => {
                bytes_op!(self, expr, suffix, *case_insensitive, ends_with)
            }
            Expression::IEquals(left, right) => {
                let mut left = self.evaluate_expr(left)?.unwrap_bytes()?;
                left.make_ascii_lowercase();
                let mut right = self.evaluate_expr(right)?.unwrap_bytes()?;
                right.make_ascii_lowercase();
                Some(Value::Boolean(left == right))
            }
            Expression::Matches(expr, regex) => {
                let s = self.evaluate_expr(expr)?.unwrap_bytes()?;
                Some(Value::Boolean(regex.as_regex().is_match(&s)))
            }
            Expression::Defined(expr) => {
                let expr = self.evaluate_expr(expr);

                Some(Value::Boolean(expr.is_some()))
            }
            Expression::Not(expr) => {
                let v = self.evaluate_expr(expr)?.to_bool();
                Some(Value::Boolean(!v))
            }

            Expression::Variable(variable_index) => {
                // For this expression, we can use the variables set to retrieve the truth value,
                // no need to rescan.
                let index = self.get_variable_index(*variable_index)?;
                let var = &mut self.variables[index];
                Some(Value::Boolean(var.find(self.mem)))
            }

            Expression::VariableAt {
                variable_index,
                offset,
            } => {
                // Safety: index has been generated during compilation and is valid.
                let offset = match self.evaluate_expr(offset) {
                    Some(v) => v.unwrap_number()?,
                    // This is actually what libyara does instead of returning an undefined value,
                    // not sure why.
                    None => return Some(Value::Boolean(false)),
                };
                match usize::try_from(offset) {
                    Ok(offset) => {
                        let index = self.get_variable_index(*variable_index)?;
                        let var = &mut self.variables[index];
                        Some(Value::Boolean(var.find_at(self.mem, offset)))
                    }
                    Err(_) => Some(Value::Boolean(false)),
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
                match (usize::try_from(from), usize::try_from(to)) {
                    (Ok(from), Ok(to)) if from <= to => {
                        let index = self.get_variable_index(*variable_index)?;
                        let var = &mut self.variables[index];

                        Some(Value::Boolean(var.find_in(self.mem, from, to)))
                    }
                    _ => Some(Value::Boolean(false)),
                }
            }

            Expression::For {
                selection,
                set,
                body,
            } => {
                let nb_elements = if set.elements.is_empty() {
                    self.variables.len()
                } else {
                    set.elements.len()
                };

                let selection = match self.evaluate_for_selection(selection, nb_elements) {
                    Some(ForSelectionEvaluation::Evaluator(e)) => e,
                    Some(ForSelectionEvaluation::Value(v)) => return Some(v),
                    None => return Some(Value::Boolean(false)),
                };

                let prev_selected_var_index = self.currently_selected_variable_index;

                let result = if set.elements.is_empty() {
                    self.evaluate_for_var(selection, body, 0..self.variables.len())
                } else {
                    self.evaluate_for_var(selection, body, set.elements.iter().copied())
                };

                self.currently_selected_variable_index = prev_selected_var_index;
                Some(result)
            }

            Expression::ForIdentifiers {
                selection,
                iterator,
                body,
            } => {
                if matches!(
                    selection,
                    ForSelection::Expr {
                        as_percent: true,
                        ..
                    }
                ) {
                    // This is, as it stands, not possible to generate such an expression.
                    // Add a debug assert just in case
                    debug_assert!(false);
                }

                // XXX: giving a dummy value for the nb_elements is ok here, since it's only
                // used for percent expr, which is not possible in this context.
                let selection = match self.evaluate_for_selection(selection, 0) {
                    Some(ForSelectionEvaluation::Evaluator(e)) => e,
                    Some(ForSelectionEvaluation::Value(v)) => return Some(v),
                    None => return Some(Value::Boolean(false)),
                };

                self.evaluate_for_iterator(iterator, selection, body)
            }

            Expression::ForRules { selection, set } => {
                let nb_elements = set.elements.len() + set.already_matched;

                let mut selection = match self.evaluate_for_selection(selection, nb_elements) {
                    Some(ForSelectionEvaluation::Evaluator(e)) => e,
                    Some(ForSelectionEvaluation::Value(v)) => return Some(v),
                    None => return Some(Value::Boolean(false)),
                };

                for _ in 0..set.already_matched {
                    if let Some(result) = selection.add_result_and_check(true) {
                        return Some(Value::Boolean(result));
                    }
                }

                for index in &set.elements {
                    let v = self.previous_rules_results.get(*index)?;
                    if let Some(result) = selection.add_result_and_check(*v) {
                        return Some(Value::Boolean(result));
                    }
                }
                Some(Value::Boolean(selection.end()))
            }

            Expression::Module(module_expr) => module::evaluate_expr(self, module_expr)
                .and_then(module::module_value_to_expr_value),

            Expression::Rule(index) => self
                .previous_rules_results
                .get(*index)
                .map(|v| Value::Boolean(*v)),

            Expression::Integer(v) => Some(Value::Integer(*v)),
            Expression::Double(v) => Some(Value::Float(*v)),
            Expression::Bytes(v) => Some(Value::Bytes(v.clone())),
            Expression::Regex(v) => Some(Value::Regex(v.clone())),
            Expression::Boolean(v) => Some(Value::Boolean(*v)),
        }
    }

    fn evaluate_for_selection(
        &mut self,
        selection: &ForSelection,
        nb_elements: usize,
    ) -> Option<ForSelectionEvaluation> {
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
                    let nb_variables = nb_elements as f64;

                    let v = value as f64 / 100. * nb_variables;
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        value = v.ceil() as i64;
                    }
                } else if value == 0 {
                    // Special case: 0 without percent is treated as None
                    return Some(FSEvaluation::Evaluator(FSEvaluator::None));
                }

                if value <= 0 {
                    Some(FSEvaluation::Value(Value::Boolean(true)))
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    let value = { value as u64 };
                    Some(FSEvaluation::Evaluator(FSEvaluator::Number(value)))
                }
            }
        }
    }

    fn evaluate_for_var<I>(
        &mut self,
        mut selection: ForSelectionEvaluator,
        body: &Expression,
        iter: I,
    ) -> Value
    where
        I: IntoIterator<Item = usize>,
    {
        for index in iter {
            self.currently_selected_variable_index = Some(index);
            let v = self.evaluate_expr(body).map_or(false, |v| v.to_bool());
            if let Some(result) = selection.add_result_and_check(v) {
                return Value::Boolean(result);
            }
        }
        Value::Boolean(selection.end())
    }

    fn evaluate_for_iterator(
        &mut self,
        iterator: &ForIterator,
        mut selection: ForSelectionEvaluator,
        body: &Expression,
    ) -> Option<Value> {
        let prev_stack_len = self.bounded_identifiers_stack.len();

        match iterator {
            ForIterator::ModuleIterator(expr) => {
                let value = module::evaluate_expr(self, expr)?;

                match value {
                    ModuleValue::Array(array) => {
                        for value in array {
                            self.bounded_identifiers_stack.push(Arc::new(value));
                            let v = self.evaluate_expr(body).map_or(false, |v| v.to_bool());
                            self.bounded_identifiers_stack.truncate(prev_stack_len);

                            if let Some(result) = selection.add_result_and_check(v) {
                                return Some(Value::Boolean(result));
                            }
                        }
                    }
                    ModuleValue::Dictionary(dict) => {
                        for (key, value) in dict {
                            self.bounded_identifiers_stack
                                .push(Arc::new(ModuleValue::Bytes(key)));
                            self.bounded_identifiers_stack.push(Arc::new(value));
                            let v = self.evaluate_expr(body).map_or(false, |v| v.to_bool());
                            self.bounded_identifiers_stack.truncate(prev_stack_len);

                            if let Some(result) = selection.add_result_and_check(v) {
                                return Some(Value::Boolean(result));
                            }
                        }
                    }
                    _ => return None,
                };

                Some(Value::Boolean(selection.end()))
            }
            ForIterator::Range { from, to } => {
                let from = self.evaluate_expr(from)?.unwrap_number()?;
                let to = self.evaluate_expr(to)?.unwrap_number()?;

                if from > to {
                    return None;
                }

                for value in from..=to {
                    self.bounded_identifiers_stack
                        .push(Arc::new(ModuleValue::Integer(value)));
                    let v = self.evaluate_expr(body).map_or(false, |v| v.to_bool());
                    self.bounded_identifiers_stack.truncate(prev_stack_len);

                    if let Some(result) = selection.add_result_and_check(v) {
                        return Some(Value::Boolean(result));
                    }
                }
                Some(Value::Boolean(selection.end()))
            }

            ForIterator::List(exprs) => {
                for expr in exprs {
                    let value = self.evaluate_expr(expr)?.unwrap_number()?;

                    self.bounded_identifiers_stack
                        .push(Arc::new(ModuleValue::Integer(value)));
                    let v = self.evaluate_expr(body).map_or(false, |v| v.to_bool());
                    self.bounded_identifiers_stack.truncate(prev_stack_len);

                    if let Some(result) = selection.add_result_and_check(v) {
                        return Some(Value::Boolean(result));
                    }
                }
                Some(Value::Boolean(selection.end()))
            }
        }
    }
}

fn eval_eq_values(left: Value, right: Value) -> Option<bool> {
    match (left, right) {
        (Value::Integer(n), Value::Integer(m)) => Some(n == m),
        (Value::Float(a), Value::Float(b)) => Some((a - b).abs() < f64::EPSILON),
        #[allow(clippy::cast_precision_loss)]
        (Value::Integer(n), Value::Float(a)) | (Value::Float(a), Value::Integer(n)) => {
            Some((a - (n as f64)).abs() < f64::EPSILON)
        }
        (Value::Bytes(a), Value::Bytes(b)) => Some(a == b),
        (Value::Boolean(a), Value::Boolean(b)) => Some(a == b),
        _ => None,
    }
}

/// Result of the evaluation of a for selection.
#[derive(Debug)]
enum ForSelectionEvaluation {
    /// An evaluator that accumulates evaluations of each variable, and return a result as early
    /// as possible.
    Evaluator(ForSelectionEvaluator),

    /// Result of the for selection if available immediately, without needing any evaluation.
    Value(Value),
}

/// Evaluator of a for selection
#[derive(Debug)]
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
