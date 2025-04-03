//! Provides methods to evaluate expressions.
//!
//! Most evaluating methods return an `Result<Value, PoisonKind>`. The `PoisonKind` represents an
//! uncomputable value, which can have two different meanings depending on the evaluation pass.
//!
//! The first evaluation pass is used to find if there are variables that need to be searched.
//! For example, if all rules have a "filesize < 50KB" condition that short-circuit the whole
//! rule's evaluation, then we should not need to scan for variables on any mem that is bigger
//! than 50KB.
//!
//! During this evaluation pass, evaluation of anything related to variables returns its own
//! poison kind. This value is fully poisonous, and will be rethrown by basically all of the
//! operators, except for a few:
//!
//! - `and` returns false if one of the operands returned false, regardless of whether some of
//!   those were poisoned.
//! - `or` returns true if one of the operands returned true, regardless of whether some of
//!   those were poisoned.
//! - the for operands may return `true` or `false` if the result does not depend on any poison
//!   value.
//!
//! The second evaluation pass is used to fully evaluate the rules. During this pass, the poisong
//! kind used is the `undefined` value as described by YARA: it is used for all operations that
//! cannot be evaluated:
//!
//! - Symbols that do not make sense, eg `pe.entrypoint` on a non PE scan.
//! - Occurences numbers not found, eg `#a[100]`.
//! - Arithmetic operations that do not make sense, eg `1 << -5`
//! - etc
//!
//! The only operators that do not rethrow the poison value are:
//!
//! - `and` and `or`
//! - all `for` variants, both for the selection and the body.
//! - `defined`
//!
//! For all of those, an undefined value is considered to be equivalent to a false boolean value.
use crate::bytes_pool::BytesPool;
use crate::compiler::expression::{Expression, ForIterator, ForSelection, VariableIndex};
use crate::compiler::rule::Rule;
use crate::memory::Memory;
use crate::regex::Regex;
use crate::scanner::ScanData;
use memchr::memmem;

use crate::compiler::ExternalValue;
use crate::module::Value as ModuleValue;

mod error;
pub use error::EvalError;

pub(crate) mod module;

#[cfg(feature = "object")]
pub(crate) mod entrypoint;

mod read_integer;
use read_integer::evaluate_read_integer;
pub(crate) mod variable;

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

    fn unwrap_number(self) -> Result<i64, PoisonKind> {
        match self {
            Self::Integer(v) => Ok(v),
            _ => Err(PoisonKind::Undefined),
        }
    }

    fn unwrap_bytes(self) -> Result<Vec<u8>, PoisonKind> {
        match self {
            Self::Bytes(v) => Ok(v),
            _ => Err(PoisonKind::Undefined),
        }
    }
}

impl From<ExternalValue> for Value {
    fn from(v: ExternalValue) -> Self {
        match v {
            ExternalValue::Integer(v) => Value::Integer(v),
            ExternalValue::Float(v) => Value::Float(v),
            ExternalValue::Bytes(v) => Value::Bytes(v),
            ExternalValue::Boolean(v) => Value::Boolean(v),
        }
    }
}

/// Evaluates an expression on a given byte slice.
///
/// Returns true if the expression (with the associated variables) matches on the given
/// byte slice, false otherwise.
pub(crate) fn evaluate_rule<'scan>(
    rule: &Rule,
    var_matches: Option<&'scan [Vec<variable::StringMatch>]>,
    previous_rules_results: &'scan [bool],
    bytes_pool: &'scan BytesPool,
    mem: &'scan mut Memory,
    scan_data: &'scan mut ScanData,
) -> Result<bool, EvalError> {
    let mut evaluator = Evaluator {
        var_matches: var_matches.map(variable::VarMatches::new),
        previous_rules_results,
        currently_selected_variable_index: None,
        bounded_identifiers_stack: Vec::new(),
        bytes_pool,
        mem,
        scan_data,
    };
    match evaluator.evaluate_expr(&rule.condition) {
        Ok(v) => Ok(v.to_bool()),
        Err(PoisonKind::Undefined) => Ok(false),
        Err(PoisonKind::VarNeeded) => Err(EvalError::Undecidable),
        Err(PoisonKind::Timeout) => Err(EvalError::Timeout),
    }
}

struct Evaluator<'scan, 'rule, 'mem, 'cb> {
    var_matches: Option<variable::VarMatches<'rule>>,

    // Array of previous rules results.
    //
    // This only stores results of rules that are depended upon, not all rules.
    previous_rules_results: &'rule [bool],

    // Index of the currently selected variable.
    //
    // This is only set when in a for expression.
    currently_selected_variable_index: Option<usize>,

    // Stack of bounded identifiers to their integer values.
    bounded_identifiers_stack: Vec<ModuleValue>,

    // Bytes intern pool, used to resolve expressions that stored bytes in the pool.
    bytes_pool: &'rule BytesPool,

    mem: &'rule mut Memory<'mem>,

    // Data related only to the scan, independent of the rule.
    scan_data: &'rule mut ScanData<'scan, 'cb>,
}

#[derive(Debug)]
enum PoisonKind {
    /// The poison comes from the need to compute variables.
    ///
    /// This value should always be propagated, unless an operator result can be computed
    /// regardless of any value the poisonous value could take.
    ///
    /// This is used during the first evaluation pass, to find rules that do not depend on
    /// their variables' matches.
    VarNeeded,

    /// Yara undefined value.
    ///
    /// This value should generally be propagated, unless for a few operators that treat this value
    /// as false.
    ///
    /// This is used during the second evaluation pass, where it represents operations that
    /// could not be computed.
    Undefined,

    /// Evaluation timed out.
    ///
    /// This value should always be rethrown, no matter what, to end the execution asap.
    Timeout,
}

macro_rules! arith_op_num_and_float {
    ($self:expr, $left:expr, $right:expr, $op:tt, $wrapping_op:ident) => {{
        let left = $self.evaluate_expr($left)?;
        let right = $self.evaluate_expr($right)?;
        match (left, right) {
            (Value::Integer(n), Value::Integer(m)) => Ok(Value::Integer(n.$wrapping_op(m))),
            (Value::Float(a), Value::Integer(n)) => {
                #[allow(clippy::cast_precision_loss)]
                Ok(Value::Float(a $op (n as f64)))
            },
            (Value::Integer(n), Value::Float(a)) => {
                #[allow(clippy::cast_precision_loss)]
                Ok(Value::Float((n as f64) $op a))
            },
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a $op b)),
            (_, _) => Err(PoisonKind::Undefined),
        }
    }}
}

macro_rules! apply_cmp_op {
    ($left:expr, $right:expr, $op:tt) => {
        match ($left, $right) {
            (Value::Integer(n), Value::Integer(m)) => n $op m,
            (Value::Float(a), Value::Float(b)) => a $op b,
            #[allow(clippy::cast_precision_loss)]
            (Value::Integer(n), Value::Float(b)) => (n as f64) $op b,
            #[allow(clippy::cast_precision_loss)]
            (Value::Float(a), Value::Integer(m)) => a $op (m as f64),
            (Value::Bytes(a), Value::Bytes(b)) => a $op b,
            _ => return Err(PoisonKind::Undefined),
        }
    }
}

impl Evaluator<'_, '_, '_, '_> {
    fn get_variable_index(&self, var_index: VariableIndex) -> Result<usize, PoisonKind> {
        var_index
            .0
            .or(self.currently_selected_variable_index)
            .ok_or(PoisonKind::Undefined)
    }

    fn get_var_matches(&self) -> Result<&variable::VarMatches, PoisonKind> {
        self.var_matches.as_ref().ok_or(PoisonKind::VarNeeded)
    }

    fn compare_strings<F>(
        &mut self,
        left: &Expression,
        right: &Expression,
        case_insensitive: bool,
        cmp: F,
    ) -> Result<Value, PoisonKind>
    where
        F: Fn(&[u8], &[u8]) -> bool,
    {
        let left = self.evaluate_expr(left)?;
        let mut left = left.unwrap_bytes()?;
        let right = self.evaluate_expr(right)?;
        let mut right = right.unwrap_bytes()?;

        Ok(Value::Boolean(if case_insensitive {
            left.make_ascii_lowercase();
            right.make_ascii_lowercase();
            cmp(&left, &right)
        } else {
            cmp(&left, &right)
        }))
    }

    fn evaluate_expr(&mut self, expr: &Expression) -> Result<Value, PoisonKind> {
        if self.scan_data.check_timeout() {
            return Err(PoisonKind::Timeout);
        }

        match expr {
            Expression::Filesize => match self.mem.filesize() {
                Some(filesize) => Ok(Value::Integer(filesize.try_into().unwrap_or(i64::MAX))),
                None => Err(PoisonKind::Undefined),
            },

            #[cfg(feature = "object")]
            Expression::Entrypoint => {
                let res = match self.mem {
                    Memory::Direct(mem) => entrypoint::get_pe_or_elf_entry_point(
                        mem,
                        self.scan_data.params.process_memory,
                    ),
                    Memory::Fragmented { .. } => self.scan_data.entrypoint,
                };
                res.and_then(|ep| i64::try_from(ep).ok())
                    .map(Value::Integer)
                    .ok_or(PoisonKind::Undefined)
            }
            #[cfg(not(feature = "object"))]
            Expression::Entrypoint => Err(PoisonKind::Undefined),

            Expression::ReadInteger { addr, ty } => evaluate_read_integer(self, addr, *ty),

            Expression::CountInRange {
                variable_index,
                from,
                to,
            } => {
                let from = self.evaluate_expr(from)?.unwrap_number()?;
                let to = self.evaluate_expr(to)?.unwrap_number()?;

                let from = usize::try_from(from).unwrap_or(0);
                let to = usize::try_from(to).unwrap_or(0);

                let var_index = self.get_variable_index(*variable_index)?;
                let count = self
                    .get_var_matches()
                    .map(|var_matches| var_matches.count_matches_in(var_index, from, to))?;

                Ok(Value::Integer(count.into()))
            }
            Expression::Count(variable_index) => {
                let var_index = self.get_variable_index(*variable_index)?;
                let count = self
                    .get_var_matches()
                    .map(|var_matches| var_matches.count_matches(var_index))?;

                Ok(Value::Integer(count.into()))
            }
            Expression::Offset {
                variable_index,
                occurence_number,
            } => {
                let occurence_number = self.evaluate_expr(occurence_number)?.unwrap_number()?;

                match usize::try_from(occurence_number) {
                    Ok(v) if v != 0 => {
                        let var_index = self.get_variable_index(*variable_index)?;
                        let mat = self.get_var_matches().map(|var_matches| {
                            var_matches.find_match_occurence(var_index, v - 1)
                        })?;

                        mat.and_then(|mat| mat.offset.checked_add(mat.base))
                            .and_then(|offset| i64::try_from(offset).ok())
                            .map(Value::Integer)
                            .ok_or(PoisonKind::Undefined)
                    }
                    Ok(_) | Err(_) => Err(PoisonKind::Undefined),
                }
            }
            Expression::Length {
                variable_index,
                occurence_number,
            } => {
                let occurence_number = self.evaluate_expr(occurence_number)?.unwrap_number()?;

                match usize::try_from(occurence_number) {
                    Ok(v) if v != 0 => {
                        let var_index = self.get_variable_index(*variable_index)?;
                        let mat = self.get_var_matches().map(|var_matches| {
                            var_matches.find_match_occurence(var_index, v - 1)
                        })?;

                        mat.and_then(|mat| i64::try_from(mat.length).ok())
                            .map(Value::Integer)
                            .ok_or(PoisonKind::Undefined)
                    }
                    Ok(_) | Err(_) => Err(PoisonKind::Undefined),
                }
            }

            Expression::Neg(expr) => {
                let v = self.evaluate_expr(expr)?;

                match v {
                    Value::Integer(n) => Ok(Value::Integer(-n)),
                    Value::Float(a) => Ok(Value::Float(-a)),
                    _ => Err(PoisonKind::Undefined),
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
                            Err(PoisonKind::Undefined)
                        } else {
                            n.checked_div(m)
                                .map(Value::Integer)
                                .ok_or(PoisonKind::Undefined)
                        }
                    }
                    (Value::Float(a), Value::Integer(n)) =>
                    {
                        #[allow(clippy::cast_precision_loss)]
                        Ok(Value::Float(a / (n as f64)))
                    }
                    (Value::Integer(n), Value::Float(a)) =>
                    {
                        #[allow(clippy::cast_precision_loss)]
                        Ok(Value::Float((n as f64) / a))
                    }
                    (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a / b)),
                    (_, _) => Err(PoisonKind::Undefined),
                }
            }
            Expression::Mod(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                left.checked_rem(right)
                    .map(Value::Integer)
                    .ok_or(PoisonKind::Undefined)
            }

            Expression::BitwiseXor(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Ok(Value::Integer(left ^ right))
            }
            Expression::BitwiseAnd(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Ok(Value::Integer(left & right))
            }
            Expression::BitwiseOr(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                Ok(Value::Integer(left | right))
            }
            Expression::BitwiseNot(expr) => {
                let v = self.evaluate_expr(expr)?.unwrap_number()?;
                Ok(Value::Integer(!v))
            }
            Expression::ShiftLeft(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                if right < 0 {
                    Err(PoisonKind::Undefined)
                } else if right >= 64 {
                    Ok(Value::Integer(0))
                } else {
                    Ok(Value::Integer(left << right))
                }
            }
            Expression::ShiftRight(left, right) => {
                let left = self.evaluate_expr(left)?.unwrap_number()?;
                let right = self.evaluate_expr(right)?.unwrap_number()?;
                if right < 0 {
                    Err(PoisonKind::Undefined)
                } else if right >= 64 {
                    Ok(Value::Integer(0))
                } else {
                    Ok(Value::Integer(left >> right))
                }
            }

            Expression::And(ops) => {
                let mut var_needed = false;

                for op in ops {
                    match self.evaluate_expr(op) {
                        Ok(v) => {
                            if !v.to_bool() {
                                return Ok(Value::Boolean(false));
                            }
                        }
                        Err(PoisonKind::Undefined) => return Ok(Value::Boolean(false)),
                        Err(PoisonKind::VarNeeded) => var_needed = true,
                        Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
                    }
                }
                if var_needed {
                    Err(PoisonKind::VarNeeded)
                } else {
                    Ok(Value::Boolean(true))
                }
            }
            Expression::Or(ops) => {
                let mut var_needed = false;

                for op in ops {
                    match self.evaluate_expr(op) {
                        Ok(v) => {
                            if v.to_bool() {
                                return Ok(Value::Boolean(true));
                            }
                        }
                        Err(PoisonKind::Undefined) => (),
                        Err(PoisonKind::VarNeeded) => var_needed = true,
                        Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
                    }
                }
                if var_needed {
                    Err(PoisonKind::VarNeeded)
                } else {
                    Ok(Value::Boolean(false))
                }
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
            } => self.compare_strings(haystack, needle, *case_insensitive, |a, b| {
                memmem::find(a, b).is_some()
            }),
            Expression::StartsWith {
                expr,
                prefix,
                case_insensitive,
            } => self.compare_strings(expr, prefix, *case_insensitive, <[u8]>::starts_with),
            Expression::EndsWith {
                expr,
                suffix,
                case_insensitive,
            } => self.compare_strings(expr, suffix, *case_insensitive, <[u8]>::ends_with),

            Expression::IEquals(left, right) => {
                let mut left = self.evaluate_expr(left)?.unwrap_bytes()?;
                left.make_ascii_lowercase();
                let mut right = self.evaluate_expr(right)?.unwrap_bytes()?;
                right.make_ascii_lowercase();
                Ok(Value::Boolean(left == right))
            }
            Expression::Matches(expr, regex) => {
                let s = self.evaluate_expr(expr)?.unwrap_bytes()?;
                Ok(Value::Boolean(regex.is_match(&s)))
            }
            Expression::Defined(expr) => match self.evaluate_expr(expr) {
                Ok(_) => Ok(Value::Boolean(true)),
                Err(PoisonKind::Undefined) => Ok(Value::Boolean(false)),
                Err(e) => Err(e),
            },
            Expression::Not(expr) => {
                let v = self.evaluate_expr(expr)?.to_bool();
                Ok(Value::Boolean(!v))
            }

            Expression::Variable(variable_index) => {
                // For this expression, we can use the variables set to retrieve the truth value,
                // no need to rescan.
                let var_index = self.get_variable_index(*variable_index)?;
                self.get_var_matches()
                    .map(|var_matches| var_matches.find(var_index))
                    .map(Value::Boolean)
            }

            Expression::VariableAt {
                variable_index,
                offset,
            } => {
                // Safety: index has been generated during compilation and is valid.
                let offset = self.evaluate_expr(offset)?.unwrap_number()?;
                match usize::try_from(offset) {
                    Ok(offset) => {
                        let var_index = self.get_variable_index(*variable_index)?;
                        self.get_var_matches()
                            .map(|var_matches| var_matches.find_at(var_index, offset))
                            .map(Value::Boolean)
                    }
                    Err(_) => Ok(Value::Boolean(false)),
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
                        let var_index = self.get_variable_index(*variable_index)?;
                        self.get_var_matches()
                            .map(|var_matches| var_matches.find_in(var_index, from, to))
                            .map(Value::Boolean)
                    }
                    _ => Ok(Value::Boolean(false)),
                }
            }

            Expression::For {
                selection,
                set,
                body,
            } => {
                let selection = match self.evaluate_for_selection(selection, set.elements.len())? {
                    ForSelectionEvaluation::Evaluator(e) => e,
                    ForSelectionEvaluation::Value(v) => return Ok(v),
                };

                let prev_selected_var_index = self.currently_selected_variable_index;
                let result = self.evaluate_for_var(selection, body, set.elements.iter().copied());
                self.currently_selected_variable_index = prev_selected_var_index;

                result
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
                let selection = match self.evaluate_for_selection(selection, 0)? {
                    ForSelectionEvaluation::Evaluator(e) => e,
                    ForSelectionEvaluation::Value(v) => return Ok(v),
                };

                match self.evaluate_for_iterator(iterator, selection, body) {
                    Ok(v) => Ok(v),
                    Err(PoisonKind::Undefined) => Ok(Value::Boolean(false)),
                    Err(e) => Err(e),
                }
            }

            Expression::ForRules { selection, set } => {
                let nb_elements = set.elements.len() + set.already_matched;

                let mut selection = match self.evaluate_for_selection(selection, nb_elements)? {
                    ForSelectionEvaluation::Evaluator(e) => e,
                    ForSelectionEvaluation::Value(v) => return Ok(v),
                };

                for _ in 0..set.already_matched {
                    if let Some(result) = selection.add_result_and_check(true) {
                        return Ok(Value::Boolean(result));
                    }
                }

                for index in &set.elements {
                    let v = self.previous_rules_results[*index];
                    if let Some(result) = selection.add_result_and_check(v) {
                        return Ok(Value::Boolean(result));
                    }
                }

                selection.end(0)
            }

            Expression::Module(module_expr) => module::evaluate_expr(self, module_expr)
                .and_then(module::module_value_to_expr_value),

            Expression::ExternalSymbol(index) => self
                .scan_data
                .external_symbols_values
                .get(*index)
                .cloned()
                .map(Into::into)
                .ok_or(PoisonKind::Undefined),

            Expression::Rule(index) => Ok(Value::Boolean(self.previous_rules_results[*index])),

            Expression::Integer(v) => Ok(Value::Integer(*v)),
            Expression::Double(v) => Ok(Value::Float(*v)),
            Expression::Bytes(v) => Ok(Value::Bytes(self.bytes_pool.get(*v).to_vec())),
            Expression::Regex(v) => Ok(Value::Regex(v.clone())),
            Expression::Boolean(v) => Ok(Value::Boolean(*v)),
        }
    }

    fn evaluate_for_selection(
        &mut self,
        selection: &ForSelection,
        nb_elements: usize,
    ) -> Result<ForSelectionEvaluation, PoisonKind> {
        use ForSelectionEvaluation as FSEvaluation;
        use ForSelectionEvaluator as FSEvaluator;

        match selection {
            ForSelection::Any => Ok(FSEvaluation::Evaluator(FSEvaluator::Number(1))),
            ForSelection::All => Ok(FSEvaluation::Evaluator(FSEvaluator::All)),
            ForSelection::None => Ok(FSEvaluation::Evaluator(FSEvaluator::None)),
            ForSelection::Expr { expr, as_percent } => {
                let mut value = match self.evaluate_expr(expr).and_then(Value::unwrap_number) {
                    Ok(v) => v,
                    Err(PoisonKind::Undefined) => {
                        return Ok(FSEvaluation::Value(Value::Boolean(false)))
                    }
                    Err(e) => return Err(e),
                };

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
                    return Ok(FSEvaluation::Evaluator(FSEvaluator::None));
                }

                if value <= 0 {
                    Ok(FSEvaluation::Value(Value::Boolean(true)))
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    let value = { value as u64 };
                    Ok(FSEvaluation::Evaluator(FSEvaluator::Number(value)))
                }
            }
        }
    }

    fn evaluate_for_var<I>(
        &mut self,
        mut selection: ForSelectionEvaluator,
        body: &Expression,
        iter: I,
    ) -> Result<Value, PoisonKind>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut nb_vars_needed = 0;

        for index in iter {
            self.currently_selected_variable_index = Some(index);
            let v = match self.evaluate_expr(body) {
                Ok(v) => v.to_bool(),
                Err(PoisonKind::Undefined) => false,
                Err(PoisonKind::VarNeeded) => {
                    nb_vars_needed += 1;
                    continue;
                }
                Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
            };

            if let Some(result) = selection.add_result_and_check(v) {
                return Ok(Value::Boolean(result));
            }
        }

        selection.end(nb_vars_needed)
    }

    fn evaluate_for_iterator(
        &mut self,
        iterator: &ForIterator,
        mut selection: ForSelectionEvaluator,
        body: &Expression,
    ) -> Result<Value, PoisonKind> {
        let mut nb_vars_needed = 0;
        let prev_stack_len = self.bounded_identifiers_stack.len();

        let selection = match iterator {
            ForIterator::ModuleIterator(expr) => {
                let value = module::evaluate_expr(self, expr)?;

                match value {
                    ModuleValue::Array(array) => {
                        for value in array {
                            self.bounded_identifiers_stack.push(value);
                            let v = self.evaluate_expr(body);
                            self.bounded_identifiers_stack.truncate(prev_stack_len);
                            let v = match v {
                                Ok(v) => v.to_bool(),
                                Err(PoisonKind::Undefined) => false,
                                Err(PoisonKind::VarNeeded) => {
                                    nb_vars_needed += 1;
                                    continue;
                                }
                                Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
                            };

                            if let Some(result) = selection.add_result_and_check(v) {
                                return Ok(Value::Boolean(result));
                            }
                        }
                    }
                    ModuleValue::Dictionary(dict) => {
                        for (key, value) in dict {
                            self.bounded_identifiers_stack.push(ModuleValue::Bytes(key));
                            self.bounded_identifiers_stack.push(value);
                            let v = self.evaluate_expr(body);
                            self.bounded_identifiers_stack.truncate(prev_stack_len);
                            let v = match v {
                                Ok(v) => v.to_bool(),
                                Err(PoisonKind::Undefined) => false,
                                Err(PoisonKind::VarNeeded) => {
                                    nb_vars_needed += 1;
                                    continue;
                                }
                                Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
                            };

                            if let Some(result) = selection.add_result_and_check(v) {
                                return Ok(Value::Boolean(result));
                            }
                        }
                    }
                    _ => return Err(PoisonKind::Undefined),
                }

                selection
            }
            ForIterator::Range { from, to } => {
                let from = self.evaluate_expr(from)?.unwrap_number()?;
                let to = self.evaluate_expr(to)?.unwrap_number()?;

                if from > to {
                    return Err(PoisonKind::Undefined);
                }

                for value in from..=to {
                    self.bounded_identifiers_stack
                        .push(ModuleValue::Integer(value));
                    let v = self.evaluate_expr(body);
                    self.bounded_identifiers_stack.truncate(prev_stack_len);
                    let v = match v {
                        Ok(v) => v.to_bool(),
                        Err(PoisonKind::Undefined) => false,
                        Err(PoisonKind::VarNeeded) => {
                            nb_vars_needed += 1;
                            continue;
                        }
                        Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
                    };

                    if let Some(result) = selection.add_result_and_check(v) {
                        return Ok(Value::Boolean(result));
                    }
                }
                selection
            }

            ForIterator::List(exprs) => {
                for expr in exprs {
                    match self.evaluate_expr(expr)? {
                        Value::Integer(value) => {
                            self.bounded_identifiers_stack
                                .push(ModuleValue::Integer(value));
                        }
                        Value::Bytes(value) => {
                            self.bounded_identifiers_stack
                                .push(ModuleValue::Bytes(value));
                        }
                        _ => return Err(PoisonKind::Undefined),
                    }
                    let v = self.evaluate_expr(body);
                    self.bounded_identifiers_stack.truncate(prev_stack_len);
                    let v = match v {
                        Ok(v) => v.to_bool(),
                        Err(PoisonKind::Undefined) => false,
                        Err(PoisonKind::VarNeeded) => {
                            nb_vars_needed += 1;
                            continue;
                        }
                        Err(PoisonKind::Timeout) => return Err(PoisonKind::Timeout),
                    };

                    if let Some(result) = selection.add_result_and_check(v) {
                        return Ok(Value::Boolean(result));
                    }
                }
                selection
            }
        };

        selection.end(nb_vars_needed)
    }
}

fn eval_eq_values(left: Value, right: Value) -> Result<bool, PoisonKind> {
    match (left, right) {
        (Value::Integer(n), Value::Integer(m)) => Ok(n == m),
        (Value::Float(a), Value::Float(b)) => Ok((a - b).abs() < f64::EPSILON),
        #[allow(clippy::cast_precision_loss)]
        (Value::Integer(n), Value::Float(a)) | (Value::Float(a), Value::Integer(n)) => {
            Ok((a - (n as f64)).abs() < f64::EPSILON)
        }
        (Value::Bytes(a), Value::Bytes(b)) => Ok(a == b),
        (Value::Boolean(a), Value::Boolean(b)) => Ok(a == b),
        _ => Err(PoisonKind::Undefined),
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
    ///
    /// `nb_vars_needed` indicates how many evaluations were not taken into account because it
    /// needed var matches computation. A result should only be returned if the value cannot change
    /// depending on any value those evaluations can take.
    fn end(self, nb_vars_needed: u64) -> Result<Value, PoisonKind> {
        match self {
            Self::All | Self::None if nb_vars_needed > 0 => Err(PoisonKind::VarNeeded),
            Self::All | Self::None => Ok(Value::Boolean(true)),
            Self::Number(n) if nb_vars_needed >= n => Err(PoisonKind::VarNeeded),
            Self::Number(_) => Ok(Value::Boolean(false)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits(Value::Integer(0));
        test_type_traits_non_clonable(ForSelectionEvaluation::Value(Value::Integer(0)));
        test_type_traits_non_clonable(ForSelectionEvaluator::None);
        test_type_traits_non_clonable(PoisonKind::Undefined);
    }
}
