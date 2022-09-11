//! Implement scanning for variables
use crate::compiler::Variable;
use crate::variable_set::SetResult;

use super::variable::Match;
use super::{ScanData, VariableEvaluation};

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
#[derive(Debug)]
pub(super) struct Variables<'scan, 'rule> {
    pub(super) variables: Vec<VariableEvaluation<'rule>>,

    /// Offset into the variables_matches for the variables of this rule.
    set_index_offset: usize,

    /// Data related only to the scan, independent of the rule.
    scan_data: &'scan ScanData<'scan>,
}

impl<'scan, 'rule> Variables<'scan, 'rule> {
    pub fn new(
        vars: &'rule [Variable],
        set_index_offset: usize,
        scan_data: &'scan ScanData<'scan>,
    ) -> Self {
        Self {
            variables: vars.iter().map(VariableEvaluation::new).collect(),
            set_index_offset,
            scan_data,
        }
    }

    pub fn find(&mut self, var_index: usize) -> bool {
        let set_result = self.variable_set_result(var_index);

        // Safety: index has been either:
        // - generated during compilation and is thus valid.
        // - retrieve from the currently selected variable, and thus valid.
        let var = &mut self.variables[var_index];

        match set_result {
            SetResult::NotFound => false,
            SetResult::Found if !var.need_full_matches() => true,
            _ => var.find(self.scan_data.mem).is_some(),
        }
    }

    pub fn find_at(&mut self, var_index: usize, offset: usize) -> bool {
        match self.variable_set_result(var_index) {
            SetResult::NotFound => false,
            SetResult::Found | SetResult::Unknown => {
                let var = &mut self.variables[var_index];
                var.find_at(self.scan_data.mem, offset)
            }
        }
    }

    pub fn find_in(&mut self, var_index: usize, from: usize, to: usize) -> bool {
        match self.variable_set_result(var_index) {
            SetResult::NotFound => false,
            SetResult::Found | SetResult::Unknown => {
                let var = &mut self.variables[var_index];
                var.find_in(self.scan_data.mem, from, to)
            }
        }
    }

    pub fn count_matches_in(&mut self, var_index: usize, from: usize, to: usize) -> u64 {
        match self.variable_set_result(var_index) {
            SetResult::NotFound => 0,
            SetResult::Unknown | SetResult::Found => {
                let var = &mut self.variables[var_index];
                var.count_matches_in(self.scan_data.mem, from, to)
            }
        }
    }

    pub fn count_matches(&mut self, var_index: usize) -> u64 {
        match self.variable_set_result(var_index) {
            SetResult::NotFound => 0,
            SetResult::Unknown | SetResult::Found => {
                let var = &mut self.variables[var_index];
                var.count_matches(self.scan_data.mem)
            }
        }
    }

    pub fn find_match_occurence(
        &mut self,
        var_index: usize,
        occurence_number: usize,
    ) -> Option<Match> {
        match self.variable_set_result(var_index) {
            SetResult::NotFound => None,
            SetResult::Unknown | SetResult::Found => {
                let var = &mut self.variables[var_index];
                var.find_match_occurence(self.scan_data.mem, occurence_number)
            }
        }
    }

    fn variable_set_result(&self, var_index: usize) -> SetResult {
        self.scan_data
            .variable_set_matches
            .matched(self.set_index_offset + var_index)
    }
}
