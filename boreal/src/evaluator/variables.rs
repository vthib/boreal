//! Implement scanning for variables
use crate::compiler::Variable;

use super::variable::Match;
use super::{ScanData, VariableEvaluation};

/// Variable evaluation context.
///
/// This is used to cache scan results for a single variable,
/// on a single input.
#[derive(Debug)]
pub(super) struct Variables<'scan, 'rule> {
    pub(super) variables: Vec<VariableEvaluation<'rule>>,

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
            variables: vars
                .iter()
                .enumerate()
                .map(|(i, var)| {
                    VariableEvaluation::new(
                        var,
                        scan_data.variable_set_matches.matched(set_index_offset + i),
                    )
                })
                .collect(),
            scan_data,
        }
    }

    pub fn find(&mut self, var_index: usize) -> bool {
        let var = &mut self.variables[var_index];

        if var.has_been_found {
            true
        } else {
            var.find(self.scan_data.mem).is_some()
        }
    }

    pub fn find_at(&mut self, var_index: usize, offset: usize) -> bool {
        let var = &mut self.variables[var_index];
        var.find_at(self.scan_data.mem, offset)
    }

    pub fn find_in(&mut self, var_index: usize, from: usize, to: usize) -> bool {
        let var = &mut self.variables[var_index];
        var.find_in(self.scan_data.mem, from, to)
    }

    pub fn count_matches_in(&mut self, var_index: usize, from: usize, to: usize) -> u64 {
        let var = &mut self.variables[var_index];
        var.count_matches_in(self.scan_data.mem, from, to)
    }

    pub fn count_matches(&mut self, var_index: usize) -> u64 {
        let var = &mut self.variables[var_index];
        var.count_matches(self.scan_data.mem)
    }

    pub fn find_match_occurence(
        &mut self,
        var_index: usize,
        occurence_number: usize,
    ) -> Option<Match> {
        let var = &mut self.variables[var_index];
        var.find_match_occurence(self.scan_data.mem, occurence_number)
    }
}
