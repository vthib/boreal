// contains tests imported from libyara
mod libyara_compat;

// Custom module "tests"
mod module_tests;

// Tests related to evaluation of rules
mod evaluation;
mod for_expression;
mod modules;
mod namespaces;
mod variables;

// Tests related to modules
mod macho;

// utils to run tests both with boreal and with yara
mod utils;
