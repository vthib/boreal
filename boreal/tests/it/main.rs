// contains tests imported from libyara
mod libyara_compat;

// Custom module "tests"
mod module_tests;

// Tests related to errors in rules
mod error;

// Tests related to conversions of YARA regexes into rust ones.
mod regex;

// Tests related to evaluation of rules
mod evaluation;
mod external_symbol;
mod for_expression;
mod full;
mod modules;
mod namespaces;
mod undefined;
mod variables;

// Tests related to different limits set.
mod limits;

// Tests related to modules
#[cfg(feature = "object")]
mod elf;
#[cfg(feature = "object")]
mod macho;
mod math;
#[cfg(feature = "object")]
mod pe;

// utils to run tests both with boreal and with yara
mod utils;
