#![allow(missing_docs)]
#![allow(unused_results)]
#![allow(unused_crate_dependencies)]
#![allow(unsafe_code)]

// contains tests imported from libyara
mod libyara_compat;

// Custom module "tests"
mod module_tests;

// Tests related to errors and warnings in rules
mod error;
mod warning;

// Tests related to conversions of YARA regexes into rust ones.
mod regex;

// Tests for the public API
mod api;

// Tests related to evaluation of rules
mod evaluation;
mod external_symbol;
mod for_expression;
mod full;
mod modules;
mod namespaces;
mod undefined;
mod variables;

// Tests related to scanning of fragmented memory
mod fragmented;

// Tests related to different limits set.
mod limits;

// Tests related to process memory scanning
#[cfg(feature = "process")]
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod process;

// Tests related to modules
#[cfg(feature = "object")]
mod dex;
#[cfg(feature = "object")]
mod dotnet;
#[cfg(feature = "object")]
mod elf;
#[cfg(feature = "object")]
mod macho;
mod math;
#[cfg(feature = "object")]
mod pe;
mod string;

#[cfg(feature = "hash")]
mod hash;

#[cfg(feature = "magic")]
mod magic;

#[cfg(feature = "cuckoo")]
mod cuckoo;

// utils to run tests both with boreal and with yara
mod utils;
