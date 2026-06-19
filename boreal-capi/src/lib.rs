//! C-API for the boreal crate.
//!
//! TODO
#![allow(unsafe_code)]
// FIXME
#![allow(missing_docs)]

use std::ffi::c_int;

pub mod compiler;
pub mod error;
pub mod rules;
pub mod scanner;

/// Compiled YARA rules.
pub struct YrRules {
    scanner: boreal::Scanner,
}

const ERROR_SUCCESS: c_int = 0;

/// Initialize the library.
// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
pub extern "C" fn yr_initialize() -> c_int {
    ERROR_SUCCESS
}

/// Deinitialize the library.
// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
pub extern "C" fn yr_finalize() -> c_int {
    ERROR_SUCCESS
}
