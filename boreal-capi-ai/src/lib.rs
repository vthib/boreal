//! C API for boreal, providing a drop-in replacement for libyara.
#![allow(unsafe_code)]
#![allow(missing_docs)]

mod compiler;
mod rules;
mod scanner;

use std::ffi::c_int;
use std::sync::Mutex;

// Error codes
pub(crate) const ERROR_SUCCESS: c_int = 0;
pub(crate) const ERROR_COULD_NOT_ATTACH_TO_PROCESS: c_int = 2;
pub(crate) const ERROR_COULD_NOT_OPEN_FILE: c_int = 3;
pub(crate) const ERROR_SCAN_TIMEOUT: c_int = 26;
pub(crate) const ERROR_INVALID_ARGUMENT: c_int = 29;
pub(crate) const ERROR_INTERNAL_FATAL_ERROR: c_int = 31;
pub(crate) const ERROR_UNSUPPORTED: c_int = 65;

// Callback message constants
pub(crate) const CALLBACK_MSG_RULE_MATCHING: c_int = 1;
pub(crate) const CALLBACK_MSG_RULE_NOT_MATCHING: c_int = 2;
pub(crate) const CALLBACK_MSG_SCAN_FINISHED: c_int = 3;
pub(crate) const CALLBACK_MSG_IMPORT_MODULE: c_int = 4;
pub(crate) const CALLBACK_MSG_MODULE_IMPORTED: c_int = 5;
pub(crate) const CALLBACK_MSG_TOO_MANY_MATCHES: c_int = 6;
pub(crate) const CALLBACK_MSG_CONSOLE_LOG: c_int = 7;

// Callback return values
pub(crate) const CALLBACK_CONTINUE: c_int = 0;

// Scan flags
pub(crate) const SCAN_FLAGS_FAST_MODE: c_int = 1;
pub(crate) const SCAN_FLAGS_PROCESS_MEMORY: c_int = 2;
pub(crate) const SCAN_FLAGS_REPORT_RULES_NOT_MATCHING: c_int = 16;

// Configuration name enum values
const YR_CONFIG_STACK_SIZE: c_int = 0;
const YR_CONFIG_MAX_STRINGS_PER_RULE: c_int = 1;
const YR_CONFIG_MAX_MATCH_DATA: c_int = 2;
const YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK: c_int = 3;

// Global configuration state
pub(crate) struct GlobalConfig {
    pub max_match_data: Option<usize>,
    pub max_process_memory_chunk: Option<usize>,
    pub stack_size: u32,
    pub max_strings_per_rule: u32,
}

pub(crate) static GLOBAL_CONFIG: Mutex<GlobalConfig> = Mutex::new(GlobalConfig {
    max_match_data: None,
    max_process_memory_chunk: None,
    stack_size: 16384,
    max_strings_per_rule: 10000,
});

/// Wrapper to make a raw pointer Send + Sync + UnwindSafe + RefUnwindSafe for use in closures.
///
/// # Safety
///
/// The caller is responsible for ensuring the pointer is used correctly across thread boundaries.
#[derive(Clone, Copy)]
pub(crate) struct RawPtr(pub *mut std::ffi::c_void);

impl RawPtr {
    /// Returns the inner pointer. Use this method in closures to force capture of the whole
    /// `RawPtr` struct (with its Send+Sync impls) rather than the inner `*mut c_void` field
    /// (which is not Send+Sync). This matters for edition 2021+ disjoint closure capture.
    pub(crate) fn get(self) -> *mut std::ffi::c_void {
        self.0
    }
}

// SAFETY: The YARA API contract requires that callbacks are called only from the scanning thread.
unsafe impl Send for RawPtr {}
unsafe impl Sync for RawPtr {}
impl std::panic::UnwindSafe for RawPtr {}
impl std::panic::RefUnwindSafe for RawPtr {}

#[unsafe(no_mangle)]
pub extern "C" fn yr_initialize() -> c_int {
    std::panic::catch_unwind(yr_initialize_inner).unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_initialize_inner() -> c_int {
    ERROR_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_finalize() -> c_int {
    std::panic::catch_unwind(yr_finalize_inner).unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_finalize_inner() -> c_int {
    ERROR_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_set_configuration(name: c_int, src: *mut std::ffi::c_void) -> c_int {
    std::panic::catch_unwind(|| yr_set_configuration_inner(name, src))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_set_configuration_inner(name: c_int, src: *mut std::ffi::c_void) -> c_int {
    if src.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    match name {
        YR_CONFIG_STACK_SIZE => {
            let value = unsafe { *(src as *const u32) };
            let Ok(mut cfg) = GLOBAL_CONFIG.lock() else {
                return ERROR_INTERNAL_FATAL_ERROR;
            };
            cfg.stack_size = value;
            ERROR_SUCCESS
        }
        YR_CONFIG_MAX_STRINGS_PER_RULE => {
            let value = unsafe { *(src as *const u32) };
            let Ok(mut cfg) = GLOBAL_CONFIG.lock() else {
                return ERROR_INTERNAL_FATAL_ERROR;
            };
            cfg.max_strings_per_rule = value;
            ERROR_SUCCESS
        }
        YR_CONFIG_MAX_MATCH_DATA => {
            let value = unsafe { *(src as *const u32) };
            let Ok(mut cfg) = GLOBAL_CONFIG.lock() else {
                return ERROR_INTERNAL_FATAL_ERROR;
            };
            cfg.max_match_data = Some(value as usize);
            ERROR_SUCCESS
        }
        YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK => {
            let value = unsafe { *(src as *const u64) };
            let Ok(mut cfg) = GLOBAL_CONFIG.lock() else {
                return ERROR_INTERNAL_FATAL_ERROR;
            };
            cfg.max_process_memory_chunk = Some(value as usize);
            ERROR_SUCCESS
        }
        _ => ERROR_INVALID_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_set_configuration_uint32(name: c_int, value: u32) -> c_int {
    std::panic::catch_unwind(|| yr_set_configuration_inner(name, &raw const value as *mut _))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_set_configuration_uint64(name: c_int, value: u64) -> c_int {
    std::panic::catch_unwind(|| yr_set_configuration_inner(name, &raw const value as *mut _))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_get_configuration(name: c_int, dest: *mut std::ffi::c_void) -> c_int {
    std::panic::catch_unwind(|| yr_get_configuration_inner(name, dest))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_get_configuration_inner(name: c_int, dest: *mut std::ffi::c_void) -> c_int {
    if dest.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    let Ok(cfg) = GLOBAL_CONFIG.lock() else {
        return ERROR_INTERNAL_FATAL_ERROR;
    };
    match name {
        YR_CONFIG_STACK_SIZE => {
            unsafe { *(dest as *mut u32) = cfg.stack_size };
            ERROR_SUCCESS
        }
        YR_CONFIG_MAX_STRINGS_PER_RULE => {
            unsafe { *(dest as *mut u32) = cfg.max_strings_per_rule };
            ERROR_SUCCESS
        }
        YR_CONFIG_MAX_MATCH_DATA => {
            let value = cfg.max_match_data.unwrap_or(512) as u32;
            unsafe { *(dest as *mut u32) = value };
            ERROR_SUCCESS
        }
        YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK => {
            let value = cfg.max_process_memory_chunk.unwrap_or(1073741824) as u64;
            unsafe { *(dest as *mut u64) = value };
            ERROR_SUCCESS
        }
        _ => ERROR_INVALID_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_get_configuration_uint32(name: c_int, dest: *mut u32) -> c_int {
    std::panic::catch_unwind(|| yr_get_configuration_inner(name, dest as *mut _))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_get_configuration_uint64(name: c_int, dest: *mut u64) -> c_int {
    std::panic::catch_unwind(|| yr_get_configuration_inner(name, dest as *mut _))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}
