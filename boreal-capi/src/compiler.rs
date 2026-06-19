use std::ffi::{CStr, c_char, c_int, c_void};

use crate::YrRules;
use crate::error::{ERROR_INTERNAL_FATAL_ERROR, ERROR_INVALID_ARGUMENT, ERROR_SUCCESS};

pub struct YrCompiler {
    compiler: Option<boreal::Compiler>,
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety: The outer pointer must be valid.
pub unsafe extern "C" fn yr_compiler_create(compiler: *mut *mut YrCompiler) -> c_int {
    std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let compiler = unsafe { &mut *compiler };
        yr_compiler_create_inner(compiler)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_create_inner(out: &mut *mut YrCompiler) -> c_int {
    let compiler = Box::new(YrCompiler {
        compiler: Some(boreal::Compiler::new()),
    });
    *out = Box::into_raw(compiler);
    ERROR_SUCCESS
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety: The passed pointer must be valid, and must have been created by `yr_compiler_create`.
pub unsafe extern "C" fn yr_compiler_destroy(compiler: *mut YrCompiler) {
    let _r = std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let compiler = unsafe { Box::from_raw(compiler) };
        drop(compiler);
    });
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety:
// - The passed pointer must be valid, and must have been created by `yr_compiler_create`.
// - The rules_data + rules_size must point to a valid array of `rules_size` bytes.
// - The namespace pointer must point to a valid c-string, or be NULL.
// - The function modifies the compiler object and thus must not be called in parallel
//   with another function that also modifies the object.
pub unsafe extern "C" fn yr_compiler_add_bytes(
    compiler: *mut YrCompiler,
    rules_data: *const c_void,
    rules_size: usize,
    namespace: *const c_char,
) -> c_int {
    std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let compiler = unsafe { &mut *compiler };
        // Safety: see function safety constraint
        let rules = unsafe { std::slice::from_raw_parts(rules_data.cast(), rules_size) };
        let namespace = if namespace.is_null() {
            None
        } else {
            // Safety: see function safety constraint
            Some(unsafe { CStr::from_ptr(namespace) })
        };
        yr_compiler_add_bytes_inner(compiler, rules, namespace)
    })
    .unwrap_or(1)
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety:
// - The passed pointer must be valid, and must have been created by `yr_compiler_create`.
// - The rules_string pointer must point to a valid c-string.
// - The namespace pointer must point to a valid c-string, or be NULL.
// - The function modifies the compiler object and thus must not be called in parallel
//   with another function that also modifies the object.
pub unsafe extern "C" fn yr_compiler_add_string(
    compiler: *mut YrCompiler,
    rules_string: *const c_char,
    namespace: *const c_char,
) -> c_int {
    std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let compiler = unsafe { &mut *compiler };
        // Safety: see function safety constraint
        let rules = unsafe { CStr::from_ptr(rules_string) };
        let namespace = if namespace.is_null() {
            None
        } else {
            // Safety: see function safety constraint
            Some(unsafe { CStr::from_ptr(namespace) })
        };
        yr_compiler_add_bytes_inner(compiler, rules.to_bytes(), namespace)
    })
    .unwrap_or(1)
}

fn yr_compiler_add_bytes_inner(
    compiler: &mut YrCompiler,
    rules: &[u8],
    namespace: Option<&CStr>,
) -> c_int {
    let Some(compiler) = compiler.compiler.as_mut() else {
        return 1;
    };
    let ns = match namespace {
        Some(ns) => match ns.to_str() {
            Ok(ns) => Some(ns),
            Err(_) => return 1,
        },
        None => None,
    };

    match std::str::from_utf8(rules) {
        Ok(rules) => {
            let res = match ns {
                Some(ns) => compiler.add_rules_str_in_namespace(rules, ns),
                None => compiler.add_rules_str(rules),
            };
            match res {
                Ok(_) => 0,
                Err(_) => 1,
            }
        }
        Err(_) => 1,
    }
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// - The `compiler` pointer must be valid, and must have been created by `yr_compiler_create`.
// - The `rules` pointer must be valid.
pub unsafe extern "C" fn yr_compiler_get_rules(
    compiler: *mut YrCompiler,
    rules: *mut *mut YrRules,
) -> c_int {
    std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let compiler = unsafe { &mut *compiler };
        // Safety: see function safety constraint
        let rules = unsafe { &mut *rules };
        yr_compiler_get_rules_inner(compiler, rules)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_get_rules_inner(compiler: &mut YrCompiler, out: &mut *mut YrRules) -> c_int {
    let Some(compiler) = compiler.compiler.take() else {
        return ERROR_INVALID_ARGUMENT;
    };
    let rules = Box::new(YrRules {
        scanner: compiler.finalize(),
    });
    *out = Box::into_raw(rules);
    ERROR_SUCCESS
}
