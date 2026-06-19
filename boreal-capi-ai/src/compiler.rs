use std::collections::HashSet;
use std::ffi::{CStr, CString, c_int, c_void};
use std::mem::ManuallyDrop;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};

use boreal::compiler::ExternalValue;

use crate::rules::YrRules;
use crate::{
    ERROR_COULD_NOT_OPEN_FILE, ERROR_INTERNAL_FATAL_ERROR, ERROR_INVALID_ARGUMENT, ERROR_SUCCESS,
    RawPtr,
};

pub type YrCompilerIncludeCallbackFunc = unsafe extern "C" fn(
    include_name: *const libc::c_char,
    calling_rule_filename: *const libc::c_char,
    calling_rule_namespace: *const libc::c_char,
    user_data: *mut c_void,
) -> *const libc::c_char;

pub type YrCompilerIncludeFreeFunc = unsafe extern "C" fn(
    callback_result_ptr: *const libc::c_char,
    user_data: *mut c_void,
);

pub struct YrCompiler {
    /// The boreal compiler, set to None after yr_compiler_get_rules.
    pub compiler: Option<boreal::Compiler>,
    /// Error message from the last failed compilation call.
    pub last_error_message: String,
    /// Include callback state.
    include_callback: Option<IncludeCallbackState>,
}

struct IncludeCallbackState {
    callback: YrCompilerIncludeCallbackFunc,
    free_func: Option<YrCompilerIncludeFreeFunc>,
    user_data: RawPtr,
}

impl YrCompiler {
    fn apply_include_callback(&mut self) {
        let Some(compiler) = self.compiler.as_mut() else {
            return;
        };
        let Some(state) = &self.include_callback else {
            return;
        };
        let callback = state.callback;
        let free_func = state.free_func;
        let user_data = state.user_data;

        // Use user_data.get() (method call) rather than user_data.0 (field access) so that
        // the move closure captures `user_data: RawPtr` (which is Send+Sync) rather than
        // the inner `*mut c_void` field (which is not Send+Sync) — see RFC 2229.
        compiler.set_include_callback(move |name, calling_file, ns| {
            let name_c =
                CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let calling_file_c = calling_file
                .and_then(|p| p.to_str())
                .and_then(|s| CString::new(s).ok());
            let ns_c = CString::new(ns)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            // SAFETY: Calling the user-provided C callback with valid C strings.
            let result = unsafe {
                callback(
                    name_c.as_ptr(),
                    calling_file_c
                        .as_ref()
                        .map_or(std::ptr::null(), |s| s.as_ptr()),
                    ns_c.as_ptr(),
                    user_data.get(),
                )
            };

            if result.is_null() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "include not found",
                ));
            }

            // SAFETY: result is a valid C string from the user callback.
            let content = unsafe { CStr::from_ptr(result) }
                .to_string_lossy()
                .into_owned();

            if let Some(free_f) = free_func {
                // SAFETY: Calling the user-provided free function with the pointer it returned.
                unsafe { free_f(result, user_data.get()) };
            }

            Ok(content)
        });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_create(compiler: *mut *mut YrCompiler) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| yr_compiler_create_inner(compiler)))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_create_inner(compiler: *mut *mut YrCompiler) -> c_int {
    if compiler.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    let boxed = Box::new(YrCompiler {
        compiler: Some(boreal::Compiler::new()),
        last_error_message: String::new(),
        include_callback: None,
    });
    // SAFETY: compiler is non-null (checked above).
    unsafe { *compiler = Box::into_raw(boxed) };
    ERROR_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_destroy(compiler: *mut YrCompiler) {
    drop(std::panic::catch_unwind(AssertUnwindSafe(|| yr_compiler_destroy_inner(compiler))));
}

fn yr_compiler_destroy_inner(compiler: *mut YrCompiler) {
    if !compiler.is_null() {
        // SAFETY: compiler was allocated by yr_compiler_create_inner.
        drop(unsafe { Box::from_raw(compiler) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_set_callback(
    _compiler: *mut YrCompiler,
    _callback: *mut c_void,
    _user_data: *mut c_void,
) {
    // Deferred: compiler error/warning callback is not yet implemented.
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_set_include_callback(
    compiler: *mut YrCompiler,
    callback: Option<YrCompilerIncludeCallbackFunc>,
    free_callback: Option<YrCompilerIncludeFreeFunc>,
    user_data: *mut c_void,
) {
    drop(std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_set_include_callback_inner(compiler, callback, free_callback, user_data)
    })));
}

fn yr_compiler_set_include_callback_inner(
    compiler: *mut YrCompiler,
    callback: Option<YrCompilerIncludeCallbackFunc>,
    free_callback: Option<YrCompilerIncludeFreeFunc>,
    user_data: *mut c_void,
) {
    if compiler.is_null() {
        return;
    }
    // SAFETY: compiler is non-null and was allocated by yr_compiler_create_inner.
    let compiler = unsafe { &mut *compiler };

    let Some(cb) = callback else {
        compiler.include_callback = None;
        return;
    };

    compiler.include_callback = Some(IncludeCallbackState {
        callback: cb,
        free_func: free_callback,
        user_data: RawPtr(user_data),
    });
    compiler.apply_include_callback();
}

fn read_fd_to_string(fd: c_int) -> Result<String, std::io::Error> {
    use std::io::Read;
    // ManuallyDrop prevents closing the fd when the File is dropped.
    let mut file = ManuallyDrop::new(unsafe {
        <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd)
    });
    let mut buf = String::new();
    let _n = file.read_to_string(&mut buf)?;
    Ok(buf)
}

fn add_rules_from_string(
    compiler: &mut YrCompiler,
    content: String,
    namespace: Option<&str>,
) -> c_int {
    let Some(boreal_compiler) = compiler.compiler.as_mut() else {
        return ERROR_INVALID_ARGUMENT;
    };
    let ns = namespace.unwrap_or("default");
    match boreal_compiler.add_rules_str_in_namespace(&content, ns) {
        Ok(_status) => ERROR_SUCCESS,
        Err(err) => {
            compiler.last_error_message = err.to_string();
            ERROR_INVALID_ARGUMENT
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_add_string(
    compiler: *mut YrCompiler,
    rules_string: *const libc::c_char,
    namespace_: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_add_string_inner(compiler, rules_string, namespace_)
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_add_string_inner(
    compiler: *mut YrCompiler,
    rules_string: *const libc::c_char,
    namespace_: *const libc::c_char,
) -> c_int {
    if compiler.is_null() || rules_string.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: Caller guarantees these are valid C strings.
    let content = unsafe { CStr::from_ptr(rules_string) }
        .to_string_lossy()
        .into_owned();
    let ns = if namespace_.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(namespace_) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    // SAFETY: compiler is non-null.
    let compiler = unsafe { &mut *compiler };
    add_rules_from_string(compiler, content, ns.as_deref())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_add_bytes(
    compiler: *mut YrCompiler,
    rules_data: *const c_void,
    rules_size: libc::size_t,
    namespace_: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_add_bytes_inner(compiler, rules_data, rules_size, namespace_)
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_add_bytes_inner(
    compiler: *mut YrCompiler,
    rules_data: *const c_void,
    rules_size: libc::size_t,
    namespace_: *const libc::c_char,
) -> c_int {
    if compiler.is_null() || rules_data.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: Caller guarantees rules_data points to rules_size valid bytes.
    let bytes = unsafe { std::slice::from_raw_parts(rules_data as *const u8, rules_size) };
    let content = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => return ERROR_INVALID_ARGUMENT,
    };
    let ns = if namespace_.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(namespace_) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    // SAFETY: compiler is non-null.
    let compiler = unsafe { &mut *compiler };
    add_rules_from_string(compiler, content, ns.as_deref())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_add_file(
    compiler: *mut YrCompiler,
    rules_file: *mut libc::FILE,
    namespace_: *const libc::c_char,
    _file_name: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_add_file_inner(compiler, rules_file, namespace_)
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_add_file_inner(
    compiler: *mut YrCompiler,
    rules_file: *mut libc::FILE,
    namespace_: *const libc::c_char,
) -> c_int {
    if compiler.is_null() || rules_file.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules_file is a valid FILE pointer.
    let fd = unsafe { libc::fileno(rules_file) };
    if fd < 0 {
        return ERROR_COULD_NOT_OPEN_FILE;
    }
    let content = match read_fd_to_string(fd) {
        Ok(s) => s,
        Err(_) => return ERROR_COULD_NOT_OPEN_FILE,
    };
    let ns = if namespace_.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(namespace_) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    // SAFETY: compiler is non-null.
    let compiler = unsafe { &mut *compiler };
    add_rules_from_string(compiler, content, ns.as_deref())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_add_fd(
    compiler: *mut YrCompiler,
    rules_fd: c_int,
    namespace_: *const libc::c_char,
    _file_name: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_add_fd_inner(compiler, rules_fd, namespace_)
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_add_fd_inner(
    compiler: *mut YrCompiler,
    rules_fd: c_int,
    namespace_: *const libc::c_char,
) -> c_int {
    if compiler.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    let content = match read_fd_to_string(rules_fd) {
        Ok(s) => s,
        Err(_) => return ERROR_COULD_NOT_OPEN_FILE,
    };
    let ns = if namespace_.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(namespace_) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    // SAFETY: compiler is non-null.
    let compiler = unsafe { &mut *compiler };
    add_rules_from_string(compiler, content, ns.as_deref())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_get_error_message(
    compiler: *mut YrCompiler,
    buffer: *mut libc::c_char,
    buffer_size: c_int,
) -> *mut libc::c_char {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_get_error_message_inner(compiler, buffer, buffer_size)
    }))
    .unwrap_or(buffer)
}

fn yr_compiler_get_error_message_inner(
    compiler: *mut YrCompiler,
    buffer: *mut libc::c_char,
    buffer_size: c_int,
) -> *mut libc::c_char {
    if compiler.is_null() || buffer.is_null() || buffer_size <= 0 {
        return buffer;
    }
    // SAFETY: compiler is non-null.
    let compiler = unsafe { &*compiler };
    let msg = &compiler.last_error_message;
    let copy_len = (msg.len()).min((buffer_size as usize).saturating_sub(1));
    // SAFETY: buffer has buffer_size bytes of space.
    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr() as *const libc::c_char, buffer, copy_len);
        *buffer.add(copy_len) = 0;
    }
    buffer
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_get_current_file_name(
    _compiler: *mut YrCompiler,
) -> *mut libc::c_char {
    // Not supported: boreal does not expose the current file during compilation.
    std::ptr::null_mut()
}

fn define_compiler_variable(
    compiler: *mut YrCompiler,
    identifier: *const libc::c_char,
    value: ExternalValue,
) -> c_int {
    if compiler.is_null() || identifier.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: compiler and identifier are non-null.
    let compiler = unsafe { &mut *compiler };
    let Some(boreal_compiler) = compiler.compiler.as_mut() else {
        return ERROR_INVALID_ARGUMENT;
    };
    let ident = unsafe { CStr::from_ptr(identifier) }.to_string_lossy();
    if boreal_compiler.define_symbol(ident.as_ref(), value) {
        ERROR_SUCCESS
    } else {
        ERROR_INVALID_ARGUMENT
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_define_integer_variable(
    compiler: *mut YrCompiler,
    identifier: *const libc::c_char,
    value: i64,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        define_compiler_variable(compiler, identifier, ExternalValue::Integer(value))
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_define_boolean_variable(
    compiler: *mut YrCompiler,
    identifier: *const libc::c_char,
    value: c_int,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        define_compiler_variable(compiler, identifier, ExternalValue::Boolean(value != 0))
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_define_float_variable(
    compiler: *mut YrCompiler,
    identifier: *const libc::c_char,
    value: f64,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        define_compiler_variable(compiler, identifier, ExternalValue::Float(value))
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_define_string_variable(
    compiler: *mut YrCompiler,
    identifier: *const libc::c_char,
    value: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        if value.is_null() {
            return ERROR_INVALID_ARGUMENT;
        }
        let s = unsafe { CStr::from_ptr(value) }.to_bytes().to_vec();
        define_compiler_variable(compiler, identifier, ExternalValue::Bytes(s))
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_compiler_get_rules(
    compiler: *mut YrCompiler,
    rules: *mut *mut YrRules,
) -> c_int {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        yr_compiler_get_rules_inner(compiler, rules)
    }))
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_compiler_get_rules_inner(
    compiler: *mut YrCompiler,
    rules: *mut *mut YrRules,
) -> c_int {
    if compiler.is_null() || rules.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: compiler is non-null.
    let compiler = unsafe { &mut *compiler };
    let Some(boreal_compiler) = compiler.compiler.take() else {
        return ERROR_INVALID_ARGUMENT;
    };
    let scanner = boreal_compiler.finalize();
    let boxed = Box::new(YrRules {
        scanner,
        disabled_rules: Arc::new(Mutex::new(HashSet::new())),
    });
    // SAFETY: rules is non-null.
    unsafe { *rules = Box::into_raw(boxed) };
    ERROR_SUCCESS
}
