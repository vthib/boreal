use std::collections::HashSet;
use std::ffi::{CStr, c_int, c_void};
use std::sync::{Arc, Mutex};

use boreal::compiler::ExternalValue;

use crate::scanner::{run_scan, ScanMode, YrMemoryBlockIterator};
use crate::{
    ERROR_INTERNAL_FATAL_ERROR, ERROR_INVALID_ARGUMENT, ERROR_SUCCESS,
    RawPtr,
};

pub type YrCallbackFunc = unsafe extern "C" fn(
    context: *mut c_void,
    message: c_int,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> c_int;

pub struct YrRules {
    pub scanner: boreal::Scanner,
    pub disabled_rules: Arc<Mutex<HashSet<String>>>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_destroy(rules: *mut YrRules) -> c_int {
    std::panic::catch_unwind(|| yr_rules_destroy_inner(rules)).unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_rules_destroy_inner(rules: *mut YrRules) -> c_int {
    if !rules.is_null() {
        // SAFETY: rules was allocated by yr_compiler_get_rules_inner.
        drop(unsafe { Box::from_raw(rules) });
    }
    ERROR_SUCCESS
}

fn define_rules_variable(
    rules: *mut YrRules,
    identifier: *const libc::c_char,
    value: ExternalValue,
) -> c_int {
    if rules.is_null() || identifier.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules and identifier are non-null.
    let rules = unsafe { &mut *rules };
    let ident = unsafe { CStr::from_ptr(identifier) }.to_string_lossy();
    match rules.scanner.define_symbol(ident.as_ref(), value) {
        Ok(()) => ERROR_SUCCESS,
        Err(_) => ERROR_INVALID_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_define_integer_variable(
    rules: *mut YrRules,
    identifier: *const libc::c_char,
    value: i64,
) -> c_int {
    std::panic::catch_unwind(|| {
        define_rules_variable(rules, identifier, ExternalValue::Integer(value))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_define_boolean_variable(
    rules: *mut YrRules,
    identifier: *const libc::c_char,
    value: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        define_rules_variable(rules, identifier, ExternalValue::Boolean(value != 0))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_define_float_variable(
    rules: *mut YrRules,
    identifier: *const libc::c_char,
    value: f64,
) -> c_int {
    std::panic::catch_unwind(|| {
        define_rules_variable(rules, identifier, ExternalValue::Float(value))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_define_string_variable(
    rules: *mut YrRules,
    identifier: *const libc::c_char,
    value: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(|| {
        if value.is_null() {
            return ERROR_INVALID_ARGUMENT;
        }
        let s = unsafe { CStr::from_ptr(value) }.to_bytes().to_vec();
        define_rules_variable(rules, identifier, ExternalValue::Bytes(s))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_scan_mem(
    rules: *mut YrRules,
    buffer: *const u8,
    buffer_size: libc::size_t,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        yr_rules_scan_mem_inner(rules, buffer, buffer_size, flags, callback, user_data, timeout)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_rules_scan_mem_inner(
    rules: *mut YrRules,
    buffer: *const u8,
    buffer_size: libc::size_t,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    if rules.is_null() || (buffer.is_null() && buffer_size > 0) {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules is non-null.
    let rules = unsafe { &mut *rules };
    let mem = if buffer.is_null() {
        &[]
    } else {
        // SAFETY: buffer points to buffer_size valid bytes.
        unsafe { std::slice::from_raw_parts(buffer, buffer_size) }
    };
    run_scan(
        &mut rules.scanner.clone(),
        &rules.disabled_rules,
        callback,
        RawPtr(user_data),
        RawPtr(std::ptr::null_mut()),
        flags,
        timeout,
        ScanMode::Mem(mem),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_scan_mem_blocks(
    rules: *mut YrRules,
    iterator: *mut YrMemoryBlockIterator,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        yr_rules_scan_mem_blocks_inner(rules, iterator, flags, callback, user_data, timeout)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_rules_scan_mem_blocks_inner(
    rules: *mut YrRules,
    iterator: *mut YrMemoryBlockIterator,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    if rules.is_null() || iterator.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules and iterator are non-null.
    let rules = unsafe { &mut *rules };
    run_scan(
        &mut rules.scanner.clone(),
        &rules.disabled_rules,
        callback,
        RawPtr(user_data),
        RawPtr(std::ptr::null_mut()),
        flags,
        timeout,
        ScanMode::MemBlocks(iterator),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_scan_file(
    rules: *mut YrRules,
    filename: *const libc::c_char,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        yr_rules_scan_file_inner(rules, filename, flags, callback, user_data, timeout)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_rules_scan_file_inner(
    rules: *mut YrRules,
    filename: *const libc::c_char,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    if rules.is_null() || filename.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules and filename are non-null.
    let rules = unsafe { &mut *rules };
    let path_str = unsafe { CStr::from_ptr(filename) }.to_string_lossy().into_owned();
    run_scan(
        &mut rules.scanner.clone(),
        &rules.disabled_rules,
        callback,
        RawPtr(user_data),
        RawPtr(std::ptr::null_mut()),
        flags,
        timeout,
        ScanMode::File(path_str),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_scan_fd(
    rules: *mut YrRules,
    fd: c_int,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        yr_rules_scan_fd_inner(rules, fd, flags, callback, user_data, timeout)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_rules_scan_fd_inner(
    rules: *mut YrRules,
    fd: c_int,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    if rules.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules is non-null.
    let rules = unsafe { &mut *rules };
    run_scan(
        &mut rules.scanner.clone(),
        &rules.disabled_rules,
        callback,
        RawPtr(user_data),
        RawPtr(std::ptr::null_mut()),
        flags,
        timeout,
        ScanMode::Fd(fd),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_scan_proc(
    rules: *mut YrRules,
    pid: c_int,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        yr_rules_scan_proc_inner(rules, pid, flags, callback, user_data, timeout)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_rules_scan_proc_inner(
    rules: *mut YrRules,
    pid: c_int,
    flags: c_int,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
    timeout: c_int,
) -> c_int {
    if rules.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules is non-null.
    let rules = unsafe { &mut *rules };
    run_scan(
        &mut rules.scanner.clone(),
        &rules.disabled_rules,
        callback,
        RawPtr(user_data),
        RawPtr(std::ptr::null_mut()),
        flags,
        timeout,
        ScanMode::Proc(pid as u32),
    )
}

#[cfg(feature = "serialize")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_save(rules: *mut YrRules, filename: *const libc::c_char) -> c_int {
    std::panic::catch_unwind(|| yr_rules_save_inner(rules, filename))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[cfg(feature = "serialize")]
fn yr_rules_save_inner(rules: *mut YrRules, filename: *const libc::c_char) -> c_int {
    if rules.is_null() || filename.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules and filename are non-null.
    let rules = unsafe { &*rules };
    let path = unsafe { CStr::from_ptr(filename) }.to_string_lossy();
    let file = match std::fs::File::create(path.as_ref()) {
        Ok(f) => f,
        Err(_) => return ERROR_COULD_NOT_OPEN_FILE,
    };
    let mut writer = std::io::BufWriter::new(file);
    match rules.scanner.to_bytes(&mut writer) {
        Ok(()) => ERROR_SUCCESS,
        Err(_) => ERROR_INTERNAL_FATAL_ERROR,
    }
}

#[cfg(feature = "serialize")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_load(
    filename: *const libc::c_char,
    rules: *mut *mut YrRules,
) -> c_int {
    std::panic::catch_unwind(|| yr_rules_load_inner(filename, rules))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[cfg(feature = "serialize")]
fn yr_rules_load_inner(filename: *const libc::c_char, rules: *mut *mut YrRules) -> c_int {
    if filename.is_null() || rules.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    let path = unsafe { CStr::from_ptr(filename) }.to_string_lossy();
    let bytes = match std::fs::read(path.as_ref()) {
        Ok(b) => b,
        Err(_) => return ERROR_COULD_NOT_OPEN_FILE,
    };
    load_rules_from_bytes(&bytes, rules)
}

#[cfg(feature = "serialize")]
fn load_rules_from_bytes(bytes: &[u8], rules: *mut *mut YrRules) -> c_int {
    use boreal::scanner::DeserializeParams;
    match boreal::Scanner::from_bytes_unchecked(bytes, DeserializeParams::default()) {
        Ok(scanner) => {
            let boxed = Box::new(YrRules {
                scanner,
                disabled_rules: Arc::new(Mutex::new(HashSet::new())),
            });
            // SAFETY: rules is non-null (checked by caller).
            unsafe { *rules = Box::into_raw(boxed) };
            ERROR_SUCCESS
        }
        Err(_) => ERROR_INVALID_ARGUMENT,
    }
}

#[cfg(feature = "serialize")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_save_stream(
    rules: *mut YrRules,
    stream: *mut YrStream,
) -> c_int {
    std::panic::catch_unwind(|| yr_rules_save_stream_inner(rules, stream))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[cfg(feature = "serialize")]
fn yr_rules_save_stream_inner(rules: *mut YrRules, stream: *mut YrStream) -> c_int {
    if rules.is_null() || stream.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules and stream are non-null.
    let rules = unsafe { &*rules };
    let mut writer = StreamWriter {
        stream: unsafe { &mut *stream },
    };
    match rules.scanner.to_bytes(&mut writer) {
        Ok(()) => ERROR_SUCCESS,
        Err(_) => ERROR_INTERNAL_FATAL_ERROR,
    }
}

#[cfg(feature = "serialize")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rules_load_stream(
    stream: *mut YrStream,
    rules: *mut *mut YrRules,
) -> c_int {
    std::panic::catch_unwind(|| yr_rules_load_stream_inner(stream, rules))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[cfg(feature = "serialize")]
fn yr_rules_load_stream_inner(stream: *mut YrStream, rules: *mut *mut YrRules) -> c_int {
    if stream.is_null() || rules.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: stream is non-null.
    let mut reader = StreamReader {
        stream: unsafe { &mut *stream },
    };
    let mut bytes = Vec::new();
    use std::io::Read;
    if reader.read_to_end(&mut bytes).is_err() {
        return ERROR_INTERNAL_FATAL_ERROR;
    }
    load_rules_from_bytes(&bytes, rules)
}

/// C-compatible stream type for serialization.
#[repr(C)]
pub struct YrStream {
    pub user_data: *mut c_void,
    pub read: Option<
        unsafe extern "C" fn(
            ptr: *mut c_void,
            size: libc::size_t,
            count: libc::size_t,
            user_data: *mut c_void,
        ) -> libc::size_t,
    >,
    pub write: Option<
        unsafe extern "C" fn(
            ptr: *const c_void,
            size: libc::size_t,
            count: libc::size_t,
            user_data: *mut c_void,
        ) -> libc::size_t,
    >,
}

#[cfg(feature = "serialize")]
struct StreamWriter<'a> {
    stream: &'a mut YrStream,
}

#[cfg(feature = "serialize")]
impl std::io::Write for StreamWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(write_fn) = self.stream.write else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no write function",
            ));
        };
        // SAFETY: write_fn is a valid C function pointer, buf is valid for buf.len() bytes.
        let written = unsafe {
            write_fn(
                buf.as_ptr() as *const c_void,
                1,
                buf.len(),
                self.stream.user_data,
            )
        };
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "serialize")]
struct StreamReader<'a> {
    stream: &'a mut YrStream,
}

#[cfg(feature = "serialize")]
impl std::io::Read for StreamReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(read_fn) = self.stream.read else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no read function",
            ));
        };
        // SAFETY: read_fn is a valid C function pointer, buf is valid for buf.len() bytes.
        let read = unsafe {
            read_fn(
                buf.as_mut_ptr() as *mut c_void,
                1,
                buf.len(),
                self.stream.user_data,
            )
        };
        Ok(read)
    }
}

// yr_rule_disable and yr_rule_enable are stubs until YR_RULE is defined.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rule_disable(_rule: *mut c_void) {
    // Deferred: requires YR_RULE struct definition.
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_rule_enable(_rule: *mut c_void) {
    // Deferred: requires YR_RULE struct definition.
}

use crate::ERROR_COULD_NOT_OPEN_FILE;
