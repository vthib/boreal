use std::collections::HashSet;
use std::ffi::{CStr, CString, c_int, c_void};
use std::mem::ManuallyDrop;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boreal::compiler::ExternalValue;
use boreal::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use boreal::module::{Console, ConsoleData};
use boreal::scanner::{CallbackEvents, ScanCallbackResult, ScanEvent, ScanParams};

use crate::rules::{YrCallbackFunc, YrRules};
use crate::{
    CALLBACK_CONTINUE, CALLBACK_MSG_CONSOLE_LOG, CALLBACK_MSG_IMPORT_MODULE,
    CALLBACK_MSG_MODULE_IMPORTED, CALLBACK_MSG_RULE_MATCHING, CALLBACK_MSG_RULE_NOT_MATCHING,
    CALLBACK_MSG_SCAN_FINISHED, CALLBACK_MSG_TOO_MANY_MATCHES, ERROR_COULD_NOT_ATTACH_TO_PROCESS,
    ERROR_COULD_NOT_OPEN_FILE, ERROR_INTERNAL_FATAL_ERROR, ERROR_INVALID_ARGUMENT, ERROR_SUCCESS,
    ERROR_SCAN_TIMEOUT, ERROR_UNSUPPORTED, GLOBAL_CONFIG, RawPtr, SCAN_FLAGS_FAST_MODE,
    SCAN_FLAGS_PROCESS_MEMORY, SCAN_FLAGS_REPORT_RULES_NOT_MATCHING,
};

/// C-compatible memory block structure for fragmented scanning.
#[repr(C)]
pub struct YrMemoryBlock {
    pub size: libc::size_t,
    pub base: u64,
    pub context: *mut c_void,
    pub fetch_data: Option<unsafe extern "C" fn(block: *mut YrMemoryBlock) -> *const u8>,
}

/// C-compatible memory block iterator for fragmented scanning.
#[repr(C)]
pub struct YrMemoryBlockIterator {
    pub context: *mut c_void,
    pub first: Option<unsafe extern "C" fn(iter: *mut YrMemoryBlockIterator) -> *mut YrMemoryBlock>,
    pub next: Option<unsafe extern "C" fn(iter: *mut YrMemoryBlockIterator) -> *mut YrMemoryBlock>,
    pub file_size: Option<unsafe extern "C" fn(iter: *mut YrMemoryBlockIterator) -> u64>,
    pub last_error: c_int,
}

/// Wraps a C YR_MEMORY_BLOCK_ITERATOR as a boreal FragmentedMemory.
#[derive(Debug)]
struct CMemoryBlockIter {
    iterator: *mut YrMemoryBlockIterator,
    started: bool,
    current_block: *mut YrMemoryBlock,
    /// The data pointer returned by the current block's fetch_data; stable until next/reset.
    current_data: *const u8,
}

// SAFETY: The YARA API contract states the iterator is used single-threaded.
unsafe impl Send for CMemoryBlockIter {}
unsafe impl Sync for CMemoryBlockIter {}

impl FragmentedMemory for CMemoryBlockIter {
    fn next(&mut self, _params: &MemoryParams) -> Option<RegionDescription> {
        // SAFETY: iterator is a valid non-null C pointer for the duration of the scan.
        let block = unsafe {
            if !self.started {
                self.started = true;
                let first_fn = (*self.iterator).first?;
                (first_fn)(self.iterator)
            } else {
                let next_fn = (*self.iterator).next?;
                (next_fn)(self.iterator)
            }
        };
        if block.is_null() {
            self.current_block = std::ptr::null_mut();
            return None;
        }
        // SAFETY: block is a valid non-null pointer returned by first/next.
        let (size, base) = unsafe { ((*block).size, (*block).base) };
        self.current_block = block;
        self.current_data = std::ptr::null();
        Some(RegionDescription {
            start: base as usize,
            length: size,
        })
    }

    fn fetch(&mut self, _params: &MemoryParams) -> Option<Region<'_>> {
        if self.current_block.is_null() {
            return None;
        }
        // SAFETY: current_block is valid (set by next()).
        let fetch_fn = unsafe { (*self.current_block).fetch_data? };
        // SAFETY: Calling the fetch function with the current block pointer.
        let ptr = unsafe { (fetch_fn)(self.current_block) };
        if ptr.is_null() {
            return None;
        }
        self.current_data = ptr;
        // SAFETY: current_block is valid.
        let (size, base) = unsafe { ((*self.current_block).size, (*self.current_block).base) };
        // SAFETY: ptr is valid for size bytes (C iterator contract); lifetime tied to &mut self.
        let mem = unsafe { std::slice::from_raw_parts(self.current_data, size) };
        Some(Region {
            start: base as usize,
            mem,
        })
    }

    fn reset(&mut self) {
        self.started = false;
        self.current_block = std::ptr::null_mut();
        self.current_data = std::ptr::null();
    }
}

/// Abstraction over the different things that can be scanned.
pub enum ScanMode<'a> {
    Mem(&'a [u8]),
    MemBlocks(*mut YrMemoryBlockIterator),
    File(String),
    Fd(c_int),
    Proc(u32),
}

fn build_scan_params(flags: c_int, timeout_secs: c_int) -> ScanParams {
    let mut params = ScanParams::default();

    // Fast mode: if NOT set, request full match data.
    if (flags & SCAN_FLAGS_FAST_MODE) == 0 {
        params = params.compute_full_matches(true);
    }

    if (flags & SCAN_FLAGS_PROCESS_MEMORY) != 0 {
        params = params.process_memory(true);
    }

    // Always request module imports, string match limit events, and rule matches.
    let mut events = CallbackEvents::RULE_MATCH
        | CallbackEvents::MODULE_IMPORT
        | CallbackEvents::STRING_REACHED_MATCH_LIMIT;
    if (flags & SCAN_FLAGS_REPORT_RULES_NOT_MATCHING) != 0 {
        events |= CallbackEvents::RULE_NO_MATCH;
    }
    params = params.callback_events(events);

    if timeout_secs > 0 {
        params = params.timeout_duration(Some(Duration::from_secs(timeout_secs as u64)));
    }

    if let Ok(cfg) = GLOBAL_CONFIG.lock() {
        if let Some(max) = cfg.max_match_data {
            params = params.match_max_length(max);
        }
        if let Some(chunk) = cfg.max_process_memory_chunk {
            params = params.memory_chunk_size(Some(chunk));
        }
    }

    params
}

fn handle_scan_event(
    event: ScanEvent<'_, '_>,
    callback: Option<YrCallbackFunc>,
    user_data: RawPtr,
    ctx: RawPtr,
    disabled_rules: &Mutex<HashSet<String>>,
) -> ScanCallbackResult {
    let Some(cb) = callback else {
        return ScanCallbackResult::Continue;
    };

    match event {
        ScanEvent::RuleMatch(rule) => {
            if let Ok(disabled) = disabled_rules.lock() {
                let key = format!("{}:{}", rule.namespace, rule.name);
                if disabled.contains(&key) {
                    return ScanCallbackResult::Continue;
                }
            }
            // Deferred: message_data will be *YR_RULE once struct is defined.
            let ret = unsafe {
                cb(
                    ctx.0,
                    CALLBACK_MSG_RULE_MATCHING,
                    std::ptr::null_mut(),
                    user_data.0,
                )
            };
            convert_callback_return(ret)
        }
        ScanEvent::RuleNoMatch(rule) => {
            if let Ok(disabled) = disabled_rules.lock() {
                let key = format!("{}:{}", rule.namespace, rule.name);
                if disabled.contains(&key) {
                    return ScanCallbackResult::Continue;
                }
            }
            // Deferred: message_data will be *YR_RULE once struct is defined.
            let ret = unsafe {
                cb(
                    ctx.0,
                    CALLBACK_MSG_RULE_NOT_MATCHING,
                    std::ptr::null_mut(),
                    user_data.0,
                )
            };
            convert_callback_return(ret)
        }
        ScanEvent::ModuleImport(_) => {
            // Fire IMPORT_MODULE, then MODULE_IMPORTED.
            // Deferred: message_data will be *YR_OBJECT_STRUCTURE once struct is defined.
            let ret1 = unsafe {
                cb(
                    ctx.0,
                    CALLBACK_MSG_IMPORT_MODULE,
                    std::ptr::null_mut(),
                    user_data.0,
                )
            };
            if ret1 != CALLBACK_CONTINUE {
                return ScanCallbackResult::Abort;
            }
            let ret2 = unsafe {
                cb(
                    ctx.0,
                    CALLBACK_MSG_MODULE_IMPORTED,
                    std::ptr::null_mut(),
                    user_data.0,
                )
            };
            convert_callback_return(ret2)
        }
        ScanEvent::StringReachedMatchLimit(_) => {
            // Deferred: message_data will be *YR_STRING once struct is defined.
            let ret = unsafe {
                cb(
                    ctx.0,
                    CALLBACK_MSG_TOO_MANY_MATCHES,
                    std::ptr::null_mut(),
                    user_data.0,
                )
            };
            convert_callback_return(ret)
        }
        _ => ScanCallbackResult::Continue,
    }
}

fn convert_callback_return(ret: c_int) -> ScanCallbackResult {
    if ret == CALLBACK_CONTINUE {
        ScanCallbackResult::Continue
    } else {
        ScanCallbackResult::Abort
    }
}

fn scan_error_to_code(err: boreal::scanner::ScanError) -> c_int {
    match err {
        boreal::scanner::ScanError::Timeout => ERROR_SCAN_TIMEOUT,
        boreal::scanner::ScanError::CannotReadFile(_) => ERROR_COULD_NOT_OPEN_FILE,
        boreal::scanner::ScanError::UnsupportedProcessScan => ERROR_UNSUPPORTED,
        boreal::scanner::ScanError::UnknownProcess
        | boreal::scanner::ScanError::CannotListProcessRegions(_) => {
            ERROR_COULD_NOT_ATTACH_TO_PROCESS
        }
        boreal::scanner::ScanError::CallbackAbort => ERROR_SUCCESS,
    }
}

/// Core scan executor. Sets params, wires callbacks, runs the scan, fires SCAN_FINISHED.
pub fn run_scan(
    scanner: &mut boreal::Scanner,
    disabled_rules: &Arc<Mutex<HashSet<String>>>,
    callback: Option<YrCallbackFunc>,
    user_data: RawPtr,
    ctx: RawPtr,
    flags: c_int,
    timeout_secs: c_int,
    mode: ScanMode<'_>,
) -> c_int {
    let params = build_scan_params(flags, timeout_secs);
    scanner.set_scan_params(params);

    // Set up the console module callback to fire CALLBACK_MSG_CONSOLE_LOG.
    // Use ctx.get() / user_data.get() (method calls) rather than field access .0 so that
    // the move closure captures RawPtr (which is Send+Sync) not *mut c_void (which is not).
    if callback.is_some() {
        scanner.set_module_data::<Console>(ConsoleData::new(move |log| {
            if let Some(cb) = callback {
                if let Ok(log_c) = CString::new(log) {
                    // SAFETY: ctx and user_data are valid for the duration of the scan.
                    let _ret = unsafe {
                        cb(
                            ctx.get(),
                            CALLBACK_MSG_CONSOLE_LOG,
                            log_c.as_ptr() as *mut c_void,
                            user_data.get(),
                        )
                    };
                }
            }
        }));
    }

    let disabled = Arc::clone(disabled_rules);

    let scan_result = match mode {
        ScanMode::Mem(mem) => scanner.scan_mem_with_callback(mem, |event| {
            handle_scan_event(event, callback, user_data, ctx, &disabled)
        }),
        ScanMode::MemBlocks(iter_ptr) => {
            // SAFETY: iter_ptr is non-null (checked by caller).
            let iter = CMemoryBlockIter {
                iterator: iter_ptr,
                started: false,
                current_block: std::ptr::null_mut(),
                current_data: std::ptr::null(),
            };
            scanner.scan_fragmented_with_callback(iter, |event| {
                handle_scan_event(event, callback, user_data, ctx, &disabled)
            })
        }
        ScanMode::File(path) => scanner.scan_file_with_callback(&path, |event| {
            handle_scan_event(event, callback, user_data, ctx, &disabled)
        }),
        ScanMode::Fd(fd) => {
            use std::io::Read;
            let mut file =
                ManuallyDrop::new(unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) });
            let mut contents = Vec::new();
            match file.read_to_end(&mut contents) {
                Ok(_) => scanner.scan_mem_with_callback(&contents, |event| {
                    handle_scan_event(event, callback, user_data, ctx, &disabled)
                }),
                Err(_) => return ERROR_COULD_NOT_OPEN_FILE,
            }
        }
        ScanMode::Proc(pid) => scanner.scan_process_with_callback(pid, |event| {
            handle_scan_event(event, callback, user_data, ctx, &disabled)
        }),
    };

    // Always fire SCAN_FINISHED after the scan.
    if let Some(cb) = callback {
        // SAFETY: ctx and user_data are valid pointers.
        let _ret = unsafe {
            cb(
                ctx.get(),
                CALLBACK_MSG_SCAN_FINISHED,
                std::ptr::null_mut(),
                user_data.get(),
            )
        };
    }

    match scan_result {
        Ok(()) => ERROR_SUCCESS,
        Err(err) => scan_error_to_code(err),
    }
}

/// Scanner object: a clone of YR_RULES' scanner plus per-scan state.
pub struct YrScanner {
    pub scanner: boreal::Scanner,
    pub disabled_rules: Arc<Mutex<HashSet<String>>>,
    pub callback: Option<YrCallbackFunc>,
    pub user_data: *mut c_void,
    pub flags: c_int,
    pub timeout_secs: c_int,
}

// SAFETY: YrScanner is only used from the thread that owns it (YARA contract).
unsafe impl Send for YrScanner {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_create(
    rules: *mut YrRules,
    scanner: *mut *mut YrScanner,
) -> c_int {
    std::panic::catch_unwind(|| yr_scanner_create_inner(rules, scanner))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_create_inner(rules: *mut YrRules, scanner: *mut *mut YrScanner) -> c_int {
    if rules.is_null() || scanner.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: rules is non-null.
    let rules = unsafe { &*rules };
    let boxed = Box::new(YrScanner {
        scanner: rules.scanner.clone(),
        disabled_rules: Arc::clone(&rules.disabled_rules),
        callback: None,
        user_data: std::ptr::null_mut(),
        flags: 0,
        timeout_secs: 0,
    });
    // SAFETY: scanner is non-null.
    unsafe { *scanner = Box::into_raw(boxed) };
    ERROR_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_destroy(scanner: *mut YrScanner) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        yr_scanner_destroy_inner(scanner);
    })));
}

fn yr_scanner_destroy_inner(scanner: *mut YrScanner) {
    if !scanner.is_null() {
        // SAFETY: scanner was allocated by yr_scanner_create_inner.
        drop(unsafe { Box::from_raw(scanner) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_set_callback(
    scanner: *mut YrScanner,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        yr_scanner_set_callback_inner(scanner, callback, user_data);
    })));
}

fn yr_scanner_set_callback_inner(
    scanner: *mut YrScanner,
    callback: Option<YrCallbackFunc>,
    user_data: *mut c_void,
) {
    if scanner.is_null() {
        return;
    }
    // SAFETY: scanner is non-null.
    let scanner = unsafe { &mut *scanner };
    scanner.callback = callback;
    scanner.user_data = user_data;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_set_timeout(scanner: *mut YrScanner, timeout: c_int) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        yr_scanner_set_timeout_inner(scanner, timeout);
    })));
}

fn yr_scanner_set_timeout_inner(scanner: *mut YrScanner, timeout: c_int) {
    if scanner.is_null() {
        return;
    }
    // SAFETY: scanner is non-null.
    unsafe { &mut *scanner }.timeout_secs = timeout;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_set_flags(scanner: *mut YrScanner, flags: c_int) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        yr_scanner_set_flags_inner(scanner, flags);
    })));
}

fn yr_scanner_set_flags_inner(scanner: *mut YrScanner, flags: c_int) {
    if scanner.is_null() {
        return;
    }
    // SAFETY: scanner is non-null.
    unsafe { &mut *scanner }.flags = flags;
}

fn define_scanner_variable(
    scanner: *mut YrScanner,
    identifier: *const libc::c_char,
    value: ExternalValue,
) -> c_int {
    if scanner.is_null() || identifier.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: scanner and identifier are non-null.
    let scanner = unsafe { &mut *scanner };
    let ident = unsafe { CStr::from_ptr(identifier) }.to_string_lossy();
    match scanner.scanner.define_symbol(ident.as_ref(), value) {
        Ok(()) => ERROR_SUCCESS,
        Err(_) => ERROR_INVALID_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_define_integer_variable(
    scanner: *mut YrScanner,
    identifier: *const libc::c_char,
    value: i64,
) -> c_int {
    std::panic::catch_unwind(|| {
        define_scanner_variable(scanner, identifier, ExternalValue::Integer(value))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_define_boolean_variable(
    scanner: *mut YrScanner,
    identifier: *const libc::c_char,
    value: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        define_scanner_variable(scanner, identifier, ExternalValue::Boolean(value != 0))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_define_float_variable(
    scanner: *mut YrScanner,
    identifier: *const libc::c_char,
    value: f64,
) -> c_int {
    std::panic::catch_unwind(|| {
        define_scanner_variable(scanner, identifier, ExternalValue::Float(value))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_define_string_variable(
    scanner: *mut YrScanner,
    identifier: *const libc::c_char,
    value: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(|| {
        if value.is_null() {
            return ERROR_INVALID_ARGUMENT;
        }
        let s = unsafe { CStr::from_ptr(value) }.to_bytes().to_vec();
        define_scanner_variable(scanner, identifier, ExternalValue::Bytes(s))
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_scan_mem(
    scanner: *mut YrScanner,
    buffer: *const u8,
    buffer_size: libc::size_t,
) -> c_int {
    std::panic::catch_unwind(|| yr_scanner_scan_mem_inner(scanner, buffer, buffer_size))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_scan_mem_inner(
    scanner: *mut YrScanner,
    buffer: *const u8,
    buffer_size: libc::size_t,
) -> c_int {
    if scanner.is_null() || (buffer.is_null() && buffer_size > 0) {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: scanner is non-null.
    let yr_scanner = unsafe { &mut *scanner };
    let mem = if buffer.is_null() {
        &[]
    } else {
        // SAFETY: buffer points to buffer_size valid bytes.
        unsafe { std::slice::from_raw_parts(buffer, buffer_size) }
    };
    let ctx = RawPtr(scanner as *mut c_void);
    run_scan(
        &mut yr_scanner.scanner,
        &yr_scanner.disabled_rules,
        yr_scanner.callback,
        RawPtr(yr_scanner.user_data),
        ctx,
        yr_scanner.flags,
        yr_scanner.timeout_secs,
        ScanMode::Mem(mem),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_scan_mem_blocks(
    scanner: *mut YrScanner,
    iterator: *mut YrMemoryBlockIterator,
) -> c_int {
    std::panic::catch_unwind(|| yr_scanner_scan_mem_blocks_inner(scanner, iterator))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_scan_mem_blocks_inner(
    scanner: *mut YrScanner,
    iterator: *mut YrMemoryBlockIterator,
) -> c_int {
    if scanner.is_null() || iterator.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: scanner is non-null.
    let yr_scanner = unsafe { &mut *scanner };
    let ctx = RawPtr(scanner as *mut c_void);
    run_scan(
        &mut yr_scanner.scanner,
        &yr_scanner.disabled_rules,
        yr_scanner.callback,
        RawPtr(yr_scanner.user_data),
        ctx,
        yr_scanner.flags,
        yr_scanner.timeout_secs,
        ScanMode::MemBlocks(iterator),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_scan_file(
    scanner: *mut YrScanner,
    filename: *const libc::c_char,
) -> c_int {
    std::panic::catch_unwind(|| yr_scanner_scan_file_inner(scanner, filename))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_scan_file_inner(
    scanner: *mut YrScanner,
    filename: *const libc::c_char,
) -> c_int {
    if scanner.is_null() || filename.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: scanner and filename are non-null.
    let yr_scanner = unsafe { &mut *scanner };
    let path = unsafe { CStr::from_ptr(filename) }.to_string_lossy().into_owned();
    let ctx = RawPtr(scanner as *mut c_void);
    run_scan(
        &mut yr_scanner.scanner,
        &yr_scanner.disabled_rules,
        yr_scanner.callback,
        RawPtr(yr_scanner.user_data),
        ctx,
        yr_scanner.flags,
        yr_scanner.timeout_secs,
        ScanMode::File(path),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_scan_fd(
    scanner: *mut YrScanner,
    fd: c_int,
) -> c_int {
    std::panic::catch_unwind(|| yr_scanner_scan_fd_inner(scanner, fd))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_scan_fd_inner(scanner: *mut YrScanner, fd: c_int) -> c_int {
    if scanner.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: scanner is non-null.
    let yr_scanner = unsafe { &mut *scanner };
    let ctx = RawPtr(scanner as *mut c_void);
    run_scan(
        &mut yr_scanner.scanner,
        &yr_scanner.disabled_rules,
        yr_scanner.callback,
        RawPtr(yr_scanner.user_data),
        ctx,
        yr_scanner.flags,
        yr_scanner.timeout_secs,
        ScanMode::Fd(fd),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_scan_proc(
    scanner: *mut YrScanner,
    pid: c_int,
) -> c_int {
    std::panic::catch_unwind(|| yr_scanner_scan_proc_inner(scanner, pid))
        .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_scan_proc_inner(scanner: *mut YrScanner, pid: c_int) -> c_int {
    if scanner.is_null() {
        return ERROR_INVALID_ARGUMENT;
    }
    // SAFETY: scanner is non-null.
    let yr_scanner = unsafe { &mut *scanner };
    let ctx = RawPtr(scanner as *mut c_void);
    run_scan(
        &mut yr_scanner.scanner,
        &yr_scanner.disabled_rules,
        yr_scanner.callback,
        RawPtr(yr_scanner.user_data),
        ctx,
        yr_scanner.flags,
        yr_scanner.timeout_secs,
        ScanMode::Proc(pid as u32),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_last_error_rule(
    _scanner: *mut YrScanner,
) -> *mut c_void {
    // Deferred: requires YR_RULE struct definition.
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn yr_scanner_last_error_string(
    _scanner: *mut YrScanner,
) -> *mut c_void {
    // Deferred: requires YR_STRING struct definition.
    std::ptr::null_mut()
}
