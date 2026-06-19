use std::ffi::{c_int, c_void};

use boreal::scanner::{ScanCallbackResult, ScanError, ScanEvent};

use crate::YrRules;
use crate::error::{
    ERROR_CALLBACK_ERROR, ERROR_INTERNAL_FATAL_ERROR, ERROR_SCAN_TIMEOUT, ERROR_SUCCESS,
};

pub struct YrScanner {
    scanner: boreal::Scanner,
    cb: Option<CallbackFn>,
    cb_user_data: CbUserData,
}

struct CbUserData(*const c_void);
// Safety: this constraint is propagated to the user that pass this pointer.
unsafe impl Send for CbUserData {}
// Safety: this constraint is propagated to the user that pass this pointer.
unsafe impl Sync for CbUserData {}

#[repr(C)]
pub struct ScanContext {
    pub file_size: u64,
    pub entry_point: u64,
}

pub const CALLBACK_MSG_RULE_MATCHING: c_int = 1;
pub const CALLBACK_MSG_RULE_NOT_MATCHING: c_int = 2;
pub const CALLBACK_MSG_SCAN_FINISHED: c_int = 3;
pub const CALLBACK_MSG_IMPORT_MODULE: c_int = 4;
pub const CALLBACK_MSG_MODULE_IMPORTED: c_int = 5;
pub const CALLBACK_MSG_TOO_MANY_MATCHES: c_int = 6;
pub const CALLBACK_MSG_CONSOLE_LOG: c_int = 7;
pub const CALLBACK_MSG_TOO_SLOW_SCANNING: c_int = 8;

pub const CALLBACK_CONTINUE: c_int = 0;
pub const CALLBACK_ABORT: c_int = 1;
pub const CALLBACK_ERROR: c_int = 2;

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety:
// - The passed pointer must be valid, and must have been created by `yr_compiler_get_rules`.
// - The `scanner` pointer must be valid.
pub unsafe extern "C" fn yr_scanner_create(
    rules: *const YrRules,
    scanner: *mut *const YrScanner,
) -> c_int {
    std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let rules = unsafe { &*rules };
        // Safety: see function safety constraint
        let scanner = unsafe { &mut *scanner };
        yr_scanner_create_inner(rules, scanner)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_create_inner(rules: &YrRules, out_scanner: &mut *const YrScanner) -> c_int {
    let scanner = Box::new(YrScanner {
        scanner: rules.scanner.clone(),
        cb: None,
        cb_user_data: CbUserData(std::ptr::null()),
    });
    *out_scanner = Box::into_raw(scanner);
    ERROR_SUCCESS
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety: The passed pointer must be valid, and must have been created by `yr_scanner_create`.
pub unsafe extern "C" fn yr_scanner_destroy(scanner: *mut YrScanner) {
    let _r = std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let scanner = unsafe { Box::from_raw(scanner) };
        drop(scanner);
    });
}

type CallbackFn = extern "C" fn(
    context: *const ScanContext,
    message: c_int,
    message_data: *const c_void,
    user_data: *const c_void,
) -> c_int;

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety:
// - The passed `scanner` pointer must be valid, and must have been created by `yr_scanner_create`.
// - The callback function should be callable repeatedly as long as the scanner object is aliva.
// - The `user_data` must be shareable and usable safely between threads (must be Send + Sync in
//   Rust terms).
pub unsafe extern "C" fn yr_scanner_set_callback(
    scanner: *mut YrScanner,
    callback: Option<CallbackFn>,
    user_data: *const c_void,
) {
    let _r = std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let scanner = unsafe { &mut *scanner };
        yr_scanner_set_callback_inner(scanner, callback, user_data);
    });
}

fn yr_scanner_set_callback_inner(
    scanner: &mut YrScanner,
    callback: Option<CallbackFn>,
    user_data: *const c_void,
) {
    scanner.cb = callback;
    scanner.cb_user_data = CbUserData(user_data);
}

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety:
// - The passed `scanner` pointer must be valid, and must have been created by `yr_scanner_create`.
// - The buffer = buffer_size must point to a valid array of `buffer_size` bytes.
pub unsafe extern "C" fn yr_scanner_scan_mem(
    scanner: *const YrScanner,
    buffer: *const u8,
    buffer_size: usize,
) -> c_int {
    std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let scanner = unsafe { &*scanner };
        // Safety: see function safety constraint
        let buffer = unsafe { std::slice::from_raw_parts(buffer, buffer_size) };
        yr_scanner_scan_mem_inner(scanner, buffer)
    })
    .unwrap_or(ERROR_INTERNAL_FATAL_ERROR)
}

fn yr_scanner_scan_mem_inner(scanner: &YrScanner, buffer: &[u8]) -> c_int {
    let res = scanner.scanner.scan_mem_with_callback(buffer, |event| {
        let Some(cb) = &scanner.cb else {
            return ScanCallbackResult::Continue;
        };

        let message_type = match event {
            ScanEvent::RuleMatch(_) => CALLBACK_MSG_RULE_MATCHING,
            ScanEvent::RuleNoMatch(_) => CALLBACK_MSG_RULE_NOT_MATCHING,
            ScanEvent::ModuleImport(_) => CALLBACK_MSG_IMPORT_MODULE,
            ScanEvent::StringReachedMatchLimit(_) => CALLBACK_MSG_TOO_MANY_MATCHES,
            _ => return ScanCallbackResult::Continue,
        };

        let context = ScanContext {
            // FIXME:
            file_size: 0,
            entry_point: 0,
        };
        let res = (cb)(
            std::ptr::from_ref(&context),
            message_type,
            // TODO: message_data
            std::ptr::null(),
            scanner.cb_user_data.0,
        );
        match res {
            CALLBACK_CONTINUE => ScanCallbackResult::Continue,
            CALLBACK_ABORT => ScanCallbackResult::Abort,
            // FIXME: not api compliant
            CALLBACK_ERROR => ScanCallbackResult::Abort,
            _ => ScanCallbackResult::Abort,
        }
    });

    match res {
        Ok(()) => 0,
        Err(ScanError::Timeout) => ERROR_SCAN_TIMEOUT,
        Err(ScanError::CallbackAbort) => ERROR_CALLBACK_ERROR,
        Err(
            ScanError::CannotReadFile(_)
            | ScanError::UnsupportedProcessScan
            | ScanError::UnknownProcess
            | ScanError::CannotListProcessRegions(_),
        ) => ERROR_INTERNAL_FATAL_ERROR,
    }
}
