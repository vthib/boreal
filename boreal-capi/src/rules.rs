use crate::YrRules;

// Safety: there is no other global function of this name
#[unsafe(no_mangle)]
// Safety: The passed pointer must be valid, and must have been created by `yr_compiler_get_rules`.
pub unsafe extern "C" fn yr_rules_destroy(rules: *mut YrRules) {
    let _r = std::panic::catch_unwind(|| {
        // Safety: see function safety constraint
        let rules = unsafe { Box::from_raw(rules) };
        drop(rules);
    });
}
