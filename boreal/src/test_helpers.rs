use std::panic::{RefUnwindSafe, UnwindSafe};

use boreal_parser::hex_string::parse_hex_string;
use boreal_parser::regex::parse_regex;

use crate::regex::{regex_ast_to_hir, Hir};

#[track_caller]
pub fn expr_to_hir(expr: &str) -> Hir {
    if expr.starts_with('{') {
        parse_hex_string(expr).unwrap().into()
    } else {
        let regex = parse_regex(&format!("/{expr}/")).unwrap();
        regex_ast_to_hir(regex.ast, &mut Vec::new())
    }
}

// Those helpers serves two purposes:
// - Ensure public types have expected impls: Clone, Debug, Send & Sync
// - Instrument those impls to avoid having those derive be marked as missed in coverage...
pub fn test_type_traits<T: Clone + std::fmt::Debug + Send + Sync>(t: T) {
    #[allow(clippy::redundant_clone)]
    let _r = t.clone();
    test_type_traits_non_clonable(t);
}

pub fn test_type_traits_non_clonable<T: std::fmt::Debug + Send + Sync>(t: T) {
    let _r = format!("{:?}", &t);
}

pub fn test_type_unwind_safe<T: UnwindSafe + RefUnwindSafe>() {}
