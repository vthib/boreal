use boreal_parser::hex_string::parse_hex_string;
use boreal_parser::regex::parse_regex;

use crate::regex::Hir;

#[track_caller]
pub fn expr_to_hir(expr: &str) -> Hir {
    if expr.starts_with('{') {
        parse_hex_string(expr).unwrap().into()
    } else {
        parse_regex(&format!("/{expr}/")).unwrap().ast.into()
    }
}

// Those helpers serves two purposes:
// - Ensure public types have expected impls: Clone, Debug, Send & Sync
// - Instrument those impls to avoid having those derive be marked as missed in coverage...
pub fn test_type_traits<T: Clone + std::fmt::Debug + Send + Sync>(t: T) {
    #[allow(clippy::redundant_clone)]
    let _r = t.clone();
    let _r = format!("{:?}", &t);
}

pub fn test_type_traits_non_clonable<T: std::fmt::Debug + Send + Sync>(t: T) {
    let _r = format!("{:?}", &t);
}
