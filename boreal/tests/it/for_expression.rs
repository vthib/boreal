use crate::utils::check_err;

#[test]
fn test_for_identifiers_errors() {
    check_err(
        "rule a { condition: for any a, b in (0..3): (true) }",
        "mem:1:29: error: expected 1 identifiers to bind, got 2",
    );
}
