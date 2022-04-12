use crate::utils::{check, check_err};

#[test]
fn test_imports() {
    check_err(
        r#"import "a"
rule foo { condition: true }"#,
        "error: unknown import a",
    );

    check(
        r#"
import "tests"
import "tests"
rule foo { condition: true }"#,
        b"",
        true,
    );
}
