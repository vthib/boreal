use crate::utils::{check_warnings, Compiler};

// Test all the files stored in the assets to make sure they emit warnings
#[test]
fn test_warning_files() {
    // Those files are not inlined here, so that they can be used to check how is the "pretty"
    // display of errors. This provides a nice way to check spans and stuff on those errors...
    for file in glob::glob("tests/assets/warning_files/**/*.yar").unwrap() {
        let file = file.unwrap();

        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read file {file:?}: {e}"));

        let expected_warnings: Vec<_> = contents
            .lines()
            .filter_map(|line| line.strip_prefix("// [expected warning]: "))
            .collect();

        println!("checking file {file:?}");
        check_warnings(&contents, &expected_warnings);
    }
}

#[test]
fn test_warning_bytes_to_bool_cast() {
    // Test that using a bytes value as a bool expr emits a warning.
    // Use multiple warnings and an include to check how warnings are accumulated
    let test_dir = tempfile::TempDir::new().unwrap();
    let included_path = test_dir.path().join("included.yar");

    std::fs::write(
        &included_path,
        r#"
rule included {
    condition:
        true and "true" and (
            for all i in (0..1) : ( "false" )
        )
}"#,
    )
    .unwrap();

    check_warnings(
        &format!(
            r#"
include "{}"

rule root {{
    condition: ""
}}"#,
            included_path.display()
        ),
        &[
            "included.yar:4:18: warning: implicit cast from a bytes value to a boolean",
            "included.yar:5:37: warning: implicit cast from a bytes value to a boolean",
            "mem:5:16: warning: implicit cast from a bytes value to a boolean",
        ],
    );
}

#[test]
fn test_warning_regex_contains_non_ascii_char() {
    check_warnings(
        r#"
rule a {
    strings:
        $a = /µ+/
    condition:
        $a and "foo" matches /aéuà/
           and /£-¤_/
}"#,
        &[
            "mem:6:32: warning: a non ascii character is present in a regex",
            "mem:6:34: warning: a non ascii character is present in a regex",
            "mem:7:17: warning: a non ascii character is present in a regex",
            "mem:7:19: warning: a non ascii character is present in a regex",
            "mem:4:15: warning: a non ascii character is present in a regex",
        ],
    );
}

#[test]
fn test_warning_regex_unknown_escape() {
    check_warnings(
        r"
rule a {
    strings:
        $a = /a\/a\i+\é_[1\2]-[a\0-\9z]2\+\🙄+/
    condition:
        $a and /\V/
}",
        &[
            "mem:6:17: warning: unknown escape sequence",
            "mem:4:19: warning: unknown escape sequence",
            "mem:4:22: warning: unknown escape sequence",
            "mem:4:22: warning: a non ascii character is present in a regex",
            "mem:4:27: warning: unknown escape sequence",
            "mem:4:33: warning: unknown escape sequence",
            "mem:4:36: warning: unknown escape sequence",
            "mem:4:43: warning: unknown escape sequence",
            "mem:4:43: warning: a non ascii character is present in a regex",
        ],
    );
}

#[test]
fn test_fail_on_warning_param() {
    let mut compiler = Compiler::new();

    // By default, warnings do not make the add fail.
    compiler.add_rules(r#"rule a { condition: "foo" }"#);

    let params = boreal::compiler::CompilerParams::default().fail_on_warnings(true);
    compiler.set_params(params);
    compiler.check_add_rules_err(
        r#"rule a { condition: "foo" }"#,
        "mem:1:21: warning: implicit cast from a bytes value to a boolean",
    );
}

#[test]
fn test_disable_unknown_escape_warning() {
    let mut compiler = Compiler::new();

    let params = boreal::compiler::CompilerParams::default()
        .fail_on_warnings(true)
        .disable_unknown_escape_warning(true);
    compiler.set_params(params);
    compiler.add_rules(
        r"
rule a {
    condition:
        /\V/
}",
    );
}
