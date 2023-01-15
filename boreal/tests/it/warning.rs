use crate::utils::check_warnings;

// Test all the files stored in the assets to make sure they emit warnings
#[test]
fn test_warning_files() {
    // Those files are not inlined here, so that they can be used to check how is the "pretty"
    // display of errors. This provides a nice way to check spans and stuff on those errors...
    for file in glob::glob("tests/assets/warning_files/**/*.yar").unwrap() {
        let file = file.unwrap();

        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read file {:?}: {}", file, e));

        let expected_warnings: Vec<_> = contents
            .lines()
            .filter_map(|line| {
                dbg!(&line);
                dbg!(line.strip_prefix("// [expected warning]: "))
            })
            .collect();

        println!("checking file {:?}", file);
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
            "mem:4:9: warning: implicit cast from a bytes value to a boolean",
            "mem:6:2: warning: implicit cast from a bytes value to a boolean",
            "mem:5:16: warning: implicit cast from a bytes value to a boolean",
        ],
    );
}
