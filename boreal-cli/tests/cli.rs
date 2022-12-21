use std::fs;
use std::io::Write;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};

fn cmd() -> Command {
    Command::cargo_bin("boreal").unwrap()
}

fn test_file(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

#[test]
fn test_no_arguments() {
    // Some arguments are required to do anything
    cmd().assert().failure();
}

#[test]
fn test_invalid_path() {
    // Invalid path to rule
    cmd()
        .arg("do_not_exist")
        .arg("input")
        .assert()
        .stdout("")
        .stderr(predicate::str::contains("IO error"))
        .failure();

    // Invalid path to input
    let rule_file = test_file("");
    cmd()
        .arg(rule_file.path())
        .arg("bad_input")
        .assert()
        .stdout("")
        .stderr(predicate::str::contains("Cannot scan bad_input"))
        .failure();
}

#[test]
fn test_single_rule() {
    let rule_file = test_file(
        r#"
rule my_rule {
    strings:
        $a = "abc"
    condition:
        any of them
}"#,
    );

    let input = test_file("aaa");
    // Not matching
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr("")
        .success();

    let input = test_file("zeabce");
    // Matching
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(predicate::eq(format!(
            "my_rule {}\n",
            input.path().display()
        )))
        .stderr("")
        .success();
}

#[test]
fn test_rule_error() {
    let rule_file = test_file(
        r#"rule a {
        strings: $a = /[z-a]/
        condition: $a
    }"#,
    );

    let input = test_file("");
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(
            predicate::str::contains("error")
                .and(predicate::str::contains("invalid regex class range")),
        )
        .failure();
}

#[test]
fn test_rule_warning() {
    let rule_file = test_file(
        r#"rule rule_with_warning {
            condition:
                "a"
        }
        "#,
    );

    let input = test_file("");

    // Warning is OK and rule is eval'ed
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(predicate::eq(format!(
            "rule_with_warning {}\n",
            input.path().display()
        )))
        .stderr(
            predicate::str::contains("warning").and(predicate::str::contains(
                "implicit cast from a bytes value to a boolean",
            )),
        )
        .success();

    // Warning is considered an error
    cmd()
        .arg("--fail-on-warnings")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(
            predicate::str::contains("warning").and(predicate::str::contains(
                "implicit cast from a bytes value to a boolean",
            )),
        )
        .failure();
}

#[test]
fn test_rule_include() {
    let temp = TempDir::new().unwrap();

    let rule_b = temp.path().join("b.yar");
    fs::write(
        rule_b,
        r#"
rule included {
    strings:
        $ = "abc"
    condition:
        any of them
}
"#,
    )
    .unwrap();

    let rule_a = temp.path().join("a.yar");
    fs::write(
        &rule_a,
        r#"
include "b.yar"

rule includer {
    strings:
        $ = "xyz"
    condition:
        included and any of them
}
"#,
    )
    .unwrap();

    // Match on the included
    let input = test_file("abc");
    cmd()
        .arg(&rule_a)
        .arg(input.path())
        .assert()
        .stdout(predicate::eq(format!(
            "included {}\n",
            input.path().display()
        )))
        .success();

    // Match on both
    let input = test_file("xyz abc");
    cmd()
        .arg(rule_a)
        .arg(input.path())
        .assert()
        .stdout(
            predicate::str::contains(format!("included {}", input.path().display())).and(
                predicate::str::contains(format!("includer {}", input.path().display())),
            ),
        )
        .success();
}

#[test]
fn test_rule_include_error() {
    let temp = TempDir::new().unwrap();

    let rule_b = temp.path().join("b.yar");
    fs::write(
        &rule_b,
        r#"
rule included {
    strings:
        $ = /[z-a]/
    condition:
        any of them
}
"#,
    )
    .unwrap();

    let rule_a = temp.path().join("a.yar");
    fs::write(&rule_a, r#"include "b.yar""#).unwrap();

    // Match on the included
    let input = test_file("");
    cmd()
        .arg(rule_a)
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(
            // Contains the path to the faulty file
            // Need canonicalize as the path is canonicalized in boreal, and this causes
            // differences on Windows.
            predicate::str::contains(rule_b.canonicalize().unwrap().display().to_string())
                .and(
                    // And the proper string that caused the error
                    predicate::str::contains("z-a"),
                )
                .and(
                    // And the error message
                    predicate::str::contains("invalid regex class range"),
                ),
        )
        .failure();
}

#[test]
#[cfg(unix)]
fn test_rule_dir() {
    use std::os::unix::fs::symlink;

    let rule_file = test_file("rule a { condition: true }");

    let temp = TempDir::new().unwrap();
    let temp2 = TempDir::new().unwrap();

    // a and b in temp
    let file_a = temp.path().join("a");
    fs::write(&file_a, "").unwrap();
    let file_b = temp.path().join("b");
    fs::write(&file_b, "").unwrap();

    // c in temp/subdir
    let subdir = temp.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    let file_c = subdir.join("c");
    fs::write(&file_c, "").unwrap();

    // d.yar and e.yar in temp2
    let file2_d = temp2.path().join("d");
    fs::write(&file2_d, "").unwrap();
    let file2_e = temp2.path().join("e");
    fs::write(&file2_e, "").unwrap();

    // symlink temp/d.yar to temp2/d.yar
    let file_d = temp.path().join("d");
    symlink(&file2_d, &file_d).unwrap();
    // symlink temp/subdir/e.yar to temp2/e.yar
    let file_e = subdir.join("e");
    symlink(&file2_e, &file_e).unwrap();

    let match_str = |input: &Path| predicate::str::contains(format!("a {}", input.display()));

    // Non recursive
    cmd()
        // Add some threads to instrument the code
        .args(["--threads", "20"])
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on "a", "b" and "d"
            match_str(&file_a)
                .and(match_str(&file_b))
                .and(match_str(&file_c).not())
                .and(match_str(&file_d))
                .and(match_str(&file_e).not()),
        )
        .stderr("")
        .success();

    // Non recursive and non follow symlinks
    cmd()
        .arg("-N")
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on "a" and "b"
            match_str(&file_a)
                .and(match_str(&file_b))
                .and(match_str(&file_c).not())
                .and(match_str(&file_d).not())
                .and(match_str(&file_e).not()),
        )
        .stderr("")
        .success();

    // Recursive
    cmd()
        .arg("-r")
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on all
            match_str(&file_a)
                .and(match_str(&file_b))
                .and(match_str(&file_c))
                .and(match_str(&file_d))
                .and(match_str(&file_e)),
        )
        .stderr("")
        .success();

    // recursive and non follow symlinks
    cmd()
        .arg("--recursive")
        .arg("--no-follow-symlinks")
        // Add some threads to instrument the code
        .args(["-p", "2"])
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on "a", "b" and "c"
            match_str(&file_a)
                .and(match_str(&file_b))
                .and(match_str(&file_c))
                .and(match_str(&file_d).not())
                .and(match_str(&file_e).not()),
        )
        .stderr("")
        .success();
}

#[test]
fn test_skip_larger() {
    let rule_file = test_file("rule a { condition: true }");

    let temp = TempDir::new().unwrap();

    // a is size 0
    let file_a = temp.path().join("a");
    fs::write(&file_a, "").unwrap();

    // b is size 100
    let file_b = temp.path().join("b");
    fs::write(&file_b, [0; 100]).unwrap();

    // c is size 1024
    let file_c = temp.path().join("c");
    fs::write(&file_c, [0; 1024]).unwrap();

    let match_file = |input: &Path| predicate::str::contains(format!("a {}", input.display()));
    let skip_file =
        |input: &Path| predicate::str::contains(format!("skipping {}", input.display()));

    // default will match the 3 files
    cmd()
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on "a", "b" and "d"
            match_file(&file_a)
                .and(match_file(&file_b))
                .and(match_file(&file_c)),
        )
        .stderr("")
        .success();

    // Limit to 1024, will skip c
    cmd()
        .args(["--skip-larger", "512"])
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on "a" and "b"
            match_file(&file_a)
                .and(match_file(&file_b))
                .and(match_file(&file_c).not()),
        )
        .stderr(
            skip_file(&file_a)
                .not()
                .and(skip_file(&file_b).not())
                .and(skip_file(&file_c)),
        )
        .success();

    // Limit to 10, will skip all but a
    cmd()
        .args(["-z", "10"])
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            // match on all
            match_file(&file_a)
                .and(match_file(&file_b).not())
                .and(match_file(&file_c).not()),
        )
        .stderr(
            skip_file(&file_a)
                .not()
                .and(skip_file(&file_b))
                .and(skip_file(&file_c)),
        )
        .success();
}

#[test]
fn test_print_module_data() {
    let rule_file = test_file(
        r#"
import "pe"
rule a {
    condition: false
}
"#,
    );

    let input = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("boreal")
        .join("tests")
        .join("assets")
        .join("libyara")
        .join("data")
        .join("mtxex.dll");
    cmd()
        .arg("-D")
        .arg(rule_file.path())
        .arg(input)
        .assert()
        .stdout(
            predicate::str::starts_with("pe\n")
                // Integer
                .and(predicate::str::contains("base_of_code = 4096 (0x1000)"))
                // Undef
                .and(predicate::str::contains("base_of_data[undef]"))
                // Array
                .and(predicate::str::contains(
                    r#"
    data_directories
        [0]
            size = 220 (0xdc)
"#,
                ))
                // Empty array
                .and(predicate::str::contains("delayed_import_details = []"))
                // Bytes printable
                .and(predicate::str::contains(r#"dll_name = "mtxex.dll""#))
                // Bytes non-printable
                .and(predicate::str::contains(
                    "[\"ProductName\"] = { 4d6963726f736f6674ae2057696e646f7773ae204f7065\
                                           726174696e672053797374656d }",
                ))
                // Struct
                .and(predicate::str::contains(
                    r#"
    image_version
        major = 10 (0xa)
        minor = 0 (0x0)
"#,
                ))
                // Dictionary
                .and(predicate::str::contains(
                    r#"
    version_info
        ["CompanyName"] = "Microsoft Corporation"
"#,
                )),
        )
        .stderr("")
        .success();
}

// Test when some inputs in a dir cannot be read
#[test]
#[cfg(unix)]
fn test_input_cannot_read() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let rule_file = test_file("rule bee { condition: true }");

    let temp = TempDir::new().unwrap();
    let child = temp.path().join("child");
    let _file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o000)
        .open(&child)
        .unwrap();

    let subdir = temp.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    fs::set_permissions(&subdir, fs::Permissions::from_mode(0o000)).unwrap();

    cmd()
        .arg("-r")
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout("")
        .stderr(
            predicate::str::contains(format!("Cannot scan file {}", child.display())).and(
                predicate::str::contains(format!("IO error for operation on {}", subdir.display())),
            ),
        )
        // Still successful, since some other files in the directory may have been scanned
        .success();
}