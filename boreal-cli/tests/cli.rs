#![allow(missing_docs)]
#![allow(unused_results)]
#![allow(unused_crate_dependencies)]
#![allow(clippy::pedantic)]

use std::io::{BufRead, Write};
use std::path::Path;
use std::{fs, io::BufReader};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};

fn cmd() -> Command {
    Command::cargo_bin("boreal").unwrap()
}

fn test_file(contents: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents).unwrap();
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
        .stderr(predicate::str::contains(
            "Cannot read rules file do_not_exist: ",
        ))
        .failure();

    // Invalid path to input
    let rule_file = test_file(b"");
    cmd()
        .arg(rule_file.path())
        .arg("bad_input")
        .assert()
        .stdout("")
        .stderr(predicate::str::contains("Cannot scan bad_input"))
        .failure();
}

#[test]
fn test_scan_file() {
    let rule_file = test_file(
        br#"
rule my_rule {
    strings:
        $a = "abc"
    condition:
        any of them
}"#,
    );

    let input = test_file(b"aaa");
    // Not matching
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr("")
        .success();

    let input = test_file(b"zeabce");
    // Matching
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("my_rule {}\n", input.path().display()))
        .stderr("")
        .success();
}

#[test]
// Need super user to run on linux and macos
#[cfg_attr(unix, ignore)]
fn test_scan_process() {
    let rule_file = test_file(
        br#"
rule process_scan {
    strings:
        $a = "PAYLOAD_ON_STACK"
    condition:
        $a
}"#,
    );

    let proc = BinHelper::run("stack");
    let pid = proc.pid();

    // Not matching
    cmd()
        .arg(rule_file.path())
        .arg(pid.to_string())
        .assert()
        .stdout(format!("process_scan {}\n", pid))
        .stderr("")
        .success();
}

#[test]
#[cfg(target_os = "linux")]
fn test_scan_process_not_found() {
    let rule_file = test_file(b"rule process_scan { condition: true }");

    // First, find an unused PID. Lets take a very big number, and have
    // some retry code until we find a proper one.
    let mut pid = 999_999_999;
    while Path::new("proc").join(pid.to_string()).exists() {
        pid += 1;
    }

    // Not matching
    cmd()
        .arg(rule_file.path())
        .arg(pid.to_string())
        .assert()
        .stdout("")
        .stderr(format!("Cannot scan {}: unknown process\n", pid))
        .failure();
}

#[test]
fn test_scan_file_with_process_name() {
    // Test that scanning a file with an integer name works, and does not
    // attempt to scan a process.
    let rule_file = test_file(
        br#"
rule is_file {
    strings:
        $a = "buzo"
    condition:
        any of them
}"#,
    );

    let temp = TempDir::new().unwrap();
    let file = temp.path().join("1");
    fs::write(file, "gabuzomeu").unwrap();
    // Matching
    cmd()
        .current_dir(temp.path())
        .arg(rule_file.path())
        .arg("1")
        .assert()
        .stdout("is_file 1\n")
        .stderr("")
        .success();
}

#[test]
fn test_rule_error() {
    let rule_file = test_file(
        br#"rule a {
        strings: $a = /[z-a]/
        condition: $a
    }"#,
    );

    let input = test_file(b"");
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
        br#"rule rule_with_warning {
            condition:
                "a"
        }
        "#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    // Warning is OK and rule is eval'ed
    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("rule_with_warning {path}\n"))
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

    // Ignore warnings
    cmd()
        .arg("-w")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("rule_with_warning {path}\n"))
        .stderr("")
        .success();
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
    let input = test_file(b"abc");
    cmd()
        .arg(&rule_a)
        .arg(input.path())
        .assert()
        .stdout(format!("included {}\n", input.path().display()))
        .success();

    // Match on both
    let input = test_file(b"xyz abc");
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
    let input = test_file(b"");
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

    let rule_file = test_file(b"rule a { condition: true }");

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
    let rule_file = test_file(b"rule a { condition: true }");

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
        br#"
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

#[test]
fn test_print_string_stats() {
    let rule_file = test_file(
        br#"
rule a {
    strings:
        $a = "ab<de>g"
        $b = { 01 ( FE | EF ) }
        $c = /foo\d??barbaz/ fullword
        $d = /.{10}/ fullword
    condition:
        any of them
}
"#,
    );

    let stats = r#"
  $a = "ab<de>g"
    literals: ["ab<de>g"]
    atoms: ["<de>"]
    atoms quality: 84
    algo: Literals
  $b = { 01 ( FE | EF ) }
    literals: [{ 01fe }, { 01ef }]
    atoms: [{ 01fe }, { 01ef }]
    atoms quality: 44
    algo: Literals
  $c = /foo\d??barbaz/ fullword
    literals: ["barbaz"]
    atoms: ["rbaz"]
    atoms quality: 80
    algo: Atomized { NonGreedy { reverse: Dfa, forward: none } }
  $d = /.{10}/ fullword
    literals: []
    atoms: []
    atoms quality: 0
    algo: Raw
"#;

    let input = test_file(b"");
    cmd()
        .arg("--string-stats")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            "default:a (from {}){}",
            rule_file.path().display(),
            stats
        ))
        .stderr("")
        .success();
}

#[test]
fn test_print_scan_stats() {
    let rule_file = test_file(
        br#"
rule a {
    strings:
        $a = "abc"
    condition:
        any of them
}
"#,
    );

    let input = test_file(b"abc");
    cmd()
        .arg("--scan-stats")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(
            predicate::str::is_match(
                r"Evaluation \{
    no_scan_eval_duration: .*,
    ac_duration: .*,
    fetch_memory_duration: .*,
    ac_confirm_duration: .*,
    nb_ac_matches: .*,
    rules_eval_duration: .*,
    raw_regexes_eval_duration: .*,
    memory_scanned_size: .*,
    nb_memory_chunks: .*,
\}
",
            )
            .unwrap(),
        )
        .stderr("")
        .success();
}

// Test when some inputs in a dir cannot be read
#[test]
#[cfg(unix)]
fn test_input_cannot_read() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let rule_file = test_file(b"rule bee { condition: true }");

    let temp = TempDir::new().unwrap();
    let child = temp.path().join("child");
    let _file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
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

#[test]
fn test_module_names() {
    cmd()
        .arg("-M")
        .assert()
        .stdout(
            predicate::str::contains("math\n")
                .and(predicate::str::contains("string\n"))
                .and(predicate::str::contains("time\n")),
        )
        .stderr("")
        // Still successful, since some other files in the directory may have been scanned
        .success();
}

#[test]
#[cfg(feature = "memmap")]
fn test_no_mmap() {
    let rule_file = test_file(
        br#"
rule first {
    strings:
        $a = "abc"
    condition:
        any of them
}
rule second {
    strings:
        $a = "xyz"
    condition:
        any of them
}"#,
    );

    let input = test_file(b"xyabcz");
    // Not matching
    cmd()
        .arg("--no-mmap")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("first {}\n", input.path().display()))
        .stderr("")
        .success();
}

#[test]
fn test_console_log() {
    let rule_file = test_file(
        br#"
import "console"

rule logger {
    condition:
        console.log("this is ", "a log")
}"#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    cmd()
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("this is a log\nlogger {path}\n"))
        .stderr("")
        .success();

    // Logs can be disabled with the -q flag
    cmd()
        .arg("-q")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("logger {path}\n"))
        .stderr("")
        .success();
}

#[test]
fn test_invalid_fragmented_scan_mode() {
    // Invalid path to rule
    cmd()
        .arg("--fragmented-scan-mode")
        .arg("bad_value")
        .arg("rules.yar")
        .arg("input")
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(
            "invalid value 'bad_value' for \
            '--fragmented-scan-mode <legacy|fast|singlepass>\': invalid value",
        ))
        .failure();
}

#[test]
fn test_invalid_compiler_profile() {
    cmd()
        .arg("--profile")
        .arg("bad_value")
        .arg("rules.yar")
        .arg("input")
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(
            "invalid value 'bad_value' for \
            '--profile <speed|memory>\': invalid value",
        ))
        .failure();
}

#[test]
fn test_tags() {
    let rule_file = test_file(
        br#"
rule notag {
    condition:
        true
}
rule tag1: first {
    condition:
        true
}
rule tag3: first second third {
    condition:
        true
}
"#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    // Test print tags
    cmd()
        .arg("-g")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            "notag [] {path}\n\
             tag1 [first] {path}\n\
             tag3 [first,second,third] {path}\n"
        ))
        .stderr("")
        .success();

    // Test filter by tag
    cmd()
        .arg("-t")
        .arg("first")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("tag1 {path}\ntag3 {path}\n"))
        .stderr("")
        .success();
    cmd()
        .arg("--tag=third")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("tag3 {path}\n"))
        .stderr("")
        .success();
    cmd()
        .arg("-t")
        .arg("")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr("")
        .success();
}

#[test]
fn test_identifier() {
    let rule_file = test_file(
        br#"
rule first { condition: true }
rule second { condition: true }
"#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    // Test filter by identifier
    cmd()
        .arg("-i")
        .arg("first")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("first {path}\n"))
        .stderr("")
        .success();
    cmd()
        .arg("--identifier=second")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("second {path}\n"))
        .stderr("")
        .success();
    cmd()
        .arg("--identifier=third")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr("")
        .success();
}

#[test]
fn test_print_meta() {
    let rule_file = test_file(
        br#"
rule first: tag {
    meta:
        integer = -15
        string = "d mol"
        test = true
    condition:
        true
}
rule second: tag {
    condition:
        true
}
rule third: tag {
    meta:
        value = "ok"
    condition:
        true
}
rule fourth { condition: true }
"#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    // Test print meta
    cmd()
        .arg("-m")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            "first [integer=-15,string=\"d mol\",test=true] {path}\n\
             second [] {path}\n\
             third [value=\"ok\"] {path}\n\
             fourth [] {path}\n"
        ))
        .stderr("")
        .success();

    // Test print meta + tag
    cmd()
        .arg("-g")
        .arg("--print-meta")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            "first [tag] [integer=-15,string=\"d mol\",test=true] {path}\n\
             second [tag] [] {path}\n\
             third [tag] [value=\"ok\"] {path}\n\
             fourth [] [] {path}\n"
        ))
        .stderr("")
        .success();
}

#[test]
fn test_print_string_matches() {
    let rule_file = test_file(
        br#"
rule my_rule {
    strings:
        $a = /<.{1,5}?>/
        $b = "abc"
    condition:
        // The rule can be evaluated without scanning the strings.
        // This ensures that printing strings forces the computation of the
        // string matches.
        true or any of them
}"#,
    );

    let input = test_file(
        b"<a>\n
<<abc>d>\n
<\x01\x02>\n
<a\tv>\n
<a\xFF>>\n
",
    );
    let path = input.path().display();

    // Test match data only
    cmd()
        .arg("-s")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            r#"my_rule {path}
0x0:$a: <a>
0x5:$a: <<abc>
0x6:$a: <abc>
0xf:$a: <\x01\x02>
0x15:$a: <a\tv>
0x1c:$a: <a\xff>
0x7:$b: abc
"#
        ))
        .stderr("")
        .success();

    // Test match length only
    cmd()
        .arg("-L")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            r#"my_rule {path}
0x0:3:$a
0x5:6:$a
0x6:5:$a
0xf:4:$a
0x15:5:$a
0x1c:4:$a
0x7:3:$b
"#
        ))
        .stderr("")
        .success();

    // Test both
    cmd()
        .arg("--print-strings")
        .arg("--print-string-length")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            r#"my_rule {path}
0x0:3:$a: <a>
0x5:6:$a: <<abc>
0x6:5:$a: <abc>
0xf:4:$a: <\x01\x02>
0x15:5:$a: <a\tv>
0x1c:4:$a: <a\xff>
0x7:3:$b: abc
"#
        ))
        .stderr("")
        .success();
}

#[test]
fn test_print_string_xor_key() {
    let rule_file = test_file(
        br#"
rule my_rule {
    strings:
        $a = "aaa" ascii wide xor
    condition:
        // The rule can be evaluated without scanning the strings.
        // This ensures that printing xor keys forces the computation of the
        // string matches.
        true or any of them
}"#,
    );

    let input = test_file(b"aaa\nbbb\nabcccba\nB#B#B#\n");
    let path = input.path().display();

    // Test xor only
    cmd()
        .arg("-X")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            r#"my_rule {path}
0x0:$a:xor(0x00,aaa)
0x4:$a:xor(0x03,aaa)
0xa:$a:xor(0x02,aaa)
0x10:$a:xor(0x23,a\x00a\x00a\x00)
"#
        ))
        .stderr("")
        .success();

    // With match data
    cmd()
        .arg("-Xs")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            r#"my_rule {path}
0x0:$a:xor(0x00,aaa): aaa
0x4:$a:xor(0x03,aaa): bbb
0xa:$a:xor(0x02,aaa): ccc
0x10:$a:xor(0x23,a\x00a\x00a\x00): B#B#B#
"#
        ))
        .stderr("")
        .success();
}

#[test]
fn test_timeout() {
    let rule_file = test_file(
        br#"
rule too_long {
    condition:
        for all i in (0..9223372036854775807) : (
            for all j in (0..9223372036854775807) : (
                for all k in (0..9223372036854775807) : (
                    for all l in (0..9223372036854775807) : (
                        i + j + k + l >= 0
                    )
                )
            )
        )
}"#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    // Test filter by identifier
    cmd()
        .arg("-a")
        .arg("1")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(format!("Cannot scan {path}: timeout\n"))
        .failure();
}

#[test]
fn test_print_namespace() {
    let rule_file = test_file(
        br#"
rule first { condition: true }
"#,
    );

    let input = test_file(b"");
    let path = input.path().display();

    // Test filter by identifier
    cmd()
        .arg("-e")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("default:first {path}\n"))
        .stderr("")
        .success();
}

#[test]
fn test_define_symbol() {
    let input = test_file(b"");
    let path = input.path().display();

    let rule_file = test_file(
        br#"
rule symbols {
    condition:
        symbol_float + 4.3 == 2.5 and
        symbol_int + 5 == 2 and
        symbol_true == true and
        symbol_false == false and
        symbol_str == "a_string" and
        symbol_str2 == "2.5a" and
        symbol_empty == ""
}
"#,
    );

    cmd()
        .arg("-d")
        .arg("symbol_float=-1.8")
        .arg("--define=symbol_int=-3")
        .arg("--define")
        .arg("symbol_true=true")
        .arg("--define")
        .arg("symbol_false=false")
        .arg("--define")
        .arg("symbol_str=a_string")
        .arg("--define")
        .arg("symbol_str2=2.5a")
        .arg("--define")
        .arg("symbol_empty=")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("symbols {path}\n"))
        .stderr("")
        .success();

    // Test a bad define
    cmd()
        .arg("-d")
        .arg("name")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(
            "invalid value 'name' for '--define <VAR=VALUE>': \
            missing '=' delimiter",
        ))
        .failure();

    // Test a mismatched type
    let bad_rule = test_file(
        br#"
rule bad_symbols {
    condition:
        symbol_float == "-1.8"
}
"#,
    );
    cmd()
        .arg("-d")
        .arg("symbol_float=-1.8")
        .arg(bad_rule.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(predicate::str::contains("expressions have invalid types"))
        .failure();
}

#[test]
fn test_scan_list() {
    let rule_file = test_file(b"rule a { condition: true }");

    // dir1
    //   a
    //   b
    // dir2
    //   subdir
    //     c
    let dir1 = TempDir::new().unwrap();
    let file_a = dir1.path().join("a");
    fs::write(&file_a, "").unwrap();
    let file_b = dir1.path().join("b");
    fs::write(&file_b, "").unwrap();

    let dir2 = TempDir::new().unwrap();
    let subdir = dir2.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    let file_c = subdir.join("c");
    fs::write(&file_c, "").unwrap();

    let match_str = |input: &Path| predicate::str::contains(format!("a {}", input.display()));

    // dir1 + c, will match the 3 filse
    let list = test_file(format!("{}\n{}\n", dir1.path().display(), file_c.display()).as_bytes());
    cmd()
        .arg("--scan-list")
        .arg(rule_file.path())
        .arg(list.path())
        .assert()
        .stdout(
            match_str(&file_a)
                .and(match_str(&file_b))
                .and(match_str(&file_c)),
        )
        .stderr("")
        .success();

    // a + dir2, but not recursive, will match only a
    let list = test_file(format!("{}\n{}\n", file_a.display(), dir2.path().display()).as_bytes());
    cmd()
        .arg("--scan-list")
        .arg(rule_file.path())
        .arg(list.path())
        .assert()
        .stdout(
            match_str(&file_a)
                .and(match_str(&file_b).not())
                .and(match_str(&file_c).not()),
        )
        .stderr("")
        .success();

    // When recursive, will match c
    cmd()
        .arg("--scan-list")
        .arg("-r")
        .arg(rule_file.path())
        .arg(list.path())
        .assert()
        .stdout(
            match_str(&file_a)
                .and(match_str(&file_b).not())
                .and(match_str(&file_c)),
        )
        .stderr("")
        .success();

    // Empty
    let list = test_file(b"");
    cmd()
        .arg("--scan-list")
        .arg(rule_file.path())
        .arg(list.path())
        .assert()
        .stdout("")
        .stderr("")
        .success();

    // Do these tests only on linux, as the error messages can depend on the OS.
    if cfg!(target_os = "linux") {
        // path is a directory
        // On linux, the open on a dir works but the read fails, making
        // this a great test to test the read failure case.
        cmd()
            .arg("--scan-list")
            .arg(rule_file.path())
            .arg(dir1.path())
            .assert()
            .stdout("")
            .stderr(predicate::str::contains(format!(
                "cannot read from scan list {}: Is a directory",
                dir1.path().display()
            )))
            .failure();

        // path does not exist
        cmd()
            .arg("--scan-list")
            .arg(rule_file.path())
            .arg("invalid_path")
            .assert()
            .stdout("")
            .stderr(predicate::str::contains(
                "cannot open scan list invalid_path: No such file or directory",
            ))
            .failure();
    }
}

#[test]
fn test_negate() {
    let rule_file = test_file(
        br#"
rule a { condition: true }
rule b { condition: false }
rule c { condition: true }
rule d { condition: false }
"#,
    );

    let input = test_file(b"");
    // Not matching
    cmd()
        .arg("-n")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            "b {}\nd {}\n",
            input.path().display(),
            input.path().display()
        ))
        .stderr("")
        .success();
}

#[test]
fn test_count() {
    let rule_file = test_file(
        br#"
rule a {
    strings:
        $ = "abc"
    condition:
        any of them
}
rule b {
    strings:
        $ = "def"
    condition:
        any of them
}
"#,
    );

    let temp = TempDir::new().unwrap();
    let file_a = temp.path().join("a");
    fs::write(&file_a, "abc").unwrap();
    let file_b = temp.path().join("b");
    fs::write(&file_b, "abcdef").unwrap();
    let file_c = temp.path().join("c");
    fs::write(&file_c, "").unwrap();

    // Test against a single file
    cmd()
        .arg("-c")
        .arg(rule_file.path())
        .arg(&file_a)
        .assert()
        .stdout(format!("{}: 1\n", file_a.display()))
        .stderr("")
        .success();

    // Test in combination with the negate flag
    cmd()
        .arg("-cn")
        .arg(rule_file.path())
        .arg(&file_c)
        .assert()
        .stdout(format!("{}: 2\n", file_c.display()))
        .stderr("")
        .success();

    // Test against a directory
    cmd()
        .arg("-c")
        .arg(rule_file.path())
        .arg(temp.path())
        .assert()
        .stdout(
            predicate::str::contains(format!("{}: 1", file_a.display()))
                .and(predicate::str::contains(format!("{}: 2", file_b.display())))
                .and(predicate::str::contains(format!("{}: 0", file_c.display()))),
        )
        .stderr("")
        .success();
}

#[test]
#[cfg_attr(unix, ignore)]
fn test_count_process() {
    let rule_file = test_file(
        br#"
rule process_scan {
    strings:
        $a = "PAYLOAD_ON_STACK"
    condition:
        $a
}"#,
    );

    let proc = BinHelper::run("stack");
    let pid = proc.pid();

    // Not matching
    cmd()
        .arg("--count")
        .arg(rule_file.path())
        .arg(pid.to_string())
        .assert()
        .stdout(format!("{pid}: 1\n"))
        .stderr("")
        .success();
}

#[test]
#[cfg_attr(unix, ignore)]
fn test_count_limit() {
    let rule_file = test_file(
        br#"
rule a { condition: true }
rule b { condition: true }
rule c { condition: true }
"#,
    );

    let input = test_file(b"");
    cmd()
        .arg("-l")
        .arg("2")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!(
            "a {}\nb {}\n",
            input.path().display(),
            input.path().display(),
        ))
        .stderr("")
        .success();

    // Also works with a process
    let proc = BinHelper::run("stack");
    let pid = proc.pid();

    // Not matching
    cmd()
        .arg("--max-rules=2")
        .arg(rule_file.path())
        .arg(pid.to_string())
        .assert()
        .stdout(format!("a {pid}\nb {pid}\n"))
        .stderr("")
        .success();
}

#[test]
fn test_max_strings_per_rule() {
    let rule_file = test_file(
        br#"
rule a {
    strings:
        $a = "aaa"
        $b = "bbb"
        $c = "ccc"
    condition:
        any of them
}
"#,
    );

    let input = test_file(b"");
    cmd()
        .arg("--max-strings-per-rule=2")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(
            predicate::str::contains("error").and(predicate::str::contains(
                "the rule contains more than 2 strings",
            )),
        )
        .failure();
}

#[test]
fn test_string_max_nb_matches() {
    let rule_file = test_file(
        br#"
rule a {
    strings:
        $a = "a"
    condition:
        any of them
}
"#,
    );

    let warning = "warning: string $a in rule default:a reached the maximum number of matches";

    // Default behavior is to print the warning and continue
    let input = test_file(b"aaaa");
    cmd()
        .arg("--string-max-nb-matches=2")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("a {}\n", input.path().display()))
        .stderr(predicate::str::contains(warning))
        .success();

    // We can ignore warnings with a flag
    cmd()
        .arg("--string-max-nb-matches=2")
        .arg("--no-warnings")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout(format!("a {}\n", input.path().display()))
        .stderr("")
        .success();

    // Or we can abort on warnings
    cmd()
        .arg("--string-max-nb-matches=2")
        .arg("--fail-on-warnings")
        .arg(rule_file.path())
        .arg(input.path())
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(warning))
        .success();
}

#[test]
#[cfg(feature = "serialize")]
fn test_save_load() {
    let rule_file = test_file(
        br#"
import "console"

rule a {
    condition:
        console.log("foo")
}
"#,
    );

    let temp = TempDir::new().unwrap();
    let save_path = temp.path().join("serialized_rules");
    let input = temp.path().join("input");
    fs::write(&input, b"a").unwrap();

    // Save into the file
    cmd()
        .arg("--save")
        .arg(rule_file.path())
        .arg(&save_path)
        .assert()
        .success();

    // Now reload
    cmd()
        .arg("-C")
        .arg(&save_path)
        .arg(&input)
        .assert()
        .stdout(format!("foo\na {}\n", input.display()))
        .stderr("")
        .success();
}

#[test]
#[cfg(feature = "serialize")]
fn test_invalid_load() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("input");
    fs::write(&input, b"a").unwrap();

    // Non existing path
    let fake_path = temp.path().join("non_existing");
    cmd()
        .arg("-C")
        .arg(&fake_path)
        .arg(&input)
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(format!(
            "Unable to read from {}",
            fake_path.display()
        )))
        .failure();

    // Failure during deserialization
    cmd()
        .arg("-C")
        .arg(&input)
        .arg(&input)
        .assert()
        .stdout("")
        .stderr(predicate::str::contains("Unable to deserialize rules"))
        .failure();
}

#[test]
#[cfg(feature = "serialize")]
fn test_invalid_save() {
    let temp = TempDir::new().unwrap();
    let rule = temp.path().join("rule");
    fs::write(&rule, b"rule a { condition: true }").unwrap();

    // Non existing path
    cmd()
        .arg("--save")
        .arg(&rule)
        .arg(&rule)
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(format!(
            "File {} already exists",
            rule.display()
        )))
        .failure();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let subdir = temp.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        let out = subdir.join("out");

        // cannot inspect file
        let mut perms = fs::metadata(&subdir).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&subdir, perms).unwrap();
        cmd()
            .arg("--save")
            .arg(&rule)
            .arg(&out)
            .assert()
            .stdout("")
            .stderr(predicate::str::contains(format!(
                "Unable to inspect file {}",
                out.display()
            )))
            .failure();

        // cannot create file
        let mut perms = fs::metadata(&subdir).unwrap().permissions();
        perms.set_mode(0o555);
        fs::set_permissions(&subdir, perms).unwrap();
        let out_path = subdir.join("out");
        cmd()
            .arg("--save")
            .arg(&rule)
            .arg(&out_path)
            .assert()
            .stdout("")
            .stderr(predicate::str::contains(format!(
                "Unable to create file {}",
                out.display()
            )))
            .failure();
    }
}

#[test]
#[cfg(feature = "cuckoo")]
fn test_module_data() {
    let temp = TempDir::new().unwrap();

    let rule = temp.path().join("rule");
    fs::write(
        &rule,
        r#"
import "cuckoo"

rule a {
    condition:
        cuckoo.network.host(/bcd/) == 1
}"#,
    )
    .unwrap();

    let data = temp.path().join("data");
    fs::write(&data, r#"{ "network": { "hosts": ["abcde"] } }"#).unwrap();

    let input = temp.path().join("input");
    fs::write(&input, "").unwrap();

    cmd()
        .arg(format!("--module-data=cuckoo={}", data.display()))
        .arg(&rule)
        .arg(&input)
        .assert()
        .stdout(format!("a {}\n", input.display()))
        .stderr("")
        .success();
}

#[test]
#[cfg(feature = "cuckoo")]
fn test_invalid_module_data() {
    let temp = TempDir::new().unwrap();

    let rule = temp.path().join("rule");
    fs::write(&rule, "rule a { condition: true }").unwrap();

    let data = temp.path().join("data");
    fs::write(&data, r"{").unwrap();

    let input = temp.path().join("input");
    fs::write(&input, "").unwrap();

    // Invalid module data
    cmd()
        .arg("-x")
        .arg("name")
        .arg(&rule)
        .arg(&input)
        .assert()
        .stdout("")
        .stderr(predicate::str::contains(
            "invalid value 'name' for '--module-data <MODULE=FILE>': \
            missing '=' delimiter",
        ))
        .failure();

    // Unknown module
    cmd()
        .arg(format!("--module-data=piou={}", data.display()))
        .arg(&rule)
        .arg(&input)
        .assert()
        .stdout("")
        .stderr("Cannot set data for unsupported module piou\n")
        .failure();

    // Non existing file
    cmd()
        .arg("-x")
        .arg("cuckoo=non_existing")
        .arg(&rule)
        .arg(&input)
        .assert()
        .stderr(predicate::str::contains(
            "Unable to read cuckoo data from file non_existing",
        ))
        .failure();

    // Cannot parse data
    cmd()
        .arg(format!("--module-data=cuckoo={}", data.display()))
        .arg(&rule)
        .arg(&input)
        .assert()
        .stdout("")
        .stderr("The data for the cuckoo module is invalid\n")
        .failure();
}

// Copied in `boreal/tests/it/utils.rs`. Not trivial to share, and won't be
// modified too frequently.
struct BinHelper {
    proc: std::process::Child,
}

impl BinHelper {
    fn run(arg: &str) -> Self {
        // Path to current exe
        let path = std::env::current_exe().unwrap();
        // Path to "deps" dir
        let path = path.parent().unwrap();
        // Path to parent of deps dir, ie destination of build artifacts
        let path = path.parent().unwrap();
        // Now select the bin helper
        let path = path.join(if cfg!(windows) {
            "boreal-test-helpers.exe"
        } else {
            "boreal-test-helpers"
        });
        if !path.exists() {
            panic!(
                "File {} not found. \
                You need to compile the `boreal-test-helpers` crate to run this test",
                path.display()
            );
        }
        let mut child = std::process::Command::new(path)
            .arg(arg)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        // Accumulate read inputs until the "ready" line is found
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut buffer = String::new();
        loop {
            buffer.clear();
            stdout.read_line(&mut buffer).unwrap();
            if buffer.trim() == "ready" {
                break;
            }
        }
        Self { proc: child }
    }

    fn pid(&self) -> u32 {
        self.proc.id()
    }
}

impl Drop for BinHelper {
    fn drop(&mut self) {
        drop(self.proc.kill());
        drop(self.proc.wait());
    }
}
