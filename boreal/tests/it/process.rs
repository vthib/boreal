use std::io::{BufRead, BufReader};

use crate::utils::Checker;
use boreal::scanner::ScanError;

const PAGE_SIZE: usize = 4 * 1024 * 1024;

#[test]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_scan_process() {
    // Scan for strings found in the bss and the stack of the test process.
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /test.{10}helper/
        $b = "PAYLOAD_ON_STACK"
    condition:
        all of them
}"#,
    );

    let helper = BinHelper::run("stack");
    checker.check_process(helper.pid(), true);
}

/// Test scanning a pid that do not exist.
#[test]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_process_not_found() {
    let pid = 999_999_999;

    let mut checker = Checker::new(r#" rule a { condition: true }"#);
    checker.assert_success = false;

    checker.check_process(pid, false);
    let err = checker.last_err.unwrap();
    assert!(matches!(err, ScanError::UnknownProcess), "{:?}", err);
    assert_eq!(err.to_string(), "unknown process");
}

/// Test scanning a pid we do not have permissions for.
#[test]
fn test_process_permission_denied() {
    #[cfg(target_os = "linux")]
    if euid_is_root() {
        println!("Cannot run this test as root, ignoring");
        return;
    }

    let pid = if cfg!(windows) { 4 } else { 1 };
    let mut checker = Checker::new(r#" rule a { condition: true }"#);
    checker.assert_success = false;

    checker.check_process(pid, false);
    let err = checker.last_err.unwrap();
    match &err {
        ScanError::CannotListProcessRegions(err) => {
            #[cfg(target_os = "macos")]
            {
                assert_eq!(err.kind(), std::io::ErrorKind::Other, "{:?}", err);
            }
            #[cfg(not(target_os = "macos"))]
            {
                assert_eq!(
                    err.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "{:?}",
                    err
                );
            }
        }
        err => panic!("Unexpected last err: {err:?}"),
    }
    assert!(err
        .to_string()
        .starts_with("error listing memory regions of process"));
}

#[cfg(target_os = "linux")]
fn euid_is_root() -> bool {
    // Quick and dirty way to check the euid of our own pid. We could
    // use getuid, by i'd rather avoid adding another dependency since
    // this can be done with a few lines of code.
    let pid = std::process::id();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    // Find the "Uid: " line.
    let uid_line = status
        .split('\n')
        .find(|line| line.starts_with("Uid:"))
        .unwrap();
    // The effective uid is the second number.
    let euid = uid_line.split_whitespace().nth(2).unwrap();
    let euid: u32 = euid.parse().unwrap();
    euid == 0
}

#[test]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_process_multiple_passes() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /test.{10}helper/
    condition:
        // First pass: string scan
        $a and
        // Second pass: uint32 eval
        uint16be(@a) == 0x7465
}"#,
    );

    let helper = BinHelper::run("stack");
    checker.check_process(helper.pid(), true);
}

#[test]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_process_max_fetched_region_size() {
    use boreal::scanner::ScanParams;

    use crate::utils::get_boreal_full_matches;

    let checker = Checker::new_without_yara(
        r#"
rule a {
    strings:
        $a = "Dwb6r5gd"
    condition:
        $a
}"#,
    );
    let mut scanner = checker.scanner().scanner;
    scanner.set_scan_params(ScanParams::default().max_fetched_region_size(PAGE_SIZE));

    let helper = BinHelper::run("max_fetched_region_size");
    assert_eq!(helper.output.len(), 4);
    let region1 = usize::from_str_radix(&helper.output[0], 16).unwrap();
    let region2 = usize::from_str_radix(&helper.output[1], 16).unwrap();
    let region3 = usize::from_str_radix(&helper.output[2], 16).unwrap();
    let region4 = usize::from_str_radix(&helper.output[3], 16).unwrap();

    let res = scanner.scan_process(helper.pid()).unwrap();
    let res = get_boreal_full_matches(&res);
    let mut expected = vec![
        (b"Dwb6r5gd".as_slice(), region1, 8),
        (b"Dwb6r5gd".as_slice(), region2 + PAGE_SIZE - 8, 8),
    ];
    // Sort by address, since the provided regions might not be in the same order as creation.
    expected.sort_by_key(|v| v.1);

    assert_eq!(res, vec![("default:a".to_owned(), vec![("a", expected)])]);

    scanner.set_scan_params(ScanParams::default().max_fetched_region_size(PAGE_SIZE * 2));
    let res = scanner.scan_process(helper.pid()).unwrap();
    let res = get_boreal_full_matches(&res);
    let mut expected = vec![
        (b"Dwb6r5gd".as_slice(), region1, 8),
        (b"Dwb6r5gd".as_slice(), region2 + PAGE_SIZE - 8, 8),
        (b"Dwb6r5gd".as_slice(), region3 + PAGE_SIZE - 4, 8),
        (b"Dwb6r5gd".as_slice(), region4 + PAGE_SIZE + 200, 8),
    ];
    // Sort by address, since the provided regions might not be in the same order as creation.
    expected.sort_by_key(|v| v.1);

    assert_eq!(res, vec![("default:a".to_owned(), vec![("a", expected)])]);
}

#[test]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_process_memory_chunk_size() {
    use boreal::scanner::ScanParams;

    use crate::utils::get_boreal_full_matches;

    let checker = Checker::new_without_yara(
        r#"
rule a {
    strings:
        $a = "T5aI0uhg7S"
    condition:
        $a
}"#,
    );
    let mut scanner = checker.scanner().scanner;
    scanner.set_scan_params(ScanParams::default().memory_chunk_size(Some(2 * PAGE_SIZE)));

    let helper = BinHelper::run("memory_chunk_size");
    assert_eq!(helper.output.len(), 3);
    let region1 = usize::from_str_radix(&helper.output[0], 16).unwrap();
    let region2 = usize::from_str_radix(&helper.output[1], 16).unwrap();
    let region3 = usize::from_str_radix(&helper.output[2], 16).unwrap();

    let res = scanner.scan_process(helper.pid()).unwrap();
    let res = get_boreal_full_matches(&res);
    let mut expected = vec![
        (b"T5aI0uhg7S".as_slice(), region1 + (PAGE_SIZE - 10), 10),
        (b"T5aI0uhg7S".as_slice(), region3 + 3 * PAGE_SIZE - 5, 10),
        (b"T5aI0uhg7S".as_slice(), region3 + 4 * PAGE_SIZE + 4096, 10),
    ];
    // Sort by address, since the provided regions might not be in the same order as creation.
    expected.sort_by_key(|v| v.1);
    assert_eq!(res, vec![("default:a".to_owned(), vec![("a", expected)])]);

    scanner.set_scan_params(ScanParams::default().memory_chunk_size(Some(3 * PAGE_SIZE)));
    let res = scanner.scan_process(helper.pid()).unwrap();
    let res = get_boreal_full_matches(&res);
    let mut expected = vec![
        (b"T5aI0uhg7S".as_slice(), region1 + (PAGE_SIZE - 10), 10),
        // We now see the one in region2
        (b"T5aI0uhg7S".as_slice(), region2 + 2 * PAGE_SIZE - 5, 10),
        // But no longer see the first one in region3
        (b"T5aI0uhg7S".as_slice(), region3 + 4 * PAGE_SIZE + 4096, 10),
    ];
    // Sort by address, since the provided regions might not be in the same order as creation.
    expected.sort_by_key(|v| v.1);

    assert_eq!(res, vec![("default:a".to_owned(), vec![("a", expected)])]);
}

#[test]
// Need super user to run on macos
#[cfg_attr(target_os = "macos", ignore)]
fn test_process_file_copy_on_write() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        // String written in the file
        $a = "RAmEtbQfVE"
    condition:
        $a
}

rule b {
    strings:
        // String written over the file contents in the private copy
        // of the process
        $b = "ste3Cd9Te8"
    condition:
        $b
}"#,
    );

    let helper = BinHelper::run("file_copy_on_write");
    assert_eq!(helper.output.len(), 2);
    let region1 = usize::from_str_radix(&helper.output[0], 16).unwrap();
    let region2 = usize::from_str_radix(&helper.output[1], 16).unwrap();

    let mut expected = vec![
        (b"ste3Cd9Te8".as_slice(), region1 + 2048 - 500, 10),
        (b"ste3Cd9Te8".as_slice(), region2 + 1000, 10),
        (b"ste3Cd9Te8".as_slice(), region2 + 4096 - 5, 10),
    ];
    expected.sort_by_key(|v| v.1);

    checker.check_process_full_matches(
        helper.pid(),
        vec![("default:b".to_owned(), vec![("b", expected)])],
    );
}

// Check that the RAM of a process does not grow too much when it is scanned.
// This is the purpose of the pagemap optimization on linux, so it is only
// implemented on linux.
#[test]
#[cfg(target_os = "linux")]
fn test_process_scan_ram_increase() {
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = "PAYLOAD_ON_STACK"
    condition:
        all of them
}"#,
    );

    let helper = BinHelper::run("stack");

    fn get_vm_rss(pid: u32) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).unwrap();
        let rss_line = status
            .split('\n')
            .find(|line| line.starts_with("VmRSS"))
            .unwrap();
        let value = rss_line.split_ascii_whitespace().nth(1).unwrap();
        // Value is in kB
        value.parse::<u64>().unwrap() * 1024
    }

    let vm_rss_before = get_vm_rss(helper.pid());
    checker.check_process(helper.pid(), true);
    let vm_rss_after = get_vm_rss(helper.pid());

    // Check that the RSS after is "close" to the RSS before, ie, less than 10% more.
    // This fails if just reading all of /proc/pid/mem.
    let diff = vm_rss_after.saturating_sub(vm_rss_before);
    assert!(
        diff < vm_rss_before / 10,
        "rss before: {}, rss after: {}, increase: {:.2}%",
        vm_rss_before,
        vm_rss_after,
        (diff as f64) * 100. / (vm_rss_before as f64)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_process_rework_file() {
    let mut checker = Checker::new(
        r#"
rule good {
    strings:
        $good = "i7B7hm8PoV"
    condition:
        $good
}

rule bad {
    strings:
        $bad = "z8Nwed8LTu"
    condition:
        $bad
}"#,
    );

    let helper = BinHelper::run("rework_file");
    assert_eq!(helper.output.len(), 3);
    let region1 = usize::from_str_radix(&helper.output[0], 16).unwrap();
    let _region2 = usize::from_str_radix(&helper.output[1], 16).unwrap();
    let region3 = usize::from_str_radix(&helper.output[2], 16).unwrap();

    let mut expected = vec![
        (b"i7B7hm8PoV".as_slice(), region1 + PAGE_SIZE + 100, 10),
        (b"i7B7hm8PoV".as_slice(), region3 + PAGE_SIZE - 500, 10),
    ];
    expected.sort_by_key(|v| v.1);

    checker.check_process_full_matches(
        helper.pid(),
        vec![("default:good".to_owned(), vec![("good", expected)])],
    );
}

struct BinHelper {
    proc: std::process::Child,
    output: Vec<String>,
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
        let mut lines = Vec::new();
        let mut buffer = String::new();
        loop {
            buffer.clear();
            stdout.read_line(&mut buffer).unwrap();
            if buffer.trim() == "ready" {
                break;
            }
            lines.push(buffer.trim().to_owned());
        }
        Self {
            proc: child,
            output: lines,
        }
    }

    fn pid(&self) -> u32 {
        self.proc.id()
    }
}

impl Drop for BinHelper {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait();
    }
}
