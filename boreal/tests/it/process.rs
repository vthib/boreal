use std::io::{BufRead, BufReader};
#[cfg(any(target_os = "linux", windows))]
use std::path::Path;

#[cfg(any(target_os = "linux", windows))]
use crate::utils::Checker;
#[cfg(any(target_os = "linux", windows))]
use boreal::scanner::ScanError;

#[test]
#[cfg(any(target_os = "linux", windows))]
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
#[cfg(any(target_os = "linux", windows))]
fn test_process_not_found() {
    // First, find an unused PID. Lets take a very big number, and have
    // some retry code until we find a proper one.

    let mut pid = 999_999_999;
    while Path::new("proc").join(pid.to_string()).exists() {
        pid += 1;
    }

    let mut checker = Checker::new(r#" rule a { condition: true }"#);
    checker.assert_success = false;

    checker.check_process(pid, false);
    let err = checker.last_err.unwrap();
    assert!(matches!(err, ScanError::UnknownProcess), "{:?}", err);
    assert_eq!(err.to_string(), "unknown process");
}

/// Test scanning a pid we do not have permissions for.
#[test]
#[cfg(any(target_os = "linux", windows))]
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
            #[cfg(windows)]
            {
                use windows::Win32::Foundation::E_ACCESSDENIED;

                assert_eq!(err.raw_os_error(), Some(E_ACCESSDENIED.0 as _), "{:?}", err);
            }
            #[cfg(target_os = "linux")]
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
#[cfg(any(target_os = "linux", windows))]
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
    scanner.set_scan_params(ScanParams::default().max_fetched_region_size(20));

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
        (b"Dwb6r5gd".as_slice(), region2 + 10, 8),
    ];
    // Sort by address, since the provided regions might not be in the same order as creation.
    expected.sort_by_key(|v| v.1);

    assert_eq!(res, vec![("default:a".to_owned(), vec![("a", expected)])]);

    scanner.set_scan_params(ScanParams::default().max_fetched_region_size(40));
    let res = scanner.scan_process(helper.pid()).unwrap();
    let res = get_boreal_full_matches(&res);
    let mut expected = vec![
        (b"Dwb6r5gd".as_slice(), region1, 8),
        (b"Dwb6r5gd".as_slice(), region2 + 10, 8),
        (b"Dwb6r5gd".as_slice(), region3 + 16, 8),
        (b"Dwb6r5gd".as_slice(), region4 + 26, 8),
    ];
    // Sort by address, since the provided regions might not be in the same order as creation.
    expected.sort_by_key(|v| v.1);

    assert_eq!(res, vec![("default:a".to_owned(), vec![("a", expected)])]);
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
