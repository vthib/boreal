#[cfg(any(target_os = "linux", windows))]
use std::path::Path;

#[cfg(any(target_os = "linux", windows))]
use crate::utils::Checker;
#[cfg(any(target_os = "linux", windows))]
use boreal::scanner::ScanError;

fn xor_bytes(v: &[u8], xor_byte: u8) -> Vec<u8> {
    v.iter().map(|b| *b ^ xor_byte).collect()
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn test_self_scan() {
    // self-scan is a bit tricky, we need to *not* match on some payload
    // from this test, nor from the compiled rule.
    // We do this by using a bit of an obfuscated regex.
    let mut checker = Checker::new(
        r#"
rule a {
    strings:
        $a = /self.{10}scan/
    condition:
        $a
}"#,
    );

    checker.check_process(std::process::id(), false);

    // This is "self0123456789scan" when xor'ed
    let payload = xor_bytes(b"|jci?>=<;:9876|lna", 15);

    checker.check_process(std::process::id(), true);

    // Black box to avoid the payload from being optimized away before
    // the process scan.
    std::hint::black_box(payload);
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
