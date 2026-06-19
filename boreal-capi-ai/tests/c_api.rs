//! C API integration tests.
//!
//! Compiles `tests/c/test_basic.c` at test-time, links it against the built
//! `libboreal_capi` shared library, and runs it as a subprocess.
#![allow(unsafe_code)]
#![allow(unused_crate_dependencies)]
#![allow(missing_docs)]

use std::path::Path;
use std::process::Command;

/// Path to the target/{profile}/ directory, emitted by build.rs.
const TARGET_DIR: &str = env!("BOREAL_CAPI_TARGET_DIR");

#[test]
fn c_api_tests() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = manifest_dir.join("tests/c/test_basic.c");
    let include_dir = manifest_dir.join("include");
    let binary = Path::new(env!("OUT_DIR")).join("c_api_test");

    // Compile the C test binary, linking against libboreal_capi.
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let compile = Command::new(&cc)
        .args([
            source.to_str().unwrap(),
            &format!("-I{}", include_dir.display()),
            &format!("-L{}", TARGET_DIR),
            "-lboreal_capi",
            "-o",
            binary.to_str().unwrap(),
        ])
        .output()
        .expect("failed to invoke C compiler");

    if !compile.status.success() {
        panic!(
            "C compilation failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&compile.stdout),
            String::from_utf8_lossy(&compile.stderr),
        );
    }

    // Run the test binary with the shared library on the search path.
    let run = Command::new(&binary)
        .env("LD_LIBRARY_PATH", TARGET_DIR)
        .output()
        .expect("failed to run C test binary");

    if !run.status.success() {
        panic!(
            "C API tests failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        );
    }

    println!("{}", String::from_utf8_lossy(&run.stdout));
}
