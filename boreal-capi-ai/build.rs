//! Emits the build target directory so integration tests can find the compiled library.
fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    // Navigate from OUT_DIR (target/{profile}/build/{crate}-{hash}/out) up to target/{profile}.
    let target_dir = std::path::Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf();
    println!(
        "cargo:rustc-env=BOREAL_CAPI_TARGET_DIR={}",
        target_dir.display()
    );
    // Recompile if the C test source changes.
    println!("cargo:rerun-if-changed=tests/c/test_basic.c");
    println!("cargo:rerun-if-changed=include/yara.h");
}
