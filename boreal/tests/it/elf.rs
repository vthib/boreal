use crate::libyara_compat::util::{
    ELF32_FILE, ELF32_MIPS_FILE, ELF32_NOSECTIONS, ELF32_SHAREDOBJ, ELF64_FILE, ELF_X64_FILE,
};
use crate::utils::{compare_module_values_on_file, compare_module_values_on_mem, Checker};

#[test]
fn test_non_elf() {
    let mut checker = Checker::new(
        r#"
    import "elf"

    rule a {
        condition:
            not defined elf.type
    }
    "#,
    );

    checker.check(b"", true);

    // Payload with the elf magic, but not a real elf.
    checker.check(b"\x7fELF\x01\0\0\0\0\0\0\0\0\0\0\0", true);
    checker.check(b"\x7fELF\x02\0\0\0\0\0\0\0\0\0\0\0", true);
    checker.check(b"\xfe\xed\xfa\xce\0\0\0\0\0\0\0\0\0\0\0\0", true);
}

#[track_caller]
fn test(mem: &[u8], condition: &str) {
    crate::utils::check(
        &format!(
            r#"import "elf"
rule test {{
condition:
    {condition}
}}"#
        ),
        mem,
        true,
    );
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_elf32() {
    compare_module_values_on_mem("elf", "ELF32_FILE", ELF32_FILE, false, &[]);
    compare_module_values_on_mem("elf", "ELF32_FILE", ELF32_FILE, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_elf64() {
    compare_module_values_on_mem("elf", "ELF64_FILE", ELF64_FILE, false, &[]);
    compare_module_values_on_mem("elf", "ELF64_FILE", ELF64_FILE, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_elf32_nosections() {
    compare_module_values_on_mem("elf", "ELF32_NOSECTIONS", ELF32_NOSECTIONS, false, &[]);
    compare_module_values_on_mem("elf", "ELF32_NOSECTIONS", ELF32_NOSECTIONS, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_elf32_sharedobj() {
    compare_module_values_on_mem("elf", "ELF32_SHAREDOBJ", ELF32_SHAREDOBJ, false, &[]);
    compare_module_values_on_mem("elf", "ELF32_SHAREDOBJ", ELF32_SHAREDOBJ, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_elf32_mips() {
    compare_module_values_on_mem("elf", "ELF32_MIPS_FILE", ELF32_MIPS_FILE, false, &[]);
    compare_module_values_on_mem("elf", "ELF32_MIPS_FILE", ELF32_MIPS_FILE, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_elf_x64_file() {
    compare_module_values_on_mem("elf", "ELF_X64_FILE", ELF_X64_FILE, false, &[]);
    compare_module_values_on_mem("elf", "ELF_X64_FILE", ELF_X64_FILE, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_smallest() {
    compare_module_values_on_file("elf", "tests/assets/elf/smallest", false, &[]);
    compare_module_values_on_file("elf", "tests/assets/elf/smallest", true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_invalid_sections() {
    compare_module_values_on_file("elf", "tests/assets/elf/invalid_sections", false, &[]);
    compare_module_values_on_file("elf", "tests/assets/elf/invalid_sections", true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_invalid_program_header() {
    compare_module_values_on_file("elf", "tests/assets/elf/invalid_program_header", false, &[]);
    compare_module_values_on_file("elf", "tests/assets/elf/invalid_program_header", true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_invalid_symbols() {
    compare_module_values_on_file("elf", "tests/assets/elf/invalid_symbols", false, &[]);
    compare_module_values_on_file("elf", "tests/assets/elf/invalid_symbols", true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_import_md5() {
    // No imports
    test(ELF32_FILE, "not defined elf.import_md5()");
    // No SHN_UNDEF symbols
    test(ELF32_SHAREDOBJ, "not defined elf.import_md5()");

    test(ELF32_NOSECTIONS, "not defined elf.import_md5()");
    test(ELF64_FILE, "not defined elf.import_md5()");

    test(
        ELF32_MIPS_FILE,
        "elf.import_md5() == \"89bd8d1f95cce5ba30f2cc5ba7e9d611\"",
    );
    test(
        ELF_X64_FILE,
        "elf.import_md5() == \"e3545a5c27dd2ed4dd1739a3c3c071b2\"",
    );
}

#[test]
#[cfg(feature = "hash")]
fn test_telfhash() {
    use crate::utils::check;

    test(ELF32_FILE, "not defined elf.telfhash()");
    test(ELF32_SHAREDOBJ, "not defined elf.telfhash()");
    test(ELF32_NOSECTIONS, "not defined elf.telfhash()");
    test(ELF64_FILE, "not defined elf.telfhash()");
    test(ELF32_MIPS_FILE, "not defined elf.telfhash()");
    test(ELF_X64_FILE, "not defined elf.telfhash()");

    let contents = std::fs::read("tests/assets/elf/elf_with_imports").unwrap();
    check(
        r#"
import "elf"
rule test {
    condition:
        elf.telfhash() ==
        "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA"
}"#,
        &contents,
        true,
    );
}
