use boreal::module::Elf;

use crate::libyara_compat::util::{
    ELF32_FILE, ELF32_MIPS_FILE, ELF32_NOSECTIONS, ELF32_SHAREDOBJ, ELF64_FILE, ELF_X64_FILE,
};
use crate::utils::{compare_module_values_on_file, compare_module_values_on_mem, Checker};

#[test]
fn test_non_elf() {
    let checker = Checker::new(
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
fn test_coverage_elf32() {
    compare_module_values_on_mem(Elf, "ELF32_FILE", ELF32_FILE, &[]);
}

#[test]
fn test_coverage_elf64() {
    compare_module_values_on_mem(Elf, "ELF64_FILE", ELF64_FILE, &[]);
}

#[test]
fn test_coverage_elf32_nosections() {
    compare_module_values_on_mem(Elf, "ELF32_NOSECTIONS", ELF32_NOSECTIONS, &[]);
}

#[test]
fn test_coverage_elf32_sharedobj() {
    compare_module_values_on_mem(Elf, "ELF32_SHAREDOBJ", ELF32_SHAREDOBJ, &[]);
}

#[test]
fn test_coverage_elf32_mips() {
    compare_module_values_on_mem(Elf, "ELF32_MIPS_FILE", ELF32_MIPS_FILE, &[]);
}

#[test]
fn test_coverage_elf_x64_file() {
    compare_module_values_on_mem(Elf, "ELF_X64_FILE", ELF_X64_FILE, &[]);
}

#[test]
fn test_coverage_smallest() {
    compare_module_values_on_file(Elf, "tests/assets/elf/smallest", &[]);
}

#[test]
fn test_coverage_invalid_sections() {
    compare_module_values_on_file(Elf, "tests/assets/elf/invalid_sections", &[]);
}

#[test]
fn test_coverage_invalid_program_header() {
    compare_module_values_on_file(Elf, "tests/assets/elf/invalid_program_header", &[]);
}

#[test]
fn test_coverage_invalid_symbols() {
    compare_module_values_on_file(Elf, "tests/assets/elf/invalid_symbols", &[]);
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
    use crate::utils::check_boreal;

    test(ELF32_FILE, "not defined elf.telfhash()");
    test(ELF32_SHAREDOBJ, "not defined elf.telfhash()");
    test(ELF32_NOSECTIONS, "not defined elf.telfhash()");
    test(ELF64_FILE, "not defined elf.telfhash()");
    test(ELF32_MIPS_FILE, "not defined elf.telfhash()");
    test(ELF_X64_FILE, "not defined elf.telfhash()");

    let contents = std::fs::read("tests/assets/elf/elf_with_imports").unwrap();
    // TODO: fixed on yara >4.3.0-rc1
    check_boreal(
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
