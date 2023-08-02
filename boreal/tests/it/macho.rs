use boreal::module::MachO;

use crate::libyara_compat::util::{
    ELF32_FILE, MACHO_PPC_FILE, MACHO_X86_64_DYLIB_FILE, MACHO_X86_FILE, MACHO_X86_OBJECT_FILE,
};
use crate::utils::{
    check_boreal, check_file, compare_module_values_on_file, compare_module_values_on_mem,
};

#[track_caller]
fn test_cond(file: &str, cond: &str) {
    check_file(
        &format!("import \"macho\" rule test {{ condition: {cond} }}"),
        file,
        true,
    );
}

#[test]
fn test_file_index_for_arch() {
    let file = "tests/assets/macho/entry_points";

    test_cond(
        file,
        "macho.file_index_for_arch(macho.CPU_TYPE_MC680X0) == 0",
    );
    test_cond(file, "macho.file_index_for_arch(macho.CPU_TYPE_ARM64) == 7");
    test_cond(
        file,
        "macho.file_index_for_arch(macho.CPU_TYPE_POWERPC, macho.CPU_SUBTYPE_POWERPC_601) == 2",
    );

    test_cond(
        file,
        "macho.file_index_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_PENTIUM_M) == 4",
    );
    test_cond(
        file,
        "macho.file_index_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_XEON) == 10",
    );
    test_cond(
        file,
        "not defined macho.file_index_for_arch(macho.CPU_TYPE_ARM, macho.CPU_SUBTYPE_ARM_V5TEJ)",
    );
    test_cond(
        file,
        "not defined macho.file_index_for_arch(macho.CPU_TYPE_MIPS)",
    );
    test_cond(file, "not defined macho.file_index_for_arch(-1)");
    test_cond(
        file,
        "not defined macho.file_index_for_arch(macho.CPU_TYPE_MIPS, -1)",
    );
}

#[test]
fn test_entry_point_for_arch() {
    let file1 = "tests/assets/libyara/data/tiny-universal";
    let file2 = "tests/assets/macho/entry_points";

    test_cond(
        file1,
        "macho.entry_point_for_arch(macho.CPU_TYPE_X86_64) == 20192",
    );
    test_cond(
        file1,
        "macho.entry_point_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_386) == 7904",
    );

    test_cond(
        file2,
        "macho.entry_point_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_PENTIUM_M) == 2008",
    );
    test_cond(
        file2,
        "not defined macho.entry_point_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_XEON)",
    );
    {
        use std::io::Read;

        let mut f = std::fs::File::open(file2).unwrap();
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();

        let cond =
            "not defined macho.entry_point_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_XEON)";
        check_boreal(
            &format!("import \"macho\" rule test {{ condition: {cond} }}"),
            &buffer,
            true,
        );
    }

    test_cond(
        file1,
        "not defined macho.entry_point_for_arch(macho.CPU_TYPE_X86, macho.CPU_SUBTYPE_PENT)",
    );
    test_cond(
        file1,
        "not defined macho.entry_point_for_arch(macho.CPU_TYPE_MIPS)",
    );
    test_cond(file1, "not defined macho.entry_point_for_arch(-1)");
    test_cond(
        file1,
        "not defined macho.entry_point_for_arch(macho.CPU_TYPE_X86, -1)",
    );
}

#[test]
fn test_coverage_non_macho() {
    compare_module_values_on_mem(MachO, "ELF32_FILE", ELF32_FILE, &[]);
}

#[test]
fn test_coverage_macho_x86() {
    compare_module_values_on_mem(MachO, "MACHO_X86_FILE", MACHO_X86_FILE, &[]);
}

#[test]
fn test_coverage_macho_ppc() {
    compare_module_values_on_mem(MachO, "MACHO_PPC_FILE", MACHO_PPC_FILE, &[]);
}

#[test]
fn test_coverage_macho_x86_object() {
    compare_module_values_on_mem(MachO, "MACHO_X86_OBJECT_FILE", MACHO_X86_OBJECT_FILE, &[]);
}

#[test]
fn test_coverage_macho_x64_dylib() {
    compare_module_values_on_mem(
        MachO,
        "MACHO_X86_64_DYLIB_FILE",
        MACHO_X86_64_DYLIB_FILE,
        &[],
    );
}

#[test]
fn test_coverage_macho_tiny_macho() {
    compare_module_values_on_file(MachO, "tests/assets/libyara/data/tiny-macho", &[]);
}

#[test]
fn test_coverage_macho_tiny_universal() {
    compare_module_values_on_file(MachO, "tests/assets/libyara/data/tiny-universal", &[]);
}

#[test]
fn test_coverage_macho_entry_points() {
    compare_module_values_on_file(MachO, "tests/assets/macho/entry_points", &[]);
}

#[test]
fn test_coverage_macho_fat64() {
    compare_module_values_on_file(MachO, "tests/assets/macho/fat64", &[]);
}
