use boreal::module::Elf;

use crate::libyara_compat::util::{
    ELF32_FILE, ELF32_MIPS_FILE, ELF32_NOSECTIONS, ELF32_SHAREDOBJ, ELF64_FILE, ELF_X64_FILE,
};
use crate::utils::compare_module_values_on_mem;

// These are mostly coverage tests, ensuring all the fields are correctly set and have the same
// values as in libyara

#[test]
fn test_coverage_elf32() {
    compare_module_values_on_mem(Elf, "ELF32_FILE", ELF32_FILE);
}

#[test]
fn test_coverage_elf64() {
    compare_module_values_on_mem(Elf, "ELF64_FILE", ELF64_FILE);
}

#[test]
fn test_coverage_elf32_nosections() {
    compare_module_values_on_mem(Elf, "ELF32_NOSECTIONS", ELF32_NOSECTIONS);
}

#[test]
fn test_coverage_elf32_sharedobj() {
    compare_module_values_on_mem(Elf, "ELF32_SHAREDOBJ", ELF32_SHAREDOBJ);
}

#[test]
fn test_coverage_elf32_mips() {
    compare_module_values_on_mem(Elf, "ELF32_MIPS_FILE", ELF32_MIPS_FILE);
}

#[test]
fn test_coverage_elf_x64_file() {
    compare_module_values_on_mem(Elf, "ELF_X64_FILE", ELF_X64_FILE);
}
