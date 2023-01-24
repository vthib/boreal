use boreal::module::MachO;

use crate::libyara_compat::util::{
    MACHO_PPC_FILE, MACHO_X86_64_DYLIB_FILE, MACHO_X86_FILE, MACHO_X86_OBJECT_FILE,
};
use crate::utils::{compare_module_values_on_file, compare_module_values_on_mem};

// These are mostly coverage tests, ensuring all the fields are correctly set and have the same
// values as in libyara

#[test]
fn test_coverage_macho_x86() {
    compare_module_values_on_mem(MachO, "MACHO_X86_FILE", MACHO_X86_FILE)
}

#[test]
fn test_coverage_macho_ppc() {
    compare_module_values_on_mem(MachO, "MACHO_PPC_FILE", MACHO_PPC_FILE)
}

#[test]
fn test_coverage_macho_x86_object() {
    compare_module_values_on_mem(MachO, "MACHO_X86_OBJECT_FILE", MACHO_X86_OBJECT_FILE)
}

#[test]
fn test_coverage_macho_x64_dylib() {
    compare_module_values_on_mem(MachO, "MACHO_X86_64_DYLIB_FILE", MACHO_X86_64_DYLIB_FILE)
}

#[test]
fn test_coverage_macho_tiny_macho() {
    compare_module_values_on_file(MachO, "tests/assets/libyara/data/tiny-macho");
}

#[test]
fn test_coverage_macho_tiny_universal() {
    compare_module_values_on_file(MachO, "tests/assets/libyara/data/tiny-universal");
}
