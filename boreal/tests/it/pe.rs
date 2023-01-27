use boreal::module::Pe;

use crate::utils::{check_file, compare_module_values_on_file};

#[test]
fn test_rva_to_offset() {
    check_file(
        "import \"pe\"
      rule test {
        condition:
          // no section from 0 to 0x1000: as this va is before the first section, it is returned
          // as is
          pe.rva_to_offset(0) == 0 and
          pe.rva_to_offset(0xFFF) == 0xFFF and

          // .text, starting at 0x1000, virtual size is 0x1774, section raw data is at 0x1000 too
          pe.rva_to_offset(0x1000) == 0x1000 and
          pe.rva_to_offset(0x12f3) == 0x12f3 and
          pe.rva_to_offset(0x2773) == 0x2773 and
          not defined pe.rva_to_offset(0x2774) and

          // .data, starting at 0x3000, virtual size is 0x30
          pe.rva_to_offset(0x301f) == 0x301f and
          not defined pe.rva_to_offset(0x3100) and

          // .bss, starting at 0x5000, but empty
          not defined pe.rva_to_offset(0x4fff) and
          not defined pe.rva_to_offset(0x5000) and
          not defined pe.rva_to_offset(0x5001) and

          // .idata, starting at 0x6000, virtual size 0x590, raw addr is 0x51FF, aligned to 0x5000
          pe.rva_to_offset(0x6000) == 0x5000 and
          pe.rva_to_offset(0x6500) == 0x5500 and

          // .tls starting at 0x8000, virtual size 0x20
          pe.rva_to_offset(0x8012) == 0x7012 and
          pe.rva_to_offset(0x801f) == 0x701f and
          not defined pe.rva_to_offset(0x8020) and

          not defined pe.rva_to_offset(0x7FFFFFFFFFFFFFFF) and
          not defined pe.rva_to_offset(-1) and
          not defined pe.rva_to_offset(-50) and

          true
      }",
        "tests/assets/libyara/data/tiny-idata-51ff",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          // Check that if raw size < virtual size, rva_to_offset uses the smaller one
          // as the limit:
          // .data at va 0x13000 has vsize 0x12DC and raw size 0xA00, raw data at 0x11800
          pe.rva_to_offset(0x13000) == 0x11800 and
          pe.rva_to_offset(0x139FF) == 0x121ff and
          not defined pe.rva_to_offset(0x13A00) and
          not defined pe.rva_to_offset(0x14200)
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );
}

#[test]
fn test_is_dll() {
    fn test_dll(file: &str, expected: bool) {
        check_file(
            &format!(
                "import \"pe\" rule test {{ condition: pe.is_dll() == {} }}",
                if expected {
                    object::pe::IMAGE_FILE_DLL
                } else {
                    0
                }
            ),
            file,
            true,
        );
    }

    test_dll("tests/assets/libyara/data/pe_imports", false);
    test_dll("tests/assets/libyara/data/mtxex.dll", true);
    test_dll("tests/assets/libyara/data/ChipTune.efi", false);
    test_dll("tests/assets/libyara/data/tiny", false);
    test_dll(
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );
}

#[test]
fn test_section_names() {
    check_file(
        r#"import "pe"
rule test {
    condition:
        pe.sections[9].full_name == ".debug_aranges" and
        pe.sections[9].name == "/4" and
        pe.sections[10].full_name == ".debug_info" and
        pe.sections[10].name == "/19" and
        pe.sections[11].full_name == ".debug_abbrev" and
        pe.sections[11].name == "/31" and
        pe.sections[12].full_name == ".debug_line" and
        pe.sections[12].name == "/45" and
        pe.sections[13].full_name == ".debug_frame" and
        pe.sections[13].name == "/57" and
        pe.sections[14].full_name == ".debug_str" and
        pe.sections[14].name == "/70" and
        pe.sections[15].full_name == ".debug_loc" and
        pe.sections[15].name == "/81" and
        pe.sections[16].full_name == ".debug_ranges" and
        pe.sections[16].name == "/92" and
        true
}"#,
        "tests/assets/libyara/data/pe_mingw",
        true,
    );
}

#[cfg(feature = "openssl")]
#[test]
fn test_signatures_valid_on() {
    fn check_valid_on(value: i64, expected_res: bool) {
        check_file(
            &format!(r#"import "pe"

            rule test {{
                condition:
                    pe.signatures[0].valid_on({value})
            }}"#),
            "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
            expected_res
        )
    }

    // This file has a signature with:
    // - not_before = 1491955200
    // - not_after = 1559692799
    check_valid_on(0, false);
    check_valid_on(-500, false);
    check_valid_on(1491955199, false);
    check_valid_on(1491955200, true);
    check_valid_on(1491955201, true);
    check_valid_on(1501239421, true);
    check_valid_on(1559692799, true);
    check_valid_on(1559692800, false);
}

#[cfg(feature = "openssl")]
#[test]
fn test_signatures_nested() {
    check_file(
        r#"import "pe"
rule test {
    condition:
        pe.number_of_signatures == 2 and
        pe.signatures[0].algorithm == "sha256WithRSAEncryption" and
        pe.signatures[0].algorithm_oid == "1.2.840.113549.1.1.11" and
        pe.signatures[0].issuer == "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code Signing CA" and
        pe.signatures[0].not_after == 1652831999 and
        pe.signatures[0].not_before == 1554940800 and
        pe.signatures[0].serial == "2b:95:56:9c:51:5a:47:9f:7c:d5:3c:02:11:7d:ba:3d" and
        pe.signatures[0].subject == "/C=GB/L=Nottingham/O=Serif (Europe) Ltd/CN=Serif (Europe) Ltd/ST=Nottinghamshire" and
        pe.signatures[0].thumbprint == "5b0d01d84785ee069cd543421be22be7c1f9b976" and
        pe.signatures[0].version == 3 and
        pe.signatures[1].algorithm == "sha256WithRSAEncryption" and
        pe.signatures[1].algorithm_oid == "1.2.840.113549.1.1.11" and
        pe.signatures[1].issuer == "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code Signing CA" and
        pe.signatures[1].not_after == 1652831999 and
        pe.signatures[1].not_before == 1554940800 and
        pe.signatures[1].serial == "2b:95:56:9c:51:5a:47:9f:7c:d5:3c:02:11:7d:ba:3d" and
        pe.signatures[1].subject == "/C=GB/L=Nottingham/O=Serif (Europe) Ltd/CN=Serif (Europe) Ltd/ST=Nottinghamshire" and
        pe.signatures[1].thumbprint == "5b0d01d84785ee069cd543421be22be7c1f9b976" and
        pe.signatures[1].version == 3 and
        not defined pe.signatures[2].version
}"#,
        "tests/assets/libyara/data/3b8b90159fa9b6048cc5410c5d53f116943564e4d05b04a843f9b3d0540d0c1c",
        true,
    );
}

// All import_details and delayed_import_details ignored diffs are solved in 4.3

#[test]
fn test_coverage_pe_ord_and_delay() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/pe/ord_and_delay.exe",
        &[
            "pe.delayed_import_details",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_resources_only() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/pe/resources_only.dll",
        &[
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_079a472d() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        &[
            "pe.delayed_import_details",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
            #[cfg(not(feature = "openssl"))]
            "pe.signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_079a472d_upx() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.upx",
        &[
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_0ca09bde() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171",
        &[
            "pe.rich_signature",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_33fc70f9() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b",
        &[
            "pe.rich_signature",
            // FIXME: this difference should not be
            "pe.entry_point",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_3b8b9015() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        3b8b90159fa9b6048cc5410c5d53f116943564e4d05b04a843f9b3d0540d0c1c",
        &[
            "pe.rich_signature",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
            #[cfg(not(feature = "openssl"))]
            "pe.signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_ca21e1c32() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386",
        &[
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            "pe.import_details[2].functions",
            "pe.import_details[2].number_of_functions",
            "pe.import_details[3].functions",
            "pe.import_details[3].number_of_functions",
            "pe.import_details[4].functions",
            "pe.import_details[4].number_of_functions",
            "pe.import_details[5].functions",
            "pe.import_details[5].number_of_functions",
            "pe.import_details[6].functions",
            "pe.import_details[6].number_of_functions",
            "pe.import_details[7].functions",
            "pe.import_details[7].number_of_functions",
            "pe.import_details[8].functions",
            "pe.import_details[8].number_of_functions",
            "pe.import_details[9].functions",
            "pe.import_details[9].number_of_functions",
            "pe.import_details[10].functions",
            "pe.import_details[10].number_of_functions",
            "pe.import_details[11].functions",
            "pe.import_details[11].number_of_functions",
            "pe.import_details[12].functions",
            "pe.import_details[12].number_of_functions",
            "pe.import_details[13].functions",
            "pe.import_details[13].number_of_functions",
            "pe.import_details[14].functions",
            "pe.import_details[14].number_of_functions",
            "pe.import_details[15].functions",
            "pe.import_details[15].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_mtxex() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/mtxex.dll",
        &[
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_mtxex_modified() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/mtxex_modified_rsrc_rva.dll",
        &[
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_pe_imports() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/pe_imports",
        &[
            "pe.delayed_import_details",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_pe_mingw() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/pe_mingw",
        &[
            "pe.rich_signature",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_tiny() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/tiny",
        &[
            "pe.rich_signature",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_tiny_51ff() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/tiny-idata-51ff",
        &[
            "pe.rich_signature",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_tiny_5200() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/tiny-idata-5200",
        &[
            "pe.rich_signature",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            "pe.import_details[2].functions",
            "pe.import_details[2].number_of_functions",
            "pe.import_details[3].functions",
            "pe.import_details[3].number_of_functions",
            "pe.import_details[4].functions",
            "pe.import_details[4].number_of_functions",
            "pe.import_details[5].functions",
            "pe.import_details[5].number_of_functions",
            "pe.import_details[6].functions",
            "pe.import_details[6].number_of_functions",
            "pe.import_details[7].functions",
            "pe.import_details[7].number_of_functions",
            "pe.import_details[8].functions",
            "pe.import_details[8].number_of_functions",
            "pe.import_details[9].functions",
            "pe.import_details[9].number_of_functions",
            "pe.import_details[10].functions",
            "pe.import_details[10].number_of_functions",
            // libyara allows getting the hint name from outside the .idata section, which
            // returns garbage. boreal do not do it, hence the differences
            "pe.import_details[0].functions[1].name",
            "pe.import_details[0].functions[2].name",
            "pe.import_details[0].functions[3].name",
            // TODO: invalid imports are still counted by libyara. Is that desirable? I don't think
            // so
            "pe.number_of_imports",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
fn test_coverage_pe_libyara_tiny_overlay() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/tiny-overlay",
        &[
            "pe.rich_signature",
            "pe.import_details[1].functions",
            "pe.import_details[1].number_of_functions",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
#[cfg(feature = "hash")]
fn test_imphash() {
    fn test_imphash(file: &str, value: &str) {
        check_file(
            &format!(
                r#"import "pe"
rule test {{
    condition:
        pe.imphash() == "{value}"
}}"#
            ),
            file,
            true,
        );
    }

    test_imphash(
        "tests/assets/pe/ord_and_delay.exe",
        "ed877188521c6652f37b0e5059a48447",
    );
    test_imphash(
        "tests/assets/pe/resources_only.dll",
        "d41d8cd98f00b204e9800998ecf8427e",
    );
    test_imphash(
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        "d8d0e06b79eed07c6482ca040d30f52a",
    );
    test_imphash(
        "tests/assets/libyara/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171",
        "dae02f32a21e03ce65412f6e56942daa",
    );
    test_imphash(
        "tests/assets/libyara/data/ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386",
        "e877d0307c6d5f448069042791efdb70",
    );
    test_imphash(
        "tests/assets/libyara/data/tiny",
        "1720bf764274b7a4052bbef0a71adc0d",
    );
}
