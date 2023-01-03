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

    // Check that if raw size < virtual size, rva_to_offset uses the smaller one as the limit.
    check_file(
        "import \"pe\"
      rule test {
        condition:
          // .data at va 0x13000 has vsize 0x12DC and raw size 0xA00, raw data at 0x11800
          pe.rva_to_offset(0x13000) == 0x11800 and
          pe.rva_to_offset(0x139FF) == 0x121ff and
          not defined pe.rva_to_offset(0x13A00) and
          not defined pe.rva_to_offset(0x14200)
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    // Check that if vsize == 0, we use size_of_raw_data for the section size on va checks
    check_file(
        "import \"pe\"
      rule test {
        condition:
          // AUTO at va 0x1000 has vsize 0 and raw size 0x4000, raw data at 0x400
          pe.rva_to_offset(0x1000) == 0x400 and
          // file size is 0x410, so results are returned only up to this offset
          pe.rva_to_offset(0x1009) == 0x409 and
          not defined pe.rva_to_offset(0x1010)
      }",
        "tests/assets/libyara/data/c6f9709feccf42f2d9e22057182fe185f177fb9daaa2649b4669a24f2ee7e3ba_0h_410h",
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
fn test_imports() {
    let file1 = "tests/assets/libyara/data/\
                 ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386";
    let file2 = "tests/assets/pe/ord_and_delay.exe";

    #[track_caller]
    fn test(file: &str, cond: &str) {
        check_file(
            &format!("import \"pe\" rule test {{ condition: {cond} }}"),
            file,
            true,
        );
    }

    // dll_name, function_name
    test(file1, r#"pe.imports("KERNEL32.dll", "ExitProcess") == 1"#);
    test(file1, r#"pe.imports("USER32.dll", "ExitProcess") == 0"#);
    test(file1, r#"pe.imports("USER32.dll", "KillTimer") == 1"#);
    // TODO
    // test(file1, r#"pe.imports("user32.dll", "killtimer") == 0"#);
    test(file1, r#"pe.imports("user32.dll", 3) == 0"#);
    // delayed imports are not found
    test(file2, r#"pe.imports("OLEAUT32.dll", "VariantInit") == 0"#);

    // dll_name, ordinal
    test(file1, r#"pe.imports("PtDMDecode.dll", 3) == 1"#);
    test(file1, r#"pe.imports("PtDMDecode.dll", 2) == 0"#);
    test(file1, r#"pe.imports("KERNEL32.dll", 2) == 0"#);
    test(file1, r#"pe.imports("PtImageRW.dll", 7) == 1"#);
    // delayed imports are not found
    test(file2, r#"pe.imports("OLEAUT32.dll", 8) == 0"#);

    // dll_name
    test(file1, r#"pe.imports("KERNEL32.dll") == 127"#);
    test(file1, r#"pe.imports("PtDMDecode.dll") == 4"#);
    test(file1, r#"pe.imports("a.dll") == 0"#);
    // delayed imports are not found
    test(file2, r#"pe.imports("OLEAUT32.dll") == 0"#);

    // dll_regex, function_regex
    test(file1, r#"pe.imports(/32/, /Scroll/) == 8"#);
    test(file1, r#"pe.imports(/32/, /Scrull/) == 0"#);
    test(file1, r#"pe.imports(/kernel32/, /STR/) == 0"#);
    test(file1, r#"pe.imports(/kernel32/i, /STR/i) == 21"#);
    test(file1, r#"pe.imports(/PtImage/, /./) == 5"#);
    // delayed imports are not found
    test(file2, r#"pe.imports(/32/, /VARIANT/i) == 0"#);

    // import_flag, dll_name, function_name
    test(
        file1,
        r#"pe.imports(pe.IMPORT_STANDARD, "KERNEL32.dll", "ExitProcess") == 1"#,
    );
    test(
        file1,
        r#"pe.imports(pe.IMPORT_DELAYED, "KERNEL32.dll", "ExitProcess") == 0"#,
    );
    test(
        file1,
        r#"pe.imports(pe.IMPORT_STANDARD | pe.IMPORT_DELAYED,
                              "KERNEL32.dll", "ExitProcess") == 1"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, "OLEAUT32.dll", "VariantInit") == 1"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD, "OLEAUT32.dll", "VariantInit") == 0"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD, "WS2_32.dll", "gethostbyname") == 1"#,
    );

    // import_flag, dll_name
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, "OLEAUT32.dll") == 2"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD, "KERNEL32.dll") == 69"#,
    );

    // import_flag, dll_name, ordinal
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, "OLEAUT32.dll", 411) == 1"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, "OLEAUT32.dll", 7) == 0"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, "OLEAUT32.dll", 8) == 1"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD, "WS2_32.dll", 52) == 1"#,
    );

    // import_flag, dll_regex, function_regex
    test(file2, r#"pe.imports(pe.IMPORT_DELAYED, /32/, /a/) == 2"#);
    test(file2, r#"pe.imports(pe.IMPORT_DELAYED, /33/, /a/) == 0"#);
    test(file2, r#"pe.imports(pe.IMPORT_DELAYED, /32/, /ab/) == 0"#);
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, /ole/i, /VARIANT/i) == 1"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD, /(OLE|WS).*32/, /./) == 2"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_DELAYED, /(OLE|WS).*32/, /./) == 2"#,
    );
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD | pe.IMPORT_DELAYED, /(OLE|WS).*32/, /./) == 4"#,
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

#[cfg(feature = "authenticode")]
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

#[cfg(feature = "authenticode")]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
fn test_coverage_pe_libyara_33fc70f9() {
    compare_module_values_on_file(
        Pe,
        "tests/assets/libyara/data/\
        33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b",
        &[
            "pe.rich_signature",
            #[cfg(not(feature = "openssl"))]
            "pe.number_of_signatures",
        ],
    );
}

#[test]
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
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

#[test]
fn test_coverage_1561_std() {
    check_file(
        r#"import "pe"
rule test {
    condition:
pe.base_of_code == 4096 and
pe.characteristics == 35 and
pe.checksum == 711829 and
(
    pe.data_directories[0].size == 0 and
    pe.data_directories[0].virtual_address == 0 and
    pe.data_directories[1].size == 200 and
    pe.data_directories[1].virtual_address == 547724 and
    pe.data_directories[2].size == 58696 and
    pe.data_directories[2].virtual_address == 667648 and
    pe.data_directories[3].size == 13932 and
    pe.data_directories[3].virtual_address == 647168 and
    pe.data_directories[4].size == 0 and
    pe.data_directories[4].virtual_address == 0 and
    pe.data_directories[5].size == 0 and
    pe.data_directories[5].virtual_address == 0 and
    pe.data_directories[6].size == 28 and
    pe.data_directories[6].virtual_address == 306048 and
    pe.data_directories[7].size == 0 and
    pe.data_directories[7].virtual_address == 0 and
    pe.data_directories[8].size == 0 and
    pe.data_directories[8].virtual_address == 0 and
    pe.data_directories[9].size == 40 and
    pe.data_directories[9].virtual_address == 532856 and
    pe.data_directories[10].size == 0 and
    pe.data_directories[10].virtual_address == 0 and
    pe.data_directories[11].size == 0 and
    pe.data_directories[11].virtual_address == 0 and
    pe.data_directories[12].size == 2800 and
    pe.data_directories[12].virtual_address == 303104 and
    pe.data_directories[13].size == 0 and
    pe.data_directories[13].virtual_address == 0 and
    pe.data_directories[14].size == 0 and
    pe.data_directories[14].virtual_address == 0 and
    pe.data_directories[15].size == 0 and
    pe.data_directories[15].virtual_address == 0)
 and
true and
pe.dll_characteristics == 33024 and
pe.entry_point == 46656 and
pe.entry_point_raw == 49728 and
pe.file_alignment == 512 and
pe.image_base == 5368709120 and
pe.image_version.major == 0 and
pe.image_version.minor == 0 and
(
    (
        pe.import_details[0].functions[0].name == "HeapReAlloc" and
        pe.import_details[0].functions[0].rva == 303560 and
        pe.import_details[0].functions[1].name == "GetProcessHeap" and
        pe.import_details[0].functions[1].rva == 303568 and
        pe.import_details[0].functions[2].name == "GetCurrentProcess" and
        pe.import_details[0].functions[2].rva == 303576 and
        pe.import_details[0].functions[3].name == "MultiByteToWideChar" and
        pe.import_details[0].functions[3].rva == 303584 and
        pe.import_details[0].functions[4].name == "GetCurrentDirectoryW" and
        pe.import_details[0].functions[4].rva == 303592 and
        pe.import_details[0].functions[5].name == "EnumResourceNamesW" and
        pe.import_details[0].functions[5].rva == 303600 and
        pe.import_details[0].functions[6].name == "FreeLibrary" and
        pe.import_details[0].functions[6].rva == 303608 and
        pe.import_details[0].functions[7].name == "LoadLibraryW" and
        pe.import_details[0].functions[7].rva == 303616 and
        pe.import_details[0].functions[8].name == "GlobalReAlloc" and
        pe.import_details[0].functions[8].rva == 303624 and
        pe.import_details[0].functions[9].name == "GlobalSize" and
        pe.import_details[0].functions[9].rva == 303632 and
        pe.import_details[0].functions[10].name == "GlobalFree" and
        pe.import_details[0].functions[10].rva == 303640 and
        pe.import_details[0].functions[11].name == "GlobalUnlock" and
        pe.import_details[0].functions[11].rva == 303648 and
        pe.import_details[0].functions[12].name == "GlobalLock" and
        pe.import_details[0].functions[12].rva == 303656 and
        pe.import_details[0].functions[13].name == "GlobalAlloc" and
        pe.import_details[0].functions[13].rva == 303664 and
        pe.import_details[0].functions[14].name == "OpenProcess" and
        pe.import_details[0].functions[14].rva == 303672 and
        pe.import_details[0].functions[15].name == "FlushFileBuffers" and
        pe.import_details[0].functions[15].rva == 303680 and
        pe.import_details[0].functions[16].name == "GetFileAttributesW" and
        pe.import_details[0].functions[16].rva == 303688 and
        pe.import_details[0].functions[17].name == "CreateFileA" and
        pe.import_details[0].functions[17].rva == 303696 and
        pe.import_details[0].functions[18].name == "WriteConsoleW" and
        pe.import_details[0].functions[18].rva == 303704 and
        pe.import_details[0].functions[19].name == "GetConsoleOutputCP" and
        pe.import_details[0].functions[19].rva == 303712 and
        pe.import_details[0].functions[20].name == "WriteConsoleA" and
        pe.import_details[0].functions[20].rva == 303720 and
        pe.import_details[0].functions[21].name == "SetStdHandle" and
        pe.import_details[0].functions[21].rva == 303728 and
        pe.import_details[0].functions[22].name == "GetConsoleMode" and
        pe.import_details[0].functions[22].rva == 303736 and
        pe.import_details[0].functions[23].name == "GetConsoleCP" and
        pe.import_details[0].functions[23].rva == 303744 and
        pe.import_details[0].functions[24].name == "GetLocaleInfoA" and
        pe.import_details[0].functions[24].rva == 303752 and
        pe.import_details[0].functions[25].name == "GetStringTypeW" and
        pe.import_details[0].functions[25].rva == 303760 and
        pe.import_details[0].functions[26].name == "GetStringTypeA" and
        pe.import_details[0].functions[26].rva == 303768 and
        pe.import_details[0].functions[27].name == "QueryPerformanceCounter" and
        pe.import_details[0].functions[27].rva == 303776 and
        pe.import_details[0].functions[28].name == "GetCurrentThread" and
        pe.import_details[0].functions[28].rva == 303784 and
        pe.import_details[0].functions[29].name == "HeapCreate" and
        pe.import_details[0].functions[29].rva == 303792 and
        pe.import_details[0].functions[30].name == "DeleteFileW" and
        pe.import_details[0].functions[30].rva == 303800 and
        pe.import_details[0].functions[31].name == "GetStartupInfoA" and
        pe.import_details[0].functions[31].rva == 303808 and
        pe.import_details[0].functions[32].name == "GetFileType" and
        pe.import_details[0].functions[32].rva == 303816 and
        pe.import_details[0].functions[33].name == "SetHandleCount" and
        pe.import_details[0].functions[33].rva == 303824 and
        pe.import_details[0].functions[34].name == "GetCommandLineW" and
        pe.import_details[0].functions[34].rva == 303832 and
        pe.import_details[0].functions[35].name == "GetEnvironmentStringsW" and
        pe.import_details[0].functions[35].rva == 303840 and
        pe.import_details[0].functions[36].name == "FreeEnvironmentStringsW" and
        pe.import_details[0].functions[36].rva == 303848 and
        pe.import_details[0].functions[37].name == "InitializeCriticalSectionAndSpinCount" and
        pe.import_details[0].functions[37].rva == 303856 and
        pe.import_details[0].functions[38].name == "LoadLibraryA" and
        pe.import_details[0].functions[38].rva == 303864 and
        pe.import_details[0].functions[39].name == "GetModuleFileNameA" and
        pe.import_details[0].functions[39].rva == 303872 and
        pe.import_details[0].functions[40].name == "GetStdHandle" and
        pe.import_details[0].functions[40].rva == 303880 and
        pe.import_details[0].functions[41].name == "HeapSize" and
        pe.import_details[0].functions[41].rva == 303888 and
        pe.import_details[0].functions[42].name == "LCMapStringW" and
        pe.import_details[0].functions[42].rva == 303896 and
        pe.import_details[0].functions[43].name == "LCMapStringA" and
        pe.import_details[0].functions[43].rva == 303904 and
        pe.import_details[0].functions[44].name == "FlsAlloc" and
        pe.import_details[0].functions[44].rva == 303912 and
        pe.import_details[0].functions[45].name == "FlsFree" and
        pe.import_details[0].functions[45].rva == 303920 and
        pe.import_details[0].functions[46].name == "FlsSetValue" and
        pe.import_details[0].functions[46].rva == 303928 and
        pe.import_details[0].functions[47].name == "FlsGetValue" and
        pe.import_details[0].functions[47].rva == 303936 and
        pe.import_details[0].functions[48].name == "DecodePointer" and
        pe.import_details[0].functions[48].rva == 303944 and
        pe.import_details[0].functions[49].name == "EncodePointer" and
        pe.import_details[0].functions[49].rva == 303952 and
        pe.import_details[0].functions[50].name == "IsValidCodePage" and
        pe.import_details[0].functions[50].rva == 303960 and
        pe.import_details[0].functions[51].name == "GetOEMCP" and
        pe.import_details[0].functions[51].rva == 303968 and
        pe.import_details[0].functions[52].name == "GetACP" and
        pe.import_details[0].functions[52].rva == 303976 and
        pe.import_details[0].functions[53].name == "GetCPInfo" and
        pe.import_details[0].functions[53].rva == 303984 and
        pe.import_details[0].functions[54].name == "RtlPcToFileHeader" and
        pe.import_details[0].functions[54].rva == 303992 and
        pe.import_details[0].functions[55].name == "RaiseException" and
        pe.import_details[0].functions[55].rva == 304000 and
        pe.import_details[0].functions[56].name == "RtlUnwindEx" and
        pe.import_details[0].functions[56].rva == 304008 and
        pe.import_details[0].functions[57].name == "GetStartupInfoW" and
        pe.import_details[0].functions[57].rva == 304016 and
        pe.import_details[0].functions[58].name == "ExitProcess" and
        pe.import_details[0].functions[58].rva == 304024 and
        pe.import_details[0].functions[59].name == "Sleep" and
        pe.import_details[0].functions[59].rva == 304032 and
        pe.import_details[0].functions[60].name == "RtlCaptureContext" and
        pe.import_details[0].functions[60].rva == 304040 and
        pe.import_details[0].functions[61].name == "RtlLookupFunctionEntry" and
        pe.import_details[0].functions[61].rva == 304048 and
        pe.import_details[0].functions[62].name == "RtlVirtualUnwind" and
        pe.import_details[0].functions[62].rva == 304056 and
        pe.import_details[0].functions[63].name == "SetUnhandledExceptionFilter" and
        pe.import_details[0].functions[63].rva == 304064 and
        pe.import_details[0].functions[64].name == "UnhandledExceptionFilter" and
        pe.import_details[0].functions[64].rva == 304072 and
        pe.import_details[0].functions[65].name == "TerminateProcess" and
        pe.import_details[0].functions[65].rva == 304080 and
        pe.import_details[0].functions[66].name == "SizeofResource" and
        pe.import_details[0].functions[66].rva == 304088 and
        pe.import_details[0].functions[67].name == "FreeResource" and
        pe.import_details[0].functions[67].rva == 304096 and
        pe.import_details[0].functions[68].name == "IsDebuggerPresent" and
        pe.import_details[0].functions[68].rva == 304104 and
        pe.import_details[0].functions[69].name == "GetCurrentThreadId" and
        pe.import_details[0].functions[69].rva == 304112 and
        pe.import_details[0].functions[70].name == "GetCurrentProcessId" and
        pe.import_details[0].functions[70].rva == 304120 and
        pe.import_details[0].functions[71].name == "FormatMessageW" and
        pe.import_details[0].functions[71].rva == 304128 and
        pe.import_details[0].functions[72].name == "GetVersionExW" and
        pe.import_details[0].functions[72].rva == 304136 and
        pe.import_details[0].functions[73].name == "DeleteCriticalSection" and
        pe.import_details[0].functions[73].rva == 304144 and
        pe.import_details[0].functions[74].name == "MoveFileExW" and
        pe.import_details[0].functions[74].rva == 304152 and
        pe.import_details[0].functions[75].name == "SetEndOfFile" and
        pe.import_details[0].functions[75].rva == 304160 and
        pe.import_details[0].functions[76].name == "SetFilePointer" and
        pe.import_details[0].functions[76].rva == 304168 and
        pe.import_details[0].functions[77].name == "UnlockFile" and
        pe.import_details[0].functions[77].rva == 304176 and
        pe.import_details[0].functions[78].name == "LockFile" and
        pe.import_details[0].functions[78].rva == 304184 and
        pe.import_details[0].functions[79].name == "GetOverlappedResult" and
        pe.import_details[0].functions[79].rva == 304192 and
        pe.import_details[0].functions[80].name == "SetCurrentDirectoryW" and
        pe.import_details[0].functions[80].rva == 304200 and
        pe.import_details[0].functions[81].name == "HeapSetInformation" and
        pe.import_details[0].functions[81].rva == 304208 and
        pe.import_details[0].functions[82].name == "CreateDirectoryW" and
        pe.import_details[0].functions[82].rva == 304216 and
        pe.import_details[0].functions[83].name == "WaitForSingleObject" and
        pe.import_details[0].functions[83].rva == 304224 and
        pe.import_details[0].functions[84].name == "CreateEventW" and
        pe.import_details[0].functions[84].rva == 304232 and
        pe.import_details[0].functions[85].name == "LockResource" and
        pe.import_details[0].functions[85].rva == 304240 and
        pe.import_details[0].functions[86].name == "LoadResource" and
        pe.import_details[0].functions[86].rva == 304248 and
        pe.import_details[0].functions[87].name == "FindResourceW" and
        pe.import_details[0].functions[87].rva == 304256 and
        pe.import_details[0].functions[88].name == "InitializeCriticalSection" and
        pe.import_details[0].functions[88].rva == 304264 and
        pe.import_details[0].functions[89].name == "SetEvent" and
        pe.import_details[0].functions[89].rva == 304272 and
        pe.import_details[0].functions[90].name == "WaitForMultipleObjects" and
        pe.import_details[0].functions[90].rva == 304280 and
        pe.import_details[0].functions[91].name == "LeaveCriticalSection" and
        pe.import_details[0].functions[91].rva == 304288 and
        pe.import_details[0].functions[92].name == "EnterCriticalSection" and
        pe.import_details[0].functions[92].rva == 304296 and
        pe.import_details[0].functions[93].name == "CreateThread" and
        pe.import_details[0].functions[93].rva == 304304 and
        pe.import_details[0].functions[94].name == "GetProcAddress" and
        pe.import_details[0].functions[94].rva == 304312 and
        pe.import_details[0].functions[95].name == "GetModuleHandleW" and
        pe.import_details[0].functions[95].rva == 304320 and
        pe.import_details[0].functions[96].name == "VirtualFree" and
        pe.import_details[0].functions[96].rva == 304328 and
        pe.import_details[0].functions[97].name == "CloseHandle" and
        pe.import_details[0].functions[97].rva == 304336 and
        pe.import_details[0].functions[98].name == "SetFileTime" and
        pe.import_details[0].functions[98].rva == 304344 and
        pe.import_details[0].functions[99].name == "VirtualAlloc" and
        pe.import_details[0].functions[99].rva == 304352 and
        pe.import_details[0].functions[100].name == "GetFileTime" and
        pe.import_details[0].functions[100].rva == 304360 and
        pe.import_details[0].functions[101].name == "GetModuleFileNameW" and
        pe.import_details[0].functions[101].rva == 304368 and
        pe.import_details[0].functions[102].name == "GetLocaleInfoW" and
        pe.import_details[0].functions[102].rva == 304376 and
        pe.import_details[0].functions[103].name == "GetTickCount" and
        pe.import_details[0].functions[103].rva == 304384 and
        pe.import_details[0].functions[104].name == "ReadFile" and
        pe.import_details[0].functions[104].rva == 304392 and
        pe.import_details[0].functions[105].name == "DeviceIoControl" and
        pe.import_details[0].functions[105].rva == 304400 and
        pe.import_details[0].functions[106].name == "GetFileSize" and
        pe.import_details[0].functions[106].rva == 304408 and
        pe.import_details[0].functions[107].name == "SetLastError" and
        pe.import_details[0].functions[107].rva == 304416 and
        pe.import_details[0].functions[108].name == "GetLastError" and
        pe.import_details[0].functions[108].rva == 304424 and
        pe.import_details[0].functions[109].name == "CreateFileW" and
        pe.import_details[0].functions[109].rva == 304432 and
        pe.import_details[0].functions[110].name == "HeapFree" and
        pe.import_details[0].functions[110].rva == 304440 and
        pe.import_details[0].functions[111].name == "WriteFile" and
        pe.import_details[0].functions[111].rva == 304448 and
        pe.import_details[0].functions[112].name == "WideCharToMultiByte" and
        pe.import_details[0].functions[112].rva == 304456 and
        pe.import_details[0].functions[113].name == "HeapAlloc" and
        pe.import_details[0].functions[113].rva == 304464 and
        pe.import_details[0].functions[114].name == "LocalFileTimeToFileTime" and
        pe.import_details[0].functions[114].rva == 304472 and
        pe.import_details[0].functions[115].name == "SystemTimeToFileTime" and
        pe.import_details[0].functions[115].rva == 304480 and
        pe.import_details[0].functions[116].name == "EnumTimeFormatsW" and
        pe.import_details[0].functions[116].rva == 304488 and
        pe.import_details[0].functions[117].name == "EnumDateFormatsW" and
        pe.import_details[0].functions[117].rva == 304496 and
        pe.import_details[0].functions[118].name == "GetSystemTimeAsFileTime" and
        pe.import_details[0].functions[118].rva == 304504 and
        pe.import_details[0].functions[119].name == "GetTimeFormatW" and
        pe.import_details[0].functions[119].rva == 304512 and
        pe.import_details[0].functions[120].name == "FileTimeToSystemTime" and
        pe.import_details[0].functions[120].rva == 304520 and
        pe.import_details[0].functions[121].name == "FileTimeToLocalFileTime" and
        pe.import_details[0].functions[121].rva == 304528 and
        pe.import_details[0].functions[122].name == "GetDateFormatW" and
        pe.import_details[0].functions[122].rva == 304536    )
 and
    pe.import_details[0].library_name == "KERNEL32.dll" and
    pe.import_details[0].number_of_functions == 123 and
    (
        pe.import_details[1].functions[0].name == "IsCharAlphaW" and
        pe.import_details[1].functions[0].rva == 304592 and
        pe.import_details[1].functions[1].name == "GetWindowLongW" and
        pe.import_details[1].functions[1].rva == 304600 and
        pe.import_details[1].functions[2].name == "SetWindowLongW" and
        pe.import_details[1].functions[2].rva == 304608 and
        pe.import_details[1].functions[3].name == "SendMessageW" and
        pe.import_details[1].functions[3].rva == 304616 and
        pe.import_details[1].functions[4].name == "SetWindowTextW" and
        pe.import_details[1].functions[4].rva == 304624 and
        pe.import_details[1].functions[5].name == "PostMessageW" and
        pe.import_details[1].functions[5].rva == 304632 and
        pe.import_details[1].functions[6].name == "GetDlgItem" and
        pe.import_details[1].functions[6].rva == 304640 and
        pe.import_details[1].functions[7].name == "SetWindowLongPtrW" and
        pe.import_details[1].functions[7].rva == 304648 and
        pe.import_details[1].functions[8].name == "GetWindowLongPtrW" and
        pe.import_details[1].functions[8].rva == 304656 and
        pe.import_details[1].functions[9].name == "EndDialog" and
        pe.import_details[1].functions[9].rva == 304664 and
        pe.import_details[1].functions[10].name == "DialogBoxParamW" and
        pe.import_details[1].functions[10].rva == 304672 and
        pe.import_details[1].functions[11].name == "CharUpperW" and
        pe.import_details[1].functions[11].rva == 304680 and
        pe.import_details[1].functions[12].name == "IsDlgButtonChecked" and
        pe.import_details[1].functions[12].rva == 304688 and
        pe.import_details[1].functions[13].name == "EnableWindow" and
        pe.import_details[1].functions[13].rva == 304696 and
        pe.import_details[1].functions[14].name == "SetDlgItemTextW" and
        pe.import_details[1].functions[14].rva == 304704 and
        pe.import_details[1].functions[15].name == "GetWindowTextLengthW" and
        pe.import_details[1].functions[15].rva == 304712 and
        pe.import_details[1].functions[16].name == "GetWindowTextW" and
        pe.import_details[1].functions[16].rva == 304720 and
        pe.import_details[1].functions[17].name == "CheckDlgButton" and
        pe.import_details[1].functions[17].rva == 304728 and
        pe.import_details[1].functions[18].name == "SetWindowTextA" and
        pe.import_details[1].functions[18].rva == 304736 and
        pe.import_details[1].functions[19].name == "CreateCursor" and
        pe.import_details[1].functions[19].rva == 304744 and
        pe.import_details[1].functions[20].name == "SetCursor" and
        pe.import_details[1].functions[20].rva == 304752 and
        pe.import_details[1].functions[21].name == "CallWindowProcW" and
        pe.import_details[1].functions[21].rva == 304760 and
        pe.import_details[1].functions[22].name == "CreateDialogIndirectParamW" and
        pe.import_details[1].functions[22].rva == 304768 and
        pe.import_details[1].functions[23].name == "SendDlgItemMessageA" and
        pe.import_details[1].functions[23].rva == 304776 and
        pe.import_details[1].functions[24].name == "DialogBoxIndirectParamW" and
        pe.import_details[1].functions[24].rva == 304784 and
        pe.import_details[1].functions[25].name == "FillRect" and
        pe.import_details[1].functions[25].rva == 304792 and
        pe.import_details[1].functions[26].name == "DeleteMenu" and
        pe.import_details[1].functions[26].rva == 304800 and
        pe.import_details[1].functions[27].name == "MessageBeep" and
        pe.import_details[1].functions[27].rva == 304808 and
        pe.import_details[1].functions[28].name == "DrawTextExW" and
        pe.import_details[1].functions[28].rva == 304816 and
        pe.import_details[1].functions[29].name == "BeginDeferWindowPos" and
        pe.import_details[1].functions[29].rva == 304824 and
        pe.import_details[1].functions[30].name == "DeferWindowPos" and
        pe.import_details[1].functions[30].rva == 304832 and
        pe.import_details[1].functions[31].name == "EndDeferWindowPos" and
        pe.import_details[1].functions[31].rva == 304840 and
        pe.import_details[1].functions[32].name == "LoadIconW" and
        pe.import_details[1].functions[32].rva == 304848 and
        pe.import_details[1].functions[33].name == "SetFocus" and
        pe.import_details[1].functions[33].rva == 304856 and
        pe.import_details[1].functions[34].name == "GetWindowTextA" and
        pe.import_details[1].functions[34].rva == 304864 and
        pe.import_details[1].functions[35].name == "InvalidateRect" and
        pe.import_details[1].functions[35].rva == 304872 and
        pe.import_details[1].functions[36].name == "SetWindowPos" and
        pe.import_details[1].functions[36].rva == 304880 and
        pe.import_details[1].functions[37].name == "GetWindowRect" and
        pe.import_details[1].functions[37].rva == 304888 and
        pe.import_details[1].functions[38].name == "SystemParametersInfoW" and
        pe.import_details[1].functions[38].rva == 304896 and
        pe.import_details[1].functions[39].name == "SetTimer" and
        pe.import_details[1].functions[39].rva == 304904 and
        pe.import_details[1].functions[40].name == "KillTimer" and
        pe.import_details[1].functions[40].rva == 304912 and
        pe.import_details[1].functions[41].name == "MapDialogRect" and
        pe.import_details[1].functions[41].rva == 304920 and
        pe.import_details[1].functions[42].name == "GetSystemMetrics" and
        pe.import_details[1].functions[42].rva == 304928 and
        pe.import_details[1].functions[43].name == "GetSystemMenu" and
        pe.import_details[1].functions[43].rva == 304936 and
        pe.import_details[1].functions[44].name == "GetMenuItemCount" and
        pe.import_details[1].functions[44].rva == 304944 and
        pe.import_details[1].functions[45].name == "GetMenuItemInfoW" and
        pe.import_details[1].functions[45].rva == 304952 and
        pe.import_details[1].functions[46].name == "LoadStringW" and
        pe.import_details[1].functions[46].rva == 304960 and
        pe.import_details[1].functions[47].name == "TrackPopupMenu" and
        pe.import_details[1].functions[47].rva == 304968 and
        pe.import_details[1].functions[48].name == "SetForegroundWindow" and
        pe.import_details[1].functions[48].rva == 304976 and
        pe.import_details[1].functions[49].name == "LoadMenuW" and
        pe.import_details[1].functions[49].rva == 304984 and
        pe.import_details[1].functions[50].name == "LoadImageW" and
        pe.import_details[1].functions[50].rva == 304992 and
        pe.import_details[1].functions[51].name == "RegisterClassExW" and
        pe.import_details[1].functions[51].rva == 305000 and
        pe.import_details[1].functions[52].name == "LoadCursorW" and
        pe.import_details[1].functions[52].rva == 305008 and
        pe.import_details[1].functions[53].name == "GetClassInfoExW" and
        pe.import_details[1].functions[53].rva == 305016 and
        pe.import_details[1].functions[54].name == "DefWindowProcW" and
        pe.import_details[1].functions[54].rva == 305024 and
        pe.import_details[1].functions[55].name == "EndPaint" and
        pe.import_details[1].functions[55].rva == 305032 and
        pe.import_details[1].functions[56].name == "TabbedTextOutW" and
        pe.import_details[1].functions[56].rva == 305040 and
        pe.import_details[1].functions[57].name == "IntersectRect" and
        pe.import_details[1].functions[57].rva == 305048 and
        pe.import_details[1].functions[58].name == "BeginPaint" and
        pe.import_details[1].functions[58].rva == 305056 and
        pe.import_details[1].functions[59].name == "GetScrollInfo" and
        pe.import_details[1].functions[59].rva == 305064 and
        pe.import_details[1].functions[60].name == "SetCapture" and
        pe.import_details[1].functions[60].rva == 305072 and
        pe.import_details[1].functions[61].name == "DestroyCaret" and
        pe.import_details[1].functions[61].rva == 305080 and
        pe.import_details[1].functions[62].name == "HideCaret" and
        pe.import_details[1].functions[62].rva == 305088 and
        pe.import_details[1].functions[63].name == "ReleaseCapture" and
        pe.import_details[1].functions[63].rva == 305096 and
        pe.import_details[1].functions[64].name == "ShowCaret" and
        pe.import_details[1].functions[64].rva == 305104 and
        pe.import_details[1].functions[65].name == "CreateCaret" and
        pe.import_details[1].functions[65].rva == 305112 and
        pe.import_details[1].functions[66].name == "SetCaretPos" and
        pe.import_details[1].functions[66].rva == 305120 and
        pe.import_details[1].functions[67].name == "GetTabbedTextExtentW" and
        pe.import_details[1].functions[67].rva == 305128 and
        pe.import_details[1].functions[68].name == "SetScrollInfo" and
        pe.import_details[1].functions[68].rva == 305136 and
        pe.import_details[1].functions[69].name == "ReleaseDC" and
        pe.import_details[1].functions[69].rva == 305144 and
        pe.import_details[1].functions[70].name == "GetDC" and
        pe.import_details[1].functions[70].rva == 305152 and
        pe.import_details[1].functions[71].name == "GetClipboardData" and
        pe.import_details[1].functions[71].rva == 305160 and
        pe.import_details[1].functions[72].name == "IsClipboardFormatAvailable" and
        pe.import_details[1].functions[72].rva == 305168 and
        pe.import_details[1].functions[73].name == "GetDlgItemInt" and
        pe.import_details[1].functions[73].rva == 305176 and
        pe.import_details[1].functions[74].name == "ScreenToClient" and
        pe.import_details[1].functions[74].rva == 305184 and
        pe.import_details[1].functions[75].name == "EnableMenuItem" and
        pe.import_details[1].functions[75].rva == 305192 and
        pe.import_details[1].functions[76].name == "GetSubMenu" and
        pe.import_details[1].functions[76].rva == 305200 and
        pe.import_details[1].functions[77].name == "GetFocus" and
        pe.import_details[1].functions[77].rva == 305208 and
        pe.import_details[1].functions[78].name == "ClientToScreen" and
        pe.import_details[1].functions[78].rva == 305216 and
        pe.import_details[1].functions[79].name == "CloseClipboard" and
        pe.import_details[1].functions[79].rva == 305224 and
        pe.import_details[1].functions[80].name == "SetClipboardData" and
        pe.import_details[1].functions[80].rva == 305232 and
        pe.import_details[1].functions[81].name == "EmptyClipboard" and
        pe.import_details[1].functions[81].rva == 305240 and
        pe.import_details[1].functions[82].name == "OpenClipboard" and
        pe.import_details[1].functions[82].rva == 305248 and
        pe.import_details[1].functions[83].name == "IsWindowVisible" and
        pe.import_details[1].functions[83].rva == 305256 and
        pe.import_details[1].functions[84].name == "GetDlgItemTextW" and
        pe.import_details[1].functions[84].rva == 305264 and
        pe.import_details[1].functions[85].name == "GetClassNameW" and
        pe.import_details[1].functions[85].rva == 305272 and
        pe.import_details[1].functions[86].name == "GetTopWindow" and
        pe.import_details[1].functions[86].rva == 305280 and
        pe.import_details[1].functions[87].name == "IsWindowEnabled" and
        pe.import_details[1].functions[87].rva == 305288 and
        pe.import_details[1].functions[88].name == "GetWindow" and
        pe.import_details[1].functions[88].rva == 305296 and
        pe.import_details[1].functions[89].name == "GetClientRect" and
        pe.import_details[1].functions[89].rva == 305304 and
        pe.import_details[1].functions[90].name == "CreateWindowExW" and
        pe.import_details[1].functions[90].rva == 305312 and
        pe.import_details[1].functions[91].name == "LoadStringA" and
        pe.import_details[1].functions[91].rva == 305320 and
        pe.import_details[1].functions[92].name == "DestroyAcceleratorTable" and
        pe.import_details[1].functions[92].rva == 305328 and
        pe.import_details[1].functions[93].name == "DispatchMessageW" and
        pe.import_details[1].functions[93].rva == 305336 and
        pe.import_details[1].functions[94].name == "TranslateMessage" and
        pe.import_details[1].functions[94].rva == 305344 and
        pe.import_details[1].functions[95].name == "TranslateAcceleratorW" and
        pe.import_details[1].functions[95].rva == 305352 and
        pe.import_details[1].functions[96].name == "GetMessageW" and
        pe.import_details[1].functions[96].rva == 305360 and
        pe.import_details[1].functions[97].name == "IsWindow" and
        pe.import_details[1].functions[97].rva == 305368 and
        pe.import_details[1].functions[98].name == "ShowWindow" and
        pe.import_details[1].functions[98].rva == 305376 and
        pe.import_details[1].functions[99].name == "CreateDialogParamW" and
        pe.import_details[1].functions[99].rva == 305384 and
        pe.import_details[1].functions[100].name == "LoadAcceleratorsW" and
        pe.import_details[1].functions[100].rva == 305392 and
        pe.import_details[1].functions[101].name == "GetParent" and
        pe.import_details[1].functions[101].rva == 305400 and
        pe.import_details[1].functions[102].name == "IsDialogMessageW" and
        pe.import_details[1].functions[102].rva == 305408 and
        pe.import_details[1].functions[103].name == "GetAsyncKeyState" and
        pe.import_details[1].functions[103].rva == 305416 and
        pe.import_details[1].functions[104].name == "DestroyWindow" and
        pe.import_details[1].functions[104].rva == 305424 and
        pe.import_details[1].functions[105].name == "PtInRect" and
        pe.import_details[1].functions[105].rva == 305432 and
        pe.import_details[1].functions[106].name == "GetActiveWindow" and
        pe.import_details[1].functions[106].rva == 305440 and
        pe.import_details[1].functions[107].name == "GetCursorPos" and
        pe.import_details[1].functions[107].rva == 305448 and
        pe.import_details[1].functions[108].name == "InsertMenuW" and
        pe.import_details[1].functions[108].rva == 305456    )
 and
    pe.import_details[1].library_name == "USER32.dll" and
    pe.import_details[1].number_of_functions == 109 and
    (
        pe.import_details[2].functions[0].name == "SetTextAlign" and
        pe.import_details[2].functions[0].rva == 303464 and
        pe.import_details[2].functions[1].name == "GetTextMetricsW" and
        pe.import_details[2].functions[1].rva == 303472 and
        pe.import_details[2].functions[2].name == "SelectObject" and
        pe.import_details[2].functions[2].rva == 303480 and
        pe.import_details[2].functions[3].name == "GetStockObject" and
        pe.import_details[2].functions[3].rva == 303488 and
        pe.import_details[2].functions[4].name == "CreateFontIndirectW" and
        pe.import_details[2].functions[4].rva == 303496 and
        pe.import_details[2].functions[5].name == "SetTextColor" and
        pe.import_details[2].functions[5].rva == 303504 and
        pe.import_details[2].functions[6].name == "SetBkColor" and
        pe.import_details[2].functions[6].rva == 303512 and
        pe.import_details[2].functions[7].name == "GetTextExtentPoint32W" and
        pe.import_details[2].functions[7].rva == 303520 and
        pe.import_details[2].functions[8].name == "GetObjectW" and
        pe.import_details[2].functions[8].rva == 303528 and
        pe.import_details[2].functions[9].name == "TextOutW" and
        pe.import_details[2].functions[9].rva == 303536 and
        pe.import_details[2].functions[10].name == "ExtTextOutW" and
        pe.import_details[2].functions[10].rva == 303544    )
 and
    pe.import_details[2].library_name == "GDI32.dll" and
    pe.import_details[2].number_of_functions == 11 and
    (
        pe.import_details[3].functions[0].name == "LookupAccountSidW" and
        pe.import_details[3].functions[0].rva == 303104 and
        pe.import_details[3].functions[1].name == "GetUserNameW" and
        pe.import_details[3].functions[1].rva == 303112 and
        pe.import_details[3].functions[2].name == "SetSecurityDescriptorSacl" and
        pe.import_details[3].functions[2].rva == 303120 and
        pe.import_details[3].functions[3].name == "SetSecurityDescriptorDacl" and
        pe.import_details[3].functions[3].rva == 303128 and
        pe.import_details[3].functions[4].name == "SetSecurityDescriptorGroup" and
        pe.import_details[3].functions[4].rva == 303136 and
        pe.import_details[3].functions[5].name == "SetSecurityDescriptorOwner" and
        pe.import_details[3].functions[5].rva == 303144 and
        pe.import_details[3].functions[6].name == "InitializeSecurityDescriptor" and
        pe.import_details[3].functions[6].rva == 303152 and
        pe.import_details[3].functions[7].name == "GetSecurityDescriptorSacl" and
        pe.import_details[3].functions[7].rva == 303160 and
        pe.import_details[3].functions[8].name == "GetSecurityDescriptorDacl" and
        pe.import_details[3].functions[8].rva == 303168 and
        pe.import_details[3].functions[9].name == "GetSecurityDescriptorGroup" and
        pe.import_details[3].functions[9].rva == 303176 and
        pe.import_details[3].functions[10].name == "GetSecurityDescriptorOwner" and
        pe.import_details[3].functions[10].rva == 303184 and
        pe.import_details[3].functions[11].name == "GetAce" and
        pe.import_details[3].functions[11].rva == 303192 and
        pe.import_details[3].functions[12].name == "AddAuditAccessAce" and
        pe.import_details[3].functions[12].rva == 303200 and
        pe.import_details[3].functions[13].name == "AddAccessDeniedAce" and
        pe.import_details[3].functions[13].rva == 303208 and
        pe.import_details[3].functions[14].name == "AddAccessAllowedAce" and
        pe.import_details[3].functions[14].rva == 303216 and
        pe.import_details[3].functions[15].name == "InitializeAcl" and
        pe.import_details[3].functions[15].rva == 303224 and
        pe.import_details[3].functions[16].name == "LookupAccountNameW" and
        pe.import_details[3].functions[16].rva == 303232 and
        pe.import_details[3].functions[17].name == "CopySid" and
        pe.import_details[3].functions[17].rva == 303240 and
        pe.import_details[3].functions[18].name == "GetLengthSid" and
        pe.import_details[3].functions[18].rva == 303248 and
        pe.import_details[3].functions[19].name == "RegSetValueExW" and
        pe.import_details[3].functions[19].rva == 303256 and
        pe.import_details[3].functions[20].name == "FreeSid" and
        pe.import_details[3].functions[20].rva == 303264 and
        pe.import_details[3].functions[21].name == "SetTokenInformation" and
        pe.import_details[3].functions[21].rva == 303272 and
        pe.import_details[3].functions[22].name == "AllocateAndInitializeSid" and
        pe.import_details[3].functions[22].rva == 303280 and
        pe.import_details[3].functions[23].name == "AdjustTokenPrivileges" and
        pe.import_details[3].functions[23].rva == 303288 and
        pe.import_details[3].functions[24].name == "LookupPrivilegeValueW" and
        pe.import_details[3].functions[24].rva == 303296 and
        pe.import_details[3].functions[25].name == "LookupPrivilegeNameW" and
        pe.import_details[3].functions[25].rva == 303304 and
        pe.import_details[3].functions[26].name == "RegCloseKey" and
        pe.import_details[3].functions[26].rva == 303312 and
        pe.import_details[3].functions[27].name == "RegQueryValueExW" and
        pe.import_details[3].functions[27].rva == 303320 and
        pe.import_details[3].functions[28].name == "RegOpenKeyExW" and
        pe.import_details[3].functions[28].rva == 303328 and
        pe.import_details[3].functions[29].name == "GetSidSubAuthority" and
        pe.import_details[3].functions[29].rva == 303336 and
        pe.import_details[3].functions[30].name == "GetSidIdentifierAuthority" and
        pe.import_details[3].functions[30].rva == 303344 and
        pe.import_details[3].functions[31].name == "GetSidSubAuthorityCount" and
        pe.import_details[3].functions[31].rva == 303352 and
        pe.import_details[3].functions[32].name == "GetTokenInformation" and
        pe.import_details[3].functions[32].rva == 303360 and
        pe.import_details[3].functions[33].name == "OpenProcessToken" and
        pe.import_details[3].functions[33].rva == 303368 and
        pe.import_details[3].functions[34].name == "OpenThreadToken" and
        pe.import_details[3].functions[34].rva == 303376    )
 and
    pe.import_details[3].library_name == "ADVAPI32.dll" and
    pe.import_details[3].number_of_functions == 35 and
    (
        pe.import_details[4].functions[0].name == "NtCreateFile" and
        pe.import_details[4].functions[0].rva == 305504 and
        pe.import_details[4].functions[1].name == "NtClose" and
        pe.import_details[4].functions[1].rva == 305512 and
        pe.import_details[4].functions[2].name == "RtlInitUnicodeString" and
        pe.import_details[4].functions[2].rva == 305520 and
        pe.import_details[4].functions[3].name == "NtOpenFile" and
        pe.import_details[4].functions[3].rva == 305528 and
        pe.import_details[4].functions[4].name == "RtlNtStatusToDosError" and
        pe.import_details[4].functions[4].rva == 305536 and
        pe.import_details[4].functions[5].name == "RtlFreeUnicodeString" and
        pe.import_details[4].functions[5].rva == 305544 and
        pe.import_details[4].functions[6].name == "RtlCreateUnicodeString" and
        pe.import_details[4].functions[6].rva == 305552 and
        pe.import_details[4].functions[7].name == "NtOpenDirectoryObject" and
        pe.import_details[4].functions[7].rva == 305560 and
        pe.import_details[4].functions[8].name == "RtlDecompressBuffer" and
        pe.import_details[4].functions[8].rva == 305568 and
        pe.import_details[4].functions[9].name == "NtDeviceIoControlFile" and
        pe.import_details[4].functions[9].rva == 305576 and
        pe.import_details[4].functions[10].name == "RtlReAllocateHeap" and
        pe.import_details[4].functions[10].rva == 305584 and
        pe.import_details[4].functions[11].name == "NtQuerySymbolicLinkObject" and
        pe.import_details[4].functions[11].rva == 305592 and
        pe.import_details[4].functions[12].name == "NtOpenSymbolicLinkObject" and
        pe.import_details[4].functions[12].rva == 305600 and
        pe.import_details[4].functions[13].name == "NtCreateSymbolicLinkObject" and
        pe.import_details[4].functions[13].rva == 305608 and
        pe.import_details[4].functions[14].name == "NtQuerySecurityObject" and
        pe.import_details[4].functions[14].rva == 305616 and
        pe.import_details[4].functions[15].name == "NtSetEaFile" and
        pe.import_details[4].functions[15].rva == 305624 and
        pe.import_details[4].functions[16].name == "NtQueryEaFile" and
        pe.import_details[4].functions[16].rva == 305632 and
        pe.import_details[4].functions[17].name == "NtSetVolumeInformationFile" and
        pe.import_details[4].functions[17].rva == 305640 and
        pe.import_details[4].functions[18].name == "NtQueryVolumeInformationFile" and
        pe.import_details[4].functions[18].rva == 305648 and
        pe.import_details[4].functions[19].name == "RtlCompareUnicodeString" and
        pe.import_details[4].functions[19].rva == 305656 and
        pe.import_details[4].functions[20].name == "NtQueryInformationProcess" and
        pe.import_details[4].functions[20].rva == 305664 and
        pe.import_details[4].functions[21].name == "NtQuerySystemInformation" and
        pe.import_details[4].functions[21].rva == 305672 and
        pe.import_details[4].functions[22].name == "NtFsControlFile" and
        pe.import_details[4].functions[22].rva == 305680 and
        pe.import_details[4].functions[23].name == "NtQueryAttributesFile" and
        pe.import_details[4].functions[23].rva == 305688 and
        pe.import_details[4].functions[24].name == "NtQueryDirectoryFile" and
        pe.import_details[4].functions[24].rva == 305696 and
        pe.import_details[4].functions[25].name == "NtQueryInformationFile" and
        pe.import_details[4].functions[25].rva == 305704 and
        pe.import_details[4].functions[26].name == "NtDeleteFile" and
        pe.import_details[4].functions[26].rva == 305712 and
        pe.import_details[4].functions[27].name == "NtSetInformationFile" and
        pe.import_details[4].functions[27].rva == 305720 and
        pe.import_details[4].functions[28].name == "RtlFreeSid" and
        pe.import_details[4].functions[28].rva == 305728 and
        pe.import_details[4].functions[29].name == "RtlSetDaclSecurityDescriptor" and
        pe.import_details[4].functions[29].rva == 305736 and
        pe.import_details[4].functions[30].name == "RtlAddAccessAllowedAce" and
        pe.import_details[4].functions[30].rva == 305744 and
        pe.import_details[4].functions[31].name == "RtlCreateAcl" and
        pe.import_details[4].functions[31].rva == 305752 and
        pe.import_details[4].functions[32].name == "RtlLengthSid" and
        pe.import_details[4].functions[32].rva == 305760 and
        pe.import_details[4].functions[33].name == "RtlAllocateAndInitializeSid" and
        pe.import_details[4].functions[33].rva == 305768 and
        pe.import_details[4].functions[34].name == "RtlFreeHeap" and
        pe.import_details[4].functions[34].rva == 305776 and
        pe.import_details[4].functions[35].name == "NtSetSecurityObject" and
        pe.import_details[4].functions[35].rva == 305784 and
        pe.import_details[4].functions[36].name == "RtlSetOwnerSecurityDescriptor" and
        pe.import_details[4].functions[36].rva == 305792 and
        pe.import_details[4].functions[37].name == "RtlCreateSecurityDescriptor" and
        pe.import_details[4].functions[37].rva == 305800 and
        pe.import_details[4].functions[38].name == "RtlAllocateHeap" and
        pe.import_details[4].functions[38].rva == 305808 and
        pe.import_details[4].functions[39].name == "NtQueryInformationToken" and
        pe.import_details[4].functions[39].rva == 305816 and
        pe.import_details[4].functions[40].name == "NtOpenProcessToken" and
        pe.import_details[4].functions[40].rva == 305824 and
        pe.import_details[4].functions[41].name == "NtUnmapViewOfSection" and
        pe.import_details[4].functions[41].rva == 305832 and
        pe.import_details[4].functions[42].name == "NtMapViewOfSection" and
        pe.import_details[4].functions[42].rva == 305840 and
        pe.import_details[4].functions[43].name == "NtOpenSection" and
        pe.import_details[4].functions[43].rva == 305848 and
        pe.import_details[4].functions[44].name == "NtCreateSection" and
        pe.import_details[4].functions[44].rva == 305856 and
        pe.import_details[4].functions[45].name == "NtUnlockFile" and
        pe.import_details[4].functions[45].rva == 305864 and
        pe.import_details[4].functions[46].name == "NtLockFile" and
        pe.import_details[4].functions[46].rva == 305872 and
        pe.import_details[4].functions[47].name == "NtWriteFile" and
        pe.import_details[4].functions[47].rva == 305880 and
        pe.import_details[4].functions[48].name == "NtReadFile" and
        pe.import_details[4].functions[48].rva == 305888    )
 and
    pe.import_details[4].library_name == "ntdll.dll" and
    pe.import_details[4].number_of_functions == 49 and
    (
        pe.import_details[5].functions[0].name == "CreatePropertySheetPageW" and
        pe.import_details[5].functions[0].rva == 303392 and
        pe.import_details[5].functions[1].name == "ImageList_ReplaceIcon" and
        pe.import_details[5].functions[1].rva == 303400 and
        pe.import_details[5].functions[2].name == "ord17" and
        pe.import_details[5].functions[2].ordinal == 17 and
        pe.import_details[5].functions[2].rva == 303408 and
        pe.import_details[5].functions[3].name == "PropertySheetW" and
        pe.import_details[5].functions[3].rva == 303416 and
        pe.import_details[5].functions[4].name == "ImageList_Create" and
        pe.import_details[5].functions[4].rva == 303424    )
 and
    pe.import_details[5].library_name == "COMCTL32.dll" and
    pe.import_details[5].number_of_functions == 5 and
    (
        pe.import_details[6].functions[0].name == "GetFileVersionInfoSizeW" and
        pe.import_details[6].functions[0].rva == 305472 and
        pe.import_details[6].functions[1].name == "GetFileVersionInfoW" and
        pe.import_details[6].functions[1].rva == 305480 and
        pe.import_details[6].functions[2].name == "VerQueryValueW" and
        pe.import_details[6].functions[2].rva == 305488    )
 and
    pe.import_details[6].library_name == "VERSION.dll" and
    pe.import_details[6].number_of_functions == 3 and
    (
        pe.import_details[7].functions[0].name == "GetSaveFileNameW" and
        pe.import_details[7].functions[0].rva == 303440 and
        pe.import_details[7].functions[1].name == "GetOpenFileNameW" and
        pe.import_details[7].functions[1].rva == 303448    )
 and
    pe.import_details[7].library_name == "COMDLG32.dll" and
    pe.import_details[7].number_of_functions == 2 and
    (
        pe.import_details[8].functions[0].name == "SHBrowseForFolderW" and
        pe.import_details[8].functions[0].rva == 304552 and
        pe.import_details[8].functions[1].name == "SHGetPathFromIDListW" and
        pe.import_details[8].functions[1].rva == 304560 and
        pe.import_details[8].functions[2].name == "SHGetMalloc" and
        pe.import_details[8].functions[2].rva == 304568 and
        pe.import_details[8].functions[3].name == "ShellExecuteW" and
        pe.import_details[8].functions[3].rva == 304576    )
 and
    pe.import_details[8].library_name == "SHELL32.dll" and
    pe.import_details[8].number_of_functions == 4)
 and
pe.is_pe == 1 and
pe.linker_version.major == 9 and
pe.linker_version.minor == 0 and
pe.loader_flags == 0 and
pe.machine == 34404 and
pe.number_of_delayed_imported_functions == 0 and
pe.number_of_delayed_imports == 0 and
pe.number_of_exports == 0 and
pe.number_of_imported_functions == 341 and
pe.number_of_imports == 9 and
pe.number_of_resources == 72 and
pe.number_of_rva_and_sizes == 16 and
pe.number_of_sections == 6 and
pe.number_of_symbols == 0 and
pe.number_of_version_infos == 9 and
pe.opthdr_magic == 523 and
pe.os_version.major == 5 and
pe.os_version.minor == 2 and
pe.overlay.offset == 0 and
pe.overlay.size == 0 and
pe.pdb_path == "FileTest.pdb" and
pe.pointer_to_symbol_table == 0 and
pe.resource_timestamp == 0 and
pe.resource_version.major == 0 and
pe.resource_version.minor == 0 and
(
    pe.resources[0].id == 106 and
    pe.resources[0].language == 1033 and
    pe.resources[0].length == 2 and
    pe.resources[0].offset == 695696 and
    pe.resources[0].rva == 720784 and
    pe.resources[0].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[1].id == 107 and
    pe.resources[1].language == 1033 and
    pe.resources[1].length == 2 and
    pe.resources[1].offset == 695688 and
    pe.resources[1].rva == 720776 and
    pe.resources[1].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[2].id == 111 and
    pe.resources[2].language == 1033 and
    pe.resources[2].length == 2 and
    pe.resources[2].offset == 695712 and
    pe.resources[2].rva == 720800 and
    pe.resources[2].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[3].id == 112 and
    pe.resources[3].language == 1033 and
    pe.resources[3].length == 2 and
    pe.resources[3].offset == 695704 and
    pe.resources[3].rva == 720792 and
    pe.resources[3].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[4].id == 114 and
    pe.resources[4].language == 1033 and
    pe.resources[4].length == 2 and
    pe.resources[4].offset == 695680 and
    pe.resources[4].rva == 720768 and
    pe.resources[4].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[5].id == 1 and
    pe.resources[5].language == 0 and
    pe.resources[5].length == 1640 and
    pe.resources[5].offset == 648112 and
    pe.resources[5].rva == 673200 and
    pe.resources[5].type == 3 and
    pe.resources[6].id == 2 and
    pe.resources[6].language == 0 and
    pe.resources[6].length == 296 and
    pe.resources[6].offset == 649752 and
    pe.resources[6].rva == 674840 and
    pe.resources[6].type == 3 and
    pe.resources[7].id == 3 and
    pe.resources[7].language == 0 and
    pe.resources[7].length == 744 and
    pe.resources[7].offset == 650048 and
    pe.resources[7].rva == 675136 and
    pe.resources[7].type == 3 and
    pe.resources[8].id == 4 and
    pe.resources[8].language == 0 and
    pe.resources[8].length == 1384 and
    pe.resources[8].offset == 650792 and
    pe.resources[8].rva == 675880 and
    pe.resources[8].type == 3 and
    pe.resources[9].id == 5 and
    pe.resources[9].language == 0 and
    pe.resources[9].length == 2216 and
    pe.resources[9].offset == 652176 and
    pe.resources[9].rva == 677264 and
    pe.resources[9].type == 3 and
    pe.resources[10].id == 6 and
    pe.resources[10].language == 0 and
    pe.resources[10].length == 3752 and
    pe.resources[10].offset == 654392 and
    pe.resources[10].rva == 679480 and
    pe.resources[10].type == 3 and
    pe.resources[11].id == 7 and
    pe.resources[11].language == 0 and
    pe.resources[11].length == 296 and
    pe.resources[11].offset == 658240 and
    pe.resources[11].rva == 683328 and
    pe.resources[11].type == 3 and
    pe.resources[12].id == 8 and
    pe.resources[12].language == 0 and
    pe.resources[12].length == 1384 and
    pe.resources[12].offset == 658536 and
    pe.resources[12].rva == 683624 and
    pe.resources[12].type == 3 and
    pe.resources[13].id == 9 and
    pe.resources[13].language == 0 and
    pe.resources[13].length == 296 and
    pe.resources[13].offset == 659960 and
    pe.resources[13].rva == 685048 and
    pe.resources[13].type == 3 and
    pe.resources[14].id == 10 and
    pe.resources[14].language == 0 and
    pe.resources[14].length == 1384 and
    pe.resources[14].offset == 660256 and
    pe.resources[14].rva == 685344 and
    pe.resources[14].type == 3 and
    pe.resources[15].id == 11 and
    pe.resources[15].language == 0 and
    pe.resources[15].length == 296 and
    pe.resources[15].offset == 661680 and
    pe.resources[15].rva == 686768 and
    pe.resources[15].type == 3 and
    pe.resources[16].id == 12 and
    pe.resources[16].language == 0 and
    pe.resources[16].length == 1384 and
    pe.resources[16].offset == 661976 and
    pe.resources[16].rva == 687064 and
    pe.resources[16].type == 3 and
    pe.resources[17].id == 13 and
    pe.resources[17].language == 0 and
    pe.resources[17].length == 296 and
    pe.resources[17].offset == 663400 and
    pe.resources[17].rva == 688488 and
    pe.resources[17].type == 3 and
    pe.resources[18].id == 14 and
    pe.resources[18].language == 0 and
    pe.resources[18].length == 1384 and
    pe.resources[18].offset == 663696 and
    pe.resources[18].rva == 688784 and
    pe.resources[18].type == 3 and
    pe.resources[19].id == 15 and
    pe.resources[19].language == 0 and
    pe.resources[19].length == 1128 and
    pe.resources[19].offset == 665120 and
    pe.resources[19].rva == 690208 and
    pe.resources[19].type == 3 and
    pe.resources[20].id == 123 and
    pe.resources[20].language == 1033 and
    pe.resources[20].length == 248 and
    pe.resources[20].offset == 667160 and
    pe.resources[20].rva == 692248 and
    pe.resources[20].type == 4 and
    pe.resources[21].id == 129 and
    pe.resources[21].language == 1033 and
    pe.resources[21].length == 164 and
    pe.resources[21].offset == 667408 and
    pe.resources[21].rva == 692496 and
    pe.resources[21].type == 4 and
    pe.resources[22].id == 139 and
    pe.resources[22].language == 1033 and
    pe.resources[22].length == 648 and
    pe.resources[22].offset == 667576 and
    pe.resources[22].rva == 692664 and
    pe.resources[22].type == 4 and
    pe.resources[23].id == 141 and
    pe.resources[23].language == 1033 and
    pe.resources[23].length == 312 and
    pe.resources[23].offset == 668224 and
    pe.resources[23].rva == 693312 and
    pe.resources[23].type == 4 and
    pe.resources[24].id == 144 and
    pe.resources[24].language == 1033 and
    pe.resources[24].length == 136 and
    pe.resources[24].offset == 668536 and
    pe.resources[24].rva == 693624 and
    pe.resources[24].type == 4 and
    pe.resources[25].id == 145 and
    pe.resources[25].language == 1033 and
    pe.resources[25].length == 128 and
    pe.resources[25].offset == 668832 and
    pe.resources[25].rva == 693920 and
    pe.resources[25].type == 4 and
    pe.resources[26].id == 146 and
    pe.resources[26].language == 1033 and
    pe.resources[26].length == 156 and
    pe.resources[26].offset == 668672 and
    pe.resources[26].rva == 693760 and
    pe.resources[26].type == 4 and
    pe.resources[27].id == 102 and
    pe.resources[27].language == 1033 and
    pe.resources[27].length == 1320 and
    pe.resources[27].offset == 669144 and
    pe.resources[27].rva == 694232 and
    pe.resources[27].type == 5 and
    pe.resources[28].id == 103 and
    pe.resources[28].language == 1033 and
    pe.resources[28].length == 1940 and
    pe.resources[28].offset == 670464 and
    pe.resources[28].rva == 695552 and
    pe.resources[28].type == 5 and
    pe.resources[29].id == 104 and
    pe.resources[29].language == 1033 and
    pe.resources[29].length == 2464 and
    pe.resources[29].offset == 672408 and
    pe.resources[29].rva == 697496 and
    pe.resources[29].type == 5 and
    pe.resources[30].id == 105 and
    pe.resources[30].language == 1033 and
    pe.resources[30].length == 1450 and
    pe.resources[30].offset == 674872 and
    pe.resources[30].rva == 699960 and
    pe.resources[30].type == 5 and
    pe.resources[31].id == 106 and
    pe.resources[31].language == 1033 and
    pe.resources[31].length == 2368 and
    pe.resources[31].offset == 686384 and
    pe.resources[31].rva == 711472 and
    pe.resources[31].type == 5 and
    pe.resources[32].id == 107 and
    pe.resources[32].language == 1033 and
    pe.resources[32].length == 2172 and
    pe.resources[32].offset == 676328 and
    pe.resources[32].rva == 701416 and
    pe.resources[32].type == 5 and
    pe.resources[33].id == 108 and
    pe.resources[33].language == 1033 and
    pe.resources[33].length == 1076 and
    pe.resources[33].offset == 678504 and
    pe.resources[33].rva == 703592 and
    pe.resources[33].type == 5 and
    pe.resources[34].id == 109 and
    pe.resources[34].language == 1033 and
    pe.resources[34].length == 928 and
    pe.resources[34].offset == 679584 and
    pe.resources[34].rva == 704672 and
    pe.resources[34].type == 5 and
    pe.resources[35].id == 110 and
    pe.resources[35].language == 1033 and
    pe.resources[35].length == 764 and
    pe.resources[35].offset == 680512 and
    pe.resources[35].rva == 705600 and
    pe.resources[35].type == 5 and
    pe.resources[36].id == 111 and
    pe.resources[36].language == 1033 and
    pe.resources[36].length == 1112 and
    pe.resources[36].offset == 681280 and
    pe.resources[36].rva == 706368 and
    pe.resources[36].type == 5 and
    pe.resources[37].id == 112 and
    pe.resources[37].language == 1033 and
    pe.resources[37].length == 1544 and
    pe.resources[37].offset == 682392 and
    pe.resources[37].rva == 707480 and
    pe.resources[37].type == 5 and
    pe.resources[38].id == 113 and
    pe.resources[38].language == 1033 and
    pe.resources[38].length == 644 and
    pe.resources[38].offset == 683936 and
    pe.resources[38].rva == 709024 and
    pe.resources[38].type == 5 and
    pe.resources[39].id == 114 and
    pe.resources[39].language == 1033 and
    pe.resources[39].length == 1500 and
    pe.resources[39].offset == 690192 and
    pe.resources[39].rva == 715280 and
    pe.resources[39].type == 5 and
    pe.resources[40].id == 118 and
    pe.resources[40].language == 1033 and
    pe.resources[40].length == 240 and
    pe.resources[40].offset == 694784 and
    pe.resources[40].rva == 719872 and
    pe.resources[40].type == 5 and
    pe.resources[41].id == 119 and
    pe.resources[41].language == 1033 and
    pe.resources[41].length == 266 and
    pe.resources[41].offset == 684584 and
    pe.resources[41].rva == 709672 and
    pe.resources[41].type == 5 and
    pe.resources[42].id == 124 and
    pe.resources[42].language == 1033 and
    pe.resources[42].length == 452 and
    pe.resources[42].offset == 684856 and
    pe.resources[42].rva == 709944 and
    pe.resources[42].type == 5 and
    pe.resources[43].id == 128 and
    pe.resources[43].language == 1033 and
    pe.resources[43].length == 532 and
    pe.resources[43].offset == 685312 and
    pe.resources[43].rva == 710400 and
    pe.resources[43].type == 5 and
    pe.resources[44].id == 132 and
    pe.resources[44].language == 1033 and
    pe.resources[44].length == 180 and
    pe.resources[44].offset == 668960 and
    pe.resources[44].rva == 694048 and
    pe.resources[44].type == 5 and
    pe.resources[45].id == 133 and
    pe.resources[45].language == 1033 and
    pe.resources[45].length == 530 and
    pe.resources[45].offset == 685848 and
    pe.resources[45].rva == 710936 and
    pe.resources[45].type == 5 and
    pe.resources[46].id == 137 and
    pe.resources[46].language == 1033 and
    pe.resources[46].length == 214 and
    pe.resources[46].offset == 688752 and
    pe.resources[46].rva == 713840 and
    pe.resources[46].type == 5 and
    pe.resources[47].id == 138 and
    pe.resources[47].language == 1033 and
    pe.resources[47].length == 466 and
    pe.resources[47].offset == 688968 and
    pe.resources[47].rva == 714056 and
    pe.resources[47].type == 5 and
    pe.resources[48].id == 140 and
    pe.resources[48].language == 1033 and
    pe.resources[48].length == 312 and
    pe.resources[48].offset == 689440 and
    pe.resources[48].rva == 714528 and
    pe.resources[48].type == 5 and
    pe.resources[49].id == 143 and
    pe.resources[49].language == 1033 and
    pe.resources[49].length == 438 and
    pe.resources[49].offset == 689752 and
    pe.resources[49].rva == 714840 and
    pe.resources[49].type == 5 and
    pe.resources[50].id == 144 and
    pe.resources[50].language == 1033 and
    pe.resources[50].length == 798 and
    pe.resources[50].offset == 691696 and
    pe.resources[50].rva == 716784 and
    pe.resources[50].type == 5 and
    pe.resources[51].id == 145 and
    pe.resources[51].language == 1033 and
    pe.resources[51].length == 826 and
    pe.resources[51].offset == 692496 and
    pe.resources[51].rva == 717584 and
    pe.resources[51].type == 5 and
    pe.resources[52].id == 146 and
    pe.resources[52].language == 1033 and
    pe.resources[52].length == 806 and
    pe.resources[52].offset == 693328 and
    pe.resources[52].rva == 718416 and
    pe.resources[52].type == 5 and
    pe.resources[53].id == 147 and
    pe.resources[53].language == 1033 and
    pe.resources[53].length == 648 and
    pe.resources[53].offset == 694136 and
    pe.resources[53].rva == 719224 and
    pe.resources[53].type == 5 and
    pe.resources[54].id == 10 and
    pe.resources[54].language == 1033 and
    pe.resources[54].length == 62 and
    pe.resources[54].offset == 701192 and
    pe.resources[54].rva == 726280 and
    pe.resources[54].type == 6 and
    pe.resources[55].id == 251 and
    pe.resources[55].language == 1033 and
    pe.resources[55].length == 968 and
    pe.resources[55].offset == 695720 and
    pe.resources[55].rva == 720808 and
    pe.resources[55].type == 6 and
    pe.resources[56].id == 252 and
    pe.resources[56].language == 1033 and
    pe.resources[56].length == 702 and
    pe.resources[56].offset == 696688 and
    pe.resources[56].rva == 721776 and
    pe.resources[56].type == 6 and
    pe.resources[57].id == 253 and
    pe.resources[57].language == 1033 and
    pe.resources[57].length == 1066 and
    pe.resources[57].offset == 697392 and
    pe.resources[57].rva == 722480 and
    pe.resources[57].type == 6 and
    pe.resources[58].id == 254 and
    pe.resources[58].language == 1033 and
    pe.resources[58].length == 710 and
    pe.resources[58].offset == 698464 and
    pe.resources[58].rva == 723552 and
    pe.resources[58].type == 6 and
    pe.resources[59].id == 255 and
    pe.resources[59].language == 1033 and
    pe.resources[59].length == 1444 and
    pe.resources[59].offset == 699176 and
    pe.resources[59].rva == 724264 and
    pe.resources[59].type == 6 and
    pe.resources[60].id == 256 and
    pe.resources[60].language == 1033 and
    pe.resources[60].length == 568 and
    pe.resources[60].offset == 700624 and
    pe.resources[60].rva == 725712 and
    pe.resources[60].type == 6 and
    pe.resources[61].id == 121 and
    pe.resources[61].language == 0 and
    pe.resources[61].length == 8 and
    pe.resources[61].offset == 646320 and
    pe.resources[61].rva == 671408 and
    pe.resources[61].type == 9 and
    pe.resources[62].id == 101 and
    pe.resources[62].language == 0 and
    pe.resources[62].length == 90 and
    pe.resources[62].offset == 658144 and
    pe.resources[62].rva == 683232 and
    pe.resources[62].type == 14 and
    pe.resources[63].id == 125 and
    pe.resources[63].language == 0 and
    pe.resources[63].length == 34 and
    pe.resources[63].offset == 659920 and
    pe.resources[63].rva == 685008 and
    pe.resources[63].type == 14 and
    pe.resources[64].id == 126 and
    pe.resources[64].language == 0 and
    pe.resources[64].length == 34 and
    pe.resources[64].offset == 661640 and
    pe.resources[64].rva == 686728 and
    pe.resources[64].type == 14 and
    pe.resources[65].id == 127 and
    pe.resources[65].language == 0 and
    pe.resources[65].length == 34 and
    pe.resources[65].offset == 663360 and
    pe.resources[65].rva == 688448 and
    pe.resources[65].type == 14 and
    pe.resources[66].id == 140 and
    pe.resources[66].language == 0 and
    pe.resources[66].length == 34 and
    pe.resources[66].offset == 665080 and
    pe.resources[66].rva == 690168 and
    pe.resources[66].type == 14 and
    pe.resources[67].id == 143 and
    pe.resources[67].language == 0 and
    pe.resources[67].length == 20 and
    pe.resources[67].offset == 666248 and
    pe.resources[67].rva == 691336 and
    pe.resources[67].type == 14 and
    pe.resources[68].id == 1 and
    pe.resources[68].language == 1033 and
    pe.resources[68].length == 888 and
    pe.resources[68].offset == 666272 and
    pe.resources[68].rva == 691360 and
    pe.resources[68].type == 16 and
    pe.resources[69].id == 1 and
    pe.resources[69].language == 0 and
    pe.resources[69].length == 1779 and
    pe.resources[69].offset == 646328 and
    pe.resources[69].rva == 671416 and
    pe.resources[69].type == 24 and
    pe.resources[70].id == 103 and
    pe.resources[70].language == 1033 and
    pe.resources[70].length == 282 and
    pe.resources[70].offset == 695392 and
    pe.resources[70].rva == 720480 and
    pe.resources[70].type == 240 and
    pe.resources[71].id == 104 and
    pe.resources[71].language == 1033 and
    pe.resources[71].length == 363 and
    pe.resources[71].offset == 695024 and
    pe.resources[71].rva == 720112 and
    pe.resources[71].type == 240)
 and
pe.rich_signature.clear_data == "\x44\x61\x6e\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x78\x83\x00\x6d\x00\x00\x00\x09\x78\x95\x00\x0a\x00\x00\x00\x09\x78\x84\x00\x3e\x00\x00\x00\x27\xc6\x7b\x00\x13\x00\x00\x00\x00\x00\x01\x00\x79\x01\x00\x00\x09\x78\x8a\x00\x1d\x00\x00\x00\x1e\x52\x94\x00\x01\x00\x00\x00\x09\x78\x91\x00\x01\x00\x00\x00" and
pe.rich_signature.key == 3773202274 and
pe.rich_signature.length == 80 and
pe.rich_signature.offset == 128 and
pe.rich_signature.raw_data == "\x26\x1e\x88\xb3\x62\x7f\xe6\xe0\x62\x7f\xe6\xe0\x62\x7f\xe6\xe0\x6b\x07\x65\xe0\x0f\x7f\xe6\xe0\x6b\x07\x73\xe0\x68\x7f\xe6\xe0\x6b\x07\x62\xe0\x5c\x7f\xe6\xe0\x45\xb9\x9d\xe0\x71\x7f\xe6\xe0\x62\x7f\xe7\xe0\x1b\x7e\xe6\xe0\x6b\x07\x6c\xe0\x7f\x7f\xe6\xe0\x7c\x2d\x72\xe0\x63\x7f\xe6\xe0\x6b\x07\x77\xe0\x63\x7f\xe6\xe0" and
true
 and
true
 and
pe.section_alignment == 4096 and
(
    pe.sections[0].characteristics == 1610612768 and
    pe.sections[0].full_name == ".text" and
    pe.sections[0].name == ".text" and
    pe.sections[0].number_of_line_numbers == 0 and
    pe.sections[0].number_of_relocations == 0 and
    pe.sections[0].pointer_to_line_numbers == 0 and
    pe.sections[0].pointer_to_relocations == 0 and
    pe.sections[0].raw_data_offset == 1024 and
    pe.sections[0].raw_data_size == 296960 and
    pe.sections[0].virtual_address == 4096 and
    pe.sections[0].virtual_size == 296514 and
    pe.sections[1].characteristics == 1073741888 and
    pe.sections[1].full_name == ".rdata" and
    pe.sections[1].name == ".rdata" and
    pe.sections[1].number_of_line_numbers == 0 and
    pe.sections[1].number_of_relocations == 0 and
    pe.sections[1].pointer_to_line_numbers == 0 and
    pe.sections[1].pointer_to_relocations == 0 and
    pe.sections[1].raw_data_offset == 297984 and
    pe.sections[1].raw_data_size == 254464 and
    pe.sections[1].virtual_address == 303104 and
    pe.sections[1].virtual_size == 254118 and
    pe.sections[2].characteristics == 3221225536 and
    pe.sections[2].full_name == ".data" and
    pe.sections[2].name == ".data" and
    pe.sections[2].number_of_line_numbers == 0 and
    pe.sections[2].number_of_relocations == 0 and
    pe.sections[2].pointer_to_line_numbers == 0 and
    pe.sections[2].pointer_to_relocations == 0 and
    pe.sections[2].raw_data_offset == 552448 and
    pe.sections[2].raw_data_size == 75264 and
    pe.sections[2].virtual_address == 561152 and
    pe.sections[2].virtual_size == 85248 and
    pe.sections[3].characteristics == 1073741888 and
    pe.sections[3].full_name == ".pdata" and
    pe.sections[3].name == ".pdata" and
    pe.sections[3].number_of_line_numbers == 0 and
    pe.sections[3].number_of_relocations == 0 and
    pe.sections[3].pointer_to_line_numbers == 0 and
    pe.sections[3].pointer_to_relocations == 0 and
    pe.sections[3].raw_data_offset == 627712 and
    pe.sections[3].raw_data_size == 14336 and
    pe.sections[3].virtual_address == 647168 and
    pe.sections[3].virtual_size == 13932 and
    pe.sections[4].characteristics == 3221225536 and
    pe.sections[4].full_name == ".tls" and
    pe.sections[4].name == ".tls" and
    pe.sections[4].number_of_line_numbers == 0 and
    pe.sections[4].number_of_relocations == 0 and
    pe.sections[4].pointer_to_line_numbers == 0 and
    pe.sections[4].pointer_to_relocations == 0 and
    pe.sections[4].raw_data_offset == 642048 and
    pe.sections[4].raw_data_size == 512 and
    pe.sections[4].virtual_address == 663552 and
    pe.sections[4].virtual_size == 9 and
    pe.sections[5].characteristics == 1073741888 and
    pe.sections[5].full_name == ".rsrc" and
    pe.sections[5].name == ".rsrc" and
    pe.sections[5].number_of_line_numbers == 0 and
    pe.sections[5].number_of_relocations == 0 and
    pe.sections[5].pointer_to_line_numbers == 0 and
    pe.sections[5].pointer_to_relocations == 0 and
    pe.sections[5].raw_data_offset == 642560 and
    pe.sections[5].raw_data_size == 58880 and
    pe.sections[5].virtual_address == 667648 and
    pe.sections[5].virtual_size == 58696)
 and
pe.size_of_code == 296960 and
pe.size_of_headers == 1024 and
pe.size_of_heap_commit == 4096 and
pe.size_of_heap_reserve == 1048576 and
pe.size_of_image == 729088 and
pe.size_of_initialized_data == 413696 and
pe.size_of_optional_header == 240 and
pe.size_of_stack_commit == 4096 and
pe.size_of_stack_reserve == 1048576 and
pe.size_of_uninitialized_data == 0 and
pe.subsystem == 2 and
pe.subsystem_version.major == 5 and
pe.subsystem_version.minor == 2 and
pe.timestamp == 1630563984 and
    pe.version_info["CompanyName"] == "Ladislav Zezula" and
    pe.version_info["FileDescription"] == "Interactive File System API Test" and
    pe.version_info["FileVersion"] == "2, 7, 0, 602" and
    pe.version_info["InternalName"] == "FileTest" and
    pe.version_info["LegalCopyright"] == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x31\x38\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info["LegalTrademarks"] == "http://www.zezula.net" and
    pe.version_info["OriginalFilename"] == "FileTest.exe" and
    pe.version_info["ProductName"] == "FileTest" and
    pe.version_info["ProductVersion"] == "2, 7, 0, 602" and
(
    pe.version_info_list[0].key == "CompanyName" and
    pe.version_info_list[0].value == "Ladislav Zezula" and
    pe.version_info_list[1].key == "FileDescription" and
    pe.version_info_list[1].value == "Interactive File System API Test" and
    pe.version_info_list[2].key == "FileVersion" and
    pe.version_info_list[2].value == "2, 7, 0, 602" and
    pe.version_info_list[3].key == "InternalName" and
    pe.version_info_list[3].value == "FileTest" and
    pe.version_info_list[4].key == "LegalCopyright" and
    pe.version_info_list[4].value == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x31\x38\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info_list[5].key == "LegalTrademarks" and
    pe.version_info_list[5].value == "http://www.zezula.net" and
    pe.version_info_list[6].key == "OriginalFilename" and
    pe.version_info_list[6].value == "FileTest.exe" and
    pe.version_info_list[7].key == "ProductName" and
    pe.version_info_list[7].value == "FileTest" and
    pe.version_info_list[8].key == "ProductVersion" and
    pe.version_info_list[8].value == "2, 7, 0, 602")
 and
pe.win32_version_value == 0
}"#,
        "tests/assets/yara_1561/x64/FileTest.exe",
        true,
    );
}

#[test]
fn test_coverage_1561_align_40() {
    check_file(
        r#"import "pe"
rule test {
    condition:
pe.base_of_code == 768 and
pe.characteristics == 35 and
pe.checksum == 753893 and
(
    pe.data_directories[0].size == 0 and
    pe.data_directories[0].virtual_address == 0 and
    pe.data_directories[1].size == 200 and
    pe.data_directories[1].virtual_address == 541964 and
    pe.data_directories[2].size == 58696 and
    pe.data_directories[2].virtual_address == 650752 and
    pe.data_directories[3].size == 13932 and
    pe.data_directories[3].virtual_address == 636736 and
    pe.data_directories[4].size == 0 and
    pe.data_directories[4].virtual_address == 0 and
    pe.data_directories[5].size == 0 and
    pe.data_directories[5].virtual_address == 0 and
    pe.data_directories[6].size == 28 and
    pe.data_directories[6].virtual_address == 300288 and
    pe.data_directories[7].size == 0 and
    pe.data_directories[7].virtual_address == 0 and
    pe.data_directories[8].size == 0 and
    pe.data_directories[8].virtual_address == 0 and
    pe.data_directories[9].size == 40 and
    pe.data_directories[9].virtual_address == 527096 and
    pe.data_directories[10].size == 0 and
    pe.data_directories[10].virtual_address == 0 and
    pe.data_directories[11].size == 0 and
    pe.data_directories[11].virtual_address == 0 and
    pe.data_directories[12].size == 2800 and
    pe.data_directories[12].virtual_address == 297344 and
    pe.data_directories[13].size == 0 and
    pe.data_directories[13].virtual_address == 0 and
    pe.data_directories[14].size == 0 and
    pe.data_directories[14].virtual_address == 0 and
    pe.data_directories[15].size == 0 and
    pe.data_directories[15].virtual_address == 0)
 and
true and
pe.dll_characteristics == 33024 and
pe.entry_point == 46400 and
pe.entry_point_raw == 46400 and
pe.file_alignment == 64 and
pe.image_base == 5368709120 and
pe.image_version.major == 0 and
pe.image_version.minor == 0 and
(
    (
        pe.import_details[0].functions[0].name == "HeapReAlloc" and
        pe.import_details[0].functions[0].rva == 297800 and
        pe.import_details[0].functions[1].name == "GetProcessHeap" and
        pe.import_details[0].functions[1].rva == 297808 and
        pe.import_details[0].functions[2].name == "GetCurrentProcess" and
        pe.import_details[0].functions[2].rva == 297816 and
        pe.import_details[0].functions[3].name == "MultiByteToWideChar" and
        pe.import_details[0].functions[3].rva == 297824 and
        pe.import_details[0].functions[4].name == "GetCurrentDirectoryW" and
        pe.import_details[0].functions[4].rva == 297832 and
        pe.import_details[0].functions[5].name == "EnumResourceNamesW" and
        pe.import_details[0].functions[5].rva == 297840 and
        pe.import_details[0].functions[6].name == "FreeLibrary" and
        pe.import_details[0].functions[6].rva == 297848 and
        pe.import_details[0].functions[7].name == "LoadLibraryW" and
        pe.import_details[0].functions[7].rva == 297856 and
        pe.import_details[0].functions[8].name == "GlobalReAlloc" and
        pe.import_details[0].functions[8].rva == 297864 and
        pe.import_details[0].functions[9].name == "GlobalSize" and
        pe.import_details[0].functions[9].rva == 297872 and
        pe.import_details[0].functions[10].name == "GlobalFree" and
        pe.import_details[0].functions[10].rva == 297880 and
        pe.import_details[0].functions[11].name == "GlobalUnlock" and
        pe.import_details[0].functions[11].rva == 297888 and
        pe.import_details[0].functions[12].name == "GlobalLock" and
        pe.import_details[0].functions[12].rva == 297896 and
        pe.import_details[0].functions[13].name == "GlobalAlloc" and
        pe.import_details[0].functions[13].rva == 297904 and
        pe.import_details[0].functions[14].name == "OpenProcess" and
        pe.import_details[0].functions[14].rva == 297912 and
        pe.import_details[0].functions[15].name == "FlushFileBuffers" and
        pe.import_details[0].functions[15].rva == 297920 and
        pe.import_details[0].functions[16].name == "GetFileAttributesW" and
        pe.import_details[0].functions[16].rva == 297928 and
        pe.import_details[0].functions[17].name == "CreateFileA" and
        pe.import_details[0].functions[17].rva == 297936 and
        pe.import_details[0].functions[18].name == "WriteConsoleW" and
        pe.import_details[0].functions[18].rva == 297944 and
        pe.import_details[0].functions[19].name == "GetConsoleOutputCP" and
        pe.import_details[0].functions[19].rva == 297952 and
        pe.import_details[0].functions[20].name == "WriteConsoleA" and
        pe.import_details[0].functions[20].rva == 297960 and
        pe.import_details[0].functions[21].name == "SetStdHandle" and
        pe.import_details[0].functions[21].rva == 297968 and
        pe.import_details[0].functions[22].name == "GetConsoleMode" and
        pe.import_details[0].functions[22].rva == 297976 and
        pe.import_details[0].functions[23].name == "GetConsoleCP" and
        pe.import_details[0].functions[23].rva == 297984 and
        pe.import_details[0].functions[24].name == "GetLocaleInfoA" and
        pe.import_details[0].functions[24].rva == 297992 and
        pe.import_details[0].functions[25].name == "GetStringTypeW" and
        pe.import_details[0].functions[25].rva == 298000 and
        pe.import_details[0].functions[26].name == "GetStringTypeA" and
        pe.import_details[0].functions[26].rva == 298008 and
        pe.import_details[0].functions[27].name == "QueryPerformanceCounter" and
        pe.import_details[0].functions[27].rva == 298016 and
        pe.import_details[0].functions[28].name == "GetCurrentThread" and
        pe.import_details[0].functions[28].rva == 298024 and
        pe.import_details[0].functions[29].name == "HeapCreate" and
        pe.import_details[0].functions[29].rva == 298032 and
        pe.import_details[0].functions[30].name == "DeleteFileW" and
        pe.import_details[0].functions[30].rva == 298040 and
        pe.import_details[0].functions[31].name == "GetStartupInfoA" and
        pe.import_details[0].functions[31].rva == 298048 and
        pe.import_details[0].functions[32].name == "GetFileType" and
        pe.import_details[0].functions[32].rva == 298056 and
        pe.import_details[0].functions[33].name == "SetHandleCount" and
        pe.import_details[0].functions[33].rva == 298064 and
        pe.import_details[0].functions[34].name == "GetCommandLineW" and
        pe.import_details[0].functions[34].rva == 298072 and
        pe.import_details[0].functions[35].name == "GetEnvironmentStringsW" and
        pe.import_details[0].functions[35].rva == 298080 and
        pe.import_details[0].functions[36].name == "FreeEnvironmentStringsW" and
        pe.import_details[0].functions[36].rva == 298088 and
        pe.import_details[0].functions[37].name == "InitializeCriticalSectionAndSpinCount" and
        pe.import_details[0].functions[37].rva == 298096 and
        pe.import_details[0].functions[38].name == "LoadLibraryA" and
        pe.import_details[0].functions[38].rva == 298104 and
        pe.import_details[0].functions[39].name == "GetModuleFileNameA" and
        pe.import_details[0].functions[39].rva == 298112 and
        pe.import_details[0].functions[40].name == "GetStdHandle" and
        pe.import_details[0].functions[40].rva == 298120 and
        pe.import_details[0].functions[41].name == "HeapSize" and
        pe.import_details[0].functions[41].rva == 298128 and
        pe.import_details[0].functions[42].name == "LCMapStringW" and
        pe.import_details[0].functions[42].rva == 298136 and
        pe.import_details[0].functions[43].name == "LCMapStringA" and
        pe.import_details[0].functions[43].rva == 298144 and
        pe.import_details[0].functions[44].name == "FlsAlloc" and
        pe.import_details[0].functions[44].rva == 298152 and
        pe.import_details[0].functions[45].name == "FlsFree" and
        pe.import_details[0].functions[45].rva == 298160 and
        pe.import_details[0].functions[46].name == "FlsSetValue" and
        pe.import_details[0].functions[46].rva == 298168 and
        pe.import_details[0].functions[47].name == "FlsGetValue" and
        pe.import_details[0].functions[47].rva == 298176 and
        pe.import_details[0].functions[48].name == "DecodePointer" and
        pe.import_details[0].functions[48].rva == 298184 and
        pe.import_details[0].functions[49].name == "EncodePointer" and
        pe.import_details[0].functions[49].rva == 298192 and
        pe.import_details[0].functions[50].name == "IsValidCodePage" and
        pe.import_details[0].functions[50].rva == 298200 and
        pe.import_details[0].functions[51].name == "GetOEMCP" and
        pe.import_details[0].functions[51].rva == 298208 and
        pe.import_details[0].functions[52].name == "GetACP" and
        pe.import_details[0].functions[52].rva == 298216 and
        pe.import_details[0].functions[53].name == "GetCPInfo" and
        pe.import_details[0].functions[53].rva == 298224 and
        pe.import_details[0].functions[54].name == "RtlPcToFileHeader" and
        pe.import_details[0].functions[54].rva == 298232 and
        pe.import_details[0].functions[55].name == "RaiseException" and
        pe.import_details[0].functions[55].rva == 298240 and
        pe.import_details[0].functions[56].name == "RtlUnwindEx" and
        pe.import_details[0].functions[56].rva == 298248 and
        pe.import_details[0].functions[57].name == "GetStartupInfoW" and
        pe.import_details[0].functions[57].rva == 298256 and
        pe.import_details[0].functions[58].name == "ExitProcess" and
        pe.import_details[0].functions[58].rva == 298264 and
        pe.import_details[0].functions[59].name == "Sleep" and
        pe.import_details[0].functions[59].rva == 298272 and
        pe.import_details[0].functions[60].name == "RtlCaptureContext" and
        pe.import_details[0].functions[60].rva == 298280 and
        pe.import_details[0].functions[61].name == "RtlLookupFunctionEntry" and
        pe.import_details[0].functions[61].rva == 298288 and
        pe.import_details[0].functions[62].name == "RtlVirtualUnwind" and
        pe.import_details[0].functions[62].rva == 298296 and
        pe.import_details[0].functions[63].name == "SetUnhandledExceptionFilter" and
        pe.import_details[0].functions[63].rva == 298304 and
        pe.import_details[0].functions[64].name == "UnhandledExceptionFilter" and
        pe.import_details[0].functions[64].rva == 298312 and
        pe.import_details[0].functions[65].name == "TerminateProcess" and
        pe.import_details[0].functions[65].rva == 298320 and
        pe.import_details[0].functions[66].name == "SizeofResource" and
        pe.import_details[0].functions[66].rva == 298328 and
        pe.import_details[0].functions[67].name == "FreeResource" and
        pe.import_details[0].functions[67].rva == 298336 and
        pe.import_details[0].functions[68].name == "IsDebuggerPresent" and
        pe.import_details[0].functions[68].rva == 298344 and
        pe.import_details[0].functions[69].name == "GetCurrentThreadId" and
        pe.import_details[0].functions[69].rva == 298352 and
        pe.import_details[0].functions[70].name == "GetCurrentProcessId" and
        pe.import_details[0].functions[70].rva == 298360 and
        pe.import_details[0].functions[71].name == "FormatMessageW" and
        pe.import_details[0].functions[71].rva == 298368 and
        pe.import_details[0].functions[72].name == "GetVersionExW" and
        pe.import_details[0].functions[72].rva == 298376 and
        pe.import_details[0].functions[73].name == "DeleteCriticalSection" and
        pe.import_details[0].functions[73].rva == 298384 and
        pe.import_details[0].functions[74].name == "MoveFileExW" and
        pe.import_details[0].functions[74].rva == 298392 and
        pe.import_details[0].functions[75].name == "SetEndOfFile" and
        pe.import_details[0].functions[75].rva == 298400 and
        pe.import_details[0].functions[76].name == "SetFilePointer" and
        pe.import_details[0].functions[76].rva == 298408 and
        pe.import_details[0].functions[77].name == "UnlockFile" and
        pe.import_details[0].functions[77].rva == 298416 and
        pe.import_details[0].functions[78].name == "LockFile" and
        pe.import_details[0].functions[78].rva == 298424 and
        pe.import_details[0].functions[79].name == "GetOverlappedResult" and
        pe.import_details[0].functions[79].rva == 298432 and
        pe.import_details[0].functions[80].name == "SetCurrentDirectoryW" and
        pe.import_details[0].functions[80].rva == 298440 and
        pe.import_details[0].functions[81].name == "HeapSetInformation" and
        pe.import_details[0].functions[81].rva == 298448 and
        pe.import_details[0].functions[82].name == "CreateDirectoryW" and
        pe.import_details[0].functions[82].rva == 298456 and
        pe.import_details[0].functions[83].name == "WaitForSingleObject" and
        pe.import_details[0].functions[83].rva == 298464 and
        pe.import_details[0].functions[84].name == "CreateEventW" and
        pe.import_details[0].functions[84].rva == 298472 and
        pe.import_details[0].functions[85].name == "LockResource" and
        pe.import_details[0].functions[85].rva == 298480 and
        pe.import_details[0].functions[86].name == "LoadResource" and
        pe.import_details[0].functions[86].rva == 298488 and
        pe.import_details[0].functions[87].name == "FindResourceW" and
        pe.import_details[0].functions[87].rva == 298496 and
        pe.import_details[0].functions[88].name == "InitializeCriticalSection" and
        pe.import_details[0].functions[88].rva == 298504 and
        pe.import_details[0].functions[89].name == "SetEvent" and
        pe.import_details[0].functions[89].rva == 298512 and
        pe.import_details[0].functions[90].name == "WaitForMultipleObjects" and
        pe.import_details[0].functions[90].rva == 298520 and
        pe.import_details[0].functions[91].name == "LeaveCriticalSection" and
        pe.import_details[0].functions[91].rva == 298528 and
        pe.import_details[0].functions[92].name == "EnterCriticalSection" and
        pe.import_details[0].functions[92].rva == 298536 and
        pe.import_details[0].functions[93].name == "CreateThread" and
        pe.import_details[0].functions[93].rva == 298544 and
        pe.import_details[0].functions[94].name == "GetProcAddress" and
        pe.import_details[0].functions[94].rva == 298552 and
        pe.import_details[0].functions[95].name == "GetModuleHandleW" and
        pe.import_details[0].functions[95].rva == 298560 and
        pe.import_details[0].functions[96].name == "VirtualFree" and
        pe.import_details[0].functions[96].rva == 298568 and
        pe.import_details[0].functions[97].name == "CloseHandle" and
        pe.import_details[0].functions[97].rva == 298576 and
        pe.import_details[0].functions[98].name == "SetFileTime" and
        pe.import_details[0].functions[98].rva == 298584 and
        pe.import_details[0].functions[99].name == "VirtualAlloc" and
        pe.import_details[0].functions[99].rva == 298592 and
        pe.import_details[0].functions[100].name == "GetFileTime" and
        pe.import_details[0].functions[100].rva == 298600 and
        pe.import_details[0].functions[101].name == "GetModuleFileNameW" and
        pe.import_details[0].functions[101].rva == 298608 and
        pe.import_details[0].functions[102].name == "GetLocaleInfoW" and
        pe.import_details[0].functions[102].rva == 298616 and
        pe.import_details[0].functions[103].name == "GetTickCount" and
        pe.import_details[0].functions[103].rva == 298624 and
        pe.import_details[0].functions[104].name == "ReadFile" and
        pe.import_details[0].functions[104].rva == 298632 and
        pe.import_details[0].functions[105].name == "DeviceIoControl" and
        pe.import_details[0].functions[105].rva == 298640 and
        pe.import_details[0].functions[106].name == "GetFileSize" and
        pe.import_details[0].functions[106].rva == 298648 and
        pe.import_details[0].functions[107].name == "SetLastError" and
        pe.import_details[0].functions[107].rva == 298656 and
        pe.import_details[0].functions[108].name == "GetLastError" and
        pe.import_details[0].functions[108].rva == 298664 and
        pe.import_details[0].functions[109].name == "CreateFileW" and
        pe.import_details[0].functions[109].rva == 298672 and
        pe.import_details[0].functions[110].name == "HeapFree" and
        pe.import_details[0].functions[110].rva == 298680 and
        pe.import_details[0].functions[111].name == "WriteFile" and
        pe.import_details[0].functions[111].rva == 298688 and
        pe.import_details[0].functions[112].name == "WideCharToMultiByte" and
        pe.import_details[0].functions[112].rva == 298696 and
        pe.import_details[0].functions[113].name == "HeapAlloc" and
        pe.import_details[0].functions[113].rva == 298704 and
        pe.import_details[0].functions[114].name == "LocalFileTimeToFileTime" and
        pe.import_details[0].functions[114].rva == 298712 and
        pe.import_details[0].functions[115].name == "SystemTimeToFileTime" and
        pe.import_details[0].functions[115].rva == 298720 and
        pe.import_details[0].functions[116].name == "EnumTimeFormatsW" and
        pe.import_details[0].functions[116].rva == 298728 and
        pe.import_details[0].functions[117].name == "EnumDateFormatsW" and
        pe.import_details[0].functions[117].rva == 298736 and
        pe.import_details[0].functions[118].name == "GetSystemTimeAsFileTime" and
        pe.import_details[0].functions[118].rva == 298744 and
        pe.import_details[0].functions[119].name == "GetTimeFormatW" and
        pe.import_details[0].functions[119].rva == 298752 and
        pe.import_details[0].functions[120].name == "FileTimeToSystemTime" and
        pe.import_details[0].functions[120].rva == 298760 and
        pe.import_details[0].functions[121].name == "FileTimeToLocalFileTime" and
        pe.import_details[0].functions[121].rva == 298768 and
        pe.import_details[0].functions[122].name == "GetDateFormatW" and
        pe.import_details[0].functions[122].rva == 298776    )
 and
    pe.import_details[0].library_name == "KERNEL32.dll" and
    pe.import_details[0].number_of_functions == 123 and
    (
        pe.import_details[1].functions[0].name == "IsCharAlphaW" and
        pe.import_details[1].functions[0].rva == 298832 and
        pe.import_details[1].functions[1].name == "GetWindowLongW" and
        pe.import_details[1].functions[1].rva == 298840 and
        pe.import_details[1].functions[2].name == "SetWindowLongW" and
        pe.import_details[1].functions[2].rva == 298848 and
        pe.import_details[1].functions[3].name == "SendMessageW" and
        pe.import_details[1].functions[3].rva == 298856 and
        pe.import_details[1].functions[4].name == "SetWindowTextW" and
        pe.import_details[1].functions[4].rva == 298864 and
        pe.import_details[1].functions[5].name == "PostMessageW" and
        pe.import_details[1].functions[5].rva == 298872 and
        pe.import_details[1].functions[6].name == "GetDlgItem" and
        pe.import_details[1].functions[6].rva == 298880 and
        pe.import_details[1].functions[7].name == "SetWindowLongPtrW" and
        pe.import_details[1].functions[7].rva == 298888 and
        pe.import_details[1].functions[8].name == "GetWindowLongPtrW" and
        pe.import_details[1].functions[8].rva == 298896 and
        pe.import_details[1].functions[9].name == "EndDialog" and
        pe.import_details[1].functions[9].rva == 298904 and
        pe.import_details[1].functions[10].name == "DialogBoxParamW" and
        pe.import_details[1].functions[10].rva == 298912 and
        pe.import_details[1].functions[11].name == "CharUpperW" and
        pe.import_details[1].functions[11].rva == 298920 and
        pe.import_details[1].functions[12].name == "IsDlgButtonChecked" and
        pe.import_details[1].functions[12].rva == 298928 and
        pe.import_details[1].functions[13].name == "EnableWindow" and
        pe.import_details[1].functions[13].rva == 298936 and
        pe.import_details[1].functions[14].name == "SetDlgItemTextW" and
        pe.import_details[1].functions[14].rva == 298944 and
        pe.import_details[1].functions[15].name == "GetWindowTextLengthW" and
        pe.import_details[1].functions[15].rva == 298952 and
        pe.import_details[1].functions[16].name == "GetWindowTextW" and
        pe.import_details[1].functions[16].rva == 298960 and
        pe.import_details[1].functions[17].name == "CheckDlgButton" and
        pe.import_details[1].functions[17].rva == 298968 and
        pe.import_details[1].functions[18].name == "SetWindowTextA" and
        pe.import_details[1].functions[18].rva == 298976 and
        pe.import_details[1].functions[19].name == "CreateCursor" and
        pe.import_details[1].functions[19].rva == 298984 and
        pe.import_details[1].functions[20].name == "SetCursor" and
        pe.import_details[1].functions[20].rva == 298992 and
        pe.import_details[1].functions[21].name == "CallWindowProcW" and
        pe.import_details[1].functions[21].rva == 299000 and
        pe.import_details[1].functions[22].name == "CreateDialogIndirectParamW" and
        pe.import_details[1].functions[22].rva == 299008 and
        pe.import_details[1].functions[23].name == "SendDlgItemMessageA" and
        pe.import_details[1].functions[23].rva == 299016 and
        pe.import_details[1].functions[24].name == "DialogBoxIndirectParamW" and
        pe.import_details[1].functions[24].rva == 299024 and
        pe.import_details[1].functions[25].name == "FillRect" and
        pe.import_details[1].functions[25].rva == 299032 and
        pe.import_details[1].functions[26].name == "DeleteMenu" and
        pe.import_details[1].functions[26].rva == 299040 and
        pe.import_details[1].functions[27].name == "MessageBeep" and
        pe.import_details[1].functions[27].rva == 299048 and
        pe.import_details[1].functions[28].name == "DrawTextExW" and
        pe.import_details[1].functions[28].rva == 299056 and
        pe.import_details[1].functions[29].name == "BeginDeferWindowPos" and
        pe.import_details[1].functions[29].rva == 299064 and
        pe.import_details[1].functions[30].name == "DeferWindowPos" and
        pe.import_details[1].functions[30].rva == 299072 and
        pe.import_details[1].functions[31].name == "EndDeferWindowPos" and
        pe.import_details[1].functions[31].rva == 299080 and
        pe.import_details[1].functions[32].name == "LoadIconW" and
        pe.import_details[1].functions[32].rva == 299088 and
        pe.import_details[1].functions[33].name == "SetFocus" and
        pe.import_details[1].functions[33].rva == 299096 and
        pe.import_details[1].functions[34].name == "GetWindowTextA" and
        pe.import_details[1].functions[34].rva == 299104 and
        pe.import_details[1].functions[35].name == "InvalidateRect" and
        pe.import_details[1].functions[35].rva == 299112 and
        pe.import_details[1].functions[36].name == "SetWindowPos" and
        pe.import_details[1].functions[36].rva == 299120 and
        pe.import_details[1].functions[37].name == "GetWindowRect" and
        pe.import_details[1].functions[37].rva == 299128 and
        pe.import_details[1].functions[38].name == "SystemParametersInfoW" and
        pe.import_details[1].functions[38].rva == 299136 and
        pe.import_details[1].functions[39].name == "SetTimer" and
        pe.import_details[1].functions[39].rva == 299144 and
        pe.import_details[1].functions[40].name == "KillTimer" and
        pe.import_details[1].functions[40].rva == 299152 and
        pe.import_details[1].functions[41].name == "MapDialogRect" and
        pe.import_details[1].functions[41].rva == 299160 and
        pe.import_details[1].functions[42].name == "GetSystemMetrics" and
        pe.import_details[1].functions[42].rva == 299168 and
        pe.import_details[1].functions[43].name == "GetSystemMenu" and
        pe.import_details[1].functions[43].rva == 299176 and
        pe.import_details[1].functions[44].name == "GetMenuItemCount" and
        pe.import_details[1].functions[44].rva == 299184 and
        pe.import_details[1].functions[45].name == "GetMenuItemInfoW" and
        pe.import_details[1].functions[45].rva == 299192 and
        pe.import_details[1].functions[46].name == "LoadStringW" and
        pe.import_details[1].functions[46].rva == 299200 and
        pe.import_details[1].functions[47].name == "TrackPopupMenu" and
        pe.import_details[1].functions[47].rva == 299208 and
        pe.import_details[1].functions[48].name == "SetForegroundWindow" and
        pe.import_details[1].functions[48].rva == 299216 and
        pe.import_details[1].functions[49].name == "LoadMenuW" and
        pe.import_details[1].functions[49].rva == 299224 and
        pe.import_details[1].functions[50].name == "LoadImageW" and
        pe.import_details[1].functions[50].rva == 299232 and
        pe.import_details[1].functions[51].name == "RegisterClassExW" and
        pe.import_details[1].functions[51].rva == 299240 and
        pe.import_details[1].functions[52].name == "LoadCursorW" and
        pe.import_details[1].functions[52].rva == 299248 and
        pe.import_details[1].functions[53].name == "GetClassInfoExW" and
        pe.import_details[1].functions[53].rva == 299256 and
        pe.import_details[1].functions[54].name == "DefWindowProcW" and
        pe.import_details[1].functions[54].rva == 299264 and
        pe.import_details[1].functions[55].name == "EndPaint" and
        pe.import_details[1].functions[55].rva == 299272 and
        pe.import_details[1].functions[56].name == "TabbedTextOutW" and
        pe.import_details[1].functions[56].rva == 299280 and
        pe.import_details[1].functions[57].name == "IntersectRect" and
        pe.import_details[1].functions[57].rva == 299288 and
        pe.import_details[1].functions[58].name == "BeginPaint" and
        pe.import_details[1].functions[58].rva == 299296 and
        pe.import_details[1].functions[59].name == "GetScrollInfo" and
        pe.import_details[1].functions[59].rva == 299304 and
        pe.import_details[1].functions[60].name == "SetCapture" and
        pe.import_details[1].functions[60].rva == 299312 and
        pe.import_details[1].functions[61].name == "DestroyCaret" and
        pe.import_details[1].functions[61].rva == 299320 and
        pe.import_details[1].functions[62].name == "HideCaret" and
        pe.import_details[1].functions[62].rva == 299328 and
        pe.import_details[1].functions[63].name == "ReleaseCapture" and
        pe.import_details[1].functions[63].rva == 299336 and
        pe.import_details[1].functions[64].name == "ShowCaret" and
        pe.import_details[1].functions[64].rva == 299344 and
        pe.import_details[1].functions[65].name == "CreateCaret" and
        pe.import_details[1].functions[65].rva == 299352 and
        pe.import_details[1].functions[66].name == "SetCaretPos" and
        pe.import_details[1].functions[66].rva == 299360 and
        pe.import_details[1].functions[67].name == "GetTabbedTextExtentW" and
        pe.import_details[1].functions[67].rva == 299368 and
        pe.import_details[1].functions[68].name == "SetScrollInfo" and
        pe.import_details[1].functions[68].rva == 299376 and
        pe.import_details[1].functions[69].name == "ReleaseDC" and
        pe.import_details[1].functions[69].rva == 299384 and
        pe.import_details[1].functions[70].name == "GetDC" and
        pe.import_details[1].functions[70].rva == 299392 and
        pe.import_details[1].functions[71].name == "GetClipboardData" and
        pe.import_details[1].functions[71].rva == 299400 and
        pe.import_details[1].functions[72].name == "IsClipboardFormatAvailable" and
        pe.import_details[1].functions[72].rva == 299408 and
        pe.import_details[1].functions[73].name == "GetDlgItemInt" and
        pe.import_details[1].functions[73].rva == 299416 and
        pe.import_details[1].functions[74].name == "ScreenToClient" and
        pe.import_details[1].functions[74].rva == 299424 and
        pe.import_details[1].functions[75].name == "EnableMenuItem" and
        pe.import_details[1].functions[75].rva == 299432 and
        pe.import_details[1].functions[76].name == "GetSubMenu" and
        pe.import_details[1].functions[76].rva == 299440 and
        pe.import_details[1].functions[77].name == "GetFocus" and
        pe.import_details[1].functions[77].rva == 299448 and
        pe.import_details[1].functions[78].name == "ClientToScreen" and
        pe.import_details[1].functions[78].rva == 299456 and
        pe.import_details[1].functions[79].name == "CloseClipboard" and
        pe.import_details[1].functions[79].rva == 299464 and
        pe.import_details[1].functions[80].name == "SetClipboardData" and
        pe.import_details[1].functions[80].rva == 299472 and
        pe.import_details[1].functions[81].name == "EmptyClipboard" and
        pe.import_details[1].functions[81].rva == 299480 and
        pe.import_details[1].functions[82].name == "OpenClipboard" and
        pe.import_details[1].functions[82].rva == 299488 and
        pe.import_details[1].functions[83].name == "IsWindowVisible" and
        pe.import_details[1].functions[83].rva == 299496 and
        pe.import_details[1].functions[84].name == "GetDlgItemTextW" and
        pe.import_details[1].functions[84].rva == 299504 and
        pe.import_details[1].functions[85].name == "GetClassNameW" and
        pe.import_details[1].functions[85].rva == 299512 and
        pe.import_details[1].functions[86].name == "GetTopWindow" and
        pe.import_details[1].functions[86].rva == 299520 and
        pe.import_details[1].functions[87].name == "IsWindowEnabled" and
        pe.import_details[1].functions[87].rva == 299528 and
        pe.import_details[1].functions[88].name == "GetWindow" and
        pe.import_details[1].functions[88].rva == 299536 and
        pe.import_details[1].functions[89].name == "GetClientRect" and
        pe.import_details[1].functions[89].rva == 299544 and
        pe.import_details[1].functions[90].name == "CreateWindowExW" and
        pe.import_details[1].functions[90].rva == 299552 and
        pe.import_details[1].functions[91].name == "LoadStringA" and
        pe.import_details[1].functions[91].rva == 299560 and
        pe.import_details[1].functions[92].name == "DestroyAcceleratorTable" and
        pe.import_details[1].functions[92].rva == 299568 and
        pe.import_details[1].functions[93].name == "DispatchMessageW" and
        pe.import_details[1].functions[93].rva == 299576 and
        pe.import_details[1].functions[94].name == "TranslateMessage" and
        pe.import_details[1].functions[94].rva == 299584 and
        pe.import_details[1].functions[95].name == "TranslateAcceleratorW" and
        pe.import_details[1].functions[95].rva == 299592 and
        pe.import_details[1].functions[96].name == "GetMessageW" and
        pe.import_details[1].functions[96].rva == 299600 and
        pe.import_details[1].functions[97].name == "IsWindow" and
        pe.import_details[1].functions[97].rva == 299608 and
        pe.import_details[1].functions[98].name == "ShowWindow" and
        pe.import_details[1].functions[98].rva == 299616 and
        pe.import_details[1].functions[99].name == "CreateDialogParamW" and
        pe.import_details[1].functions[99].rva == 299624 and
        pe.import_details[1].functions[100].name == "LoadAcceleratorsW" and
        pe.import_details[1].functions[100].rva == 299632 and
        pe.import_details[1].functions[101].name == "GetParent" and
        pe.import_details[1].functions[101].rva == 299640 and
        pe.import_details[1].functions[102].name == "IsDialogMessageW" and
        pe.import_details[1].functions[102].rva == 299648 and
        pe.import_details[1].functions[103].name == "GetAsyncKeyState" and
        pe.import_details[1].functions[103].rva == 299656 and
        pe.import_details[1].functions[104].name == "DestroyWindow" and
        pe.import_details[1].functions[104].rva == 299664 and
        pe.import_details[1].functions[105].name == "PtInRect" and
        pe.import_details[1].functions[105].rva == 299672 and
        pe.import_details[1].functions[106].name == "GetActiveWindow" and
        pe.import_details[1].functions[106].rva == 299680 and
        pe.import_details[1].functions[107].name == "GetCursorPos" and
        pe.import_details[1].functions[107].rva == 299688 and
        pe.import_details[1].functions[108].name == "InsertMenuW" and
        pe.import_details[1].functions[108].rva == 299696    )
 and
    pe.import_details[1].library_name == "USER32.dll" and
    pe.import_details[1].number_of_functions == 109 and
    (
        pe.import_details[2].functions[0].name == "SetTextAlign" and
        pe.import_details[2].functions[0].rva == 297704 and
        pe.import_details[2].functions[1].name == "GetTextMetricsW" and
        pe.import_details[2].functions[1].rva == 297712 and
        pe.import_details[2].functions[2].name == "SelectObject" and
        pe.import_details[2].functions[2].rva == 297720 and
        pe.import_details[2].functions[3].name == "GetStockObject" and
        pe.import_details[2].functions[3].rva == 297728 and
        pe.import_details[2].functions[4].name == "CreateFontIndirectW" and
        pe.import_details[2].functions[4].rva == 297736 and
        pe.import_details[2].functions[5].name == "SetTextColor" and
        pe.import_details[2].functions[5].rva == 297744 and
        pe.import_details[2].functions[6].name == "SetBkColor" and
        pe.import_details[2].functions[6].rva == 297752 and
        pe.import_details[2].functions[7].name == "GetTextExtentPoint32W" and
        pe.import_details[2].functions[7].rva == 297760 and
        pe.import_details[2].functions[8].name == "GetObjectW" and
        pe.import_details[2].functions[8].rva == 297768 and
        pe.import_details[2].functions[9].name == "TextOutW" and
        pe.import_details[2].functions[9].rva == 297776 and
        pe.import_details[2].functions[10].name == "ExtTextOutW" and
        pe.import_details[2].functions[10].rva == 297784    )
 and
    pe.import_details[2].library_name == "GDI32.dll" and
    pe.import_details[2].number_of_functions == 11 and
    (
        pe.import_details[3].functions[0].name == "LookupAccountSidW" and
        pe.import_details[3].functions[0].rva == 297344 and
        pe.import_details[3].functions[1].name == "GetUserNameW" and
        pe.import_details[3].functions[1].rva == 297352 and
        pe.import_details[3].functions[2].name == "SetSecurityDescriptorSacl" and
        pe.import_details[3].functions[2].rva == 297360 and
        pe.import_details[3].functions[3].name == "SetSecurityDescriptorDacl" and
        pe.import_details[3].functions[3].rva == 297368 and
        pe.import_details[3].functions[4].name == "SetSecurityDescriptorGroup" and
        pe.import_details[3].functions[4].rva == 297376 and
        pe.import_details[3].functions[5].name == "SetSecurityDescriptorOwner" and
        pe.import_details[3].functions[5].rva == 297384 and
        pe.import_details[3].functions[6].name == "InitializeSecurityDescriptor" and
        pe.import_details[3].functions[6].rva == 297392 and
        pe.import_details[3].functions[7].name == "GetSecurityDescriptorSacl" and
        pe.import_details[3].functions[7].rva == 297400 and
        pe.import_details[3].functions[8].name == "GetSecurityDescriptorDacl" and
        pe.import_details[3].functions[8].rva == 297408 and
        pe.import_details[3].functions[9].name == "GetSecurityDescriptorGroup" and
        pe.import_details[3].functions[9].rva == 297416 and
        pe.import_details[3].functions[10].name == "GetSecurityDescriptorOwner" and
        pe.import_details[3].functions[10].rva == 297424 and
        pe.import_details[3].functions[11].name == "GetAce" and
        pe.import_details[3].functions[11].rva == 297432 and
        pe.import_details[3].functions[12].name == "AddAuditAccessAce" and
        pe.import_details[3].functions[12].rva == 297440 and
        pe.import_details[3].functions[13].name == "AddAccessDeniedAce" and
        pe.import_details[3].functions[13].rva == 297448 and
        pe.import_details[3].functions[14].name == "AddAccessAllowedAce" and
        pe.import_details[3].functions[14].rva == 297456 and
        pe.import_details[3].functions[15].name == "InitializeAcl" and
        pe.import_details[3].functions[15].rva == 297464 and
        pe.import_details[3].functions[16].name == "LookupAccountNameW" and
        pe.import_details[3].functions[16].rva == 297472 and
        pe.import_details[3].functions[17].name == "CopySid" and
        pe.import_details[3].functions[17].rva == 297480 and
        pe.import_details[3].functions[18].name == "GetLengthSid" and
        pe.import_details[3].functions[18].rva == 297488 and
        pe.import_details[3].functions[19].name == "RegSetValueExW" and
        pe.import_details[3].functions[19].rva == 297496 and
        pe.import_details[3].functions[20].name == "FreeSid" and
        pe.import_details[3].functions[20].rva == 297504 and
        pe.import_details[3].functions[21].name == "SetTokenInformation" and
        pe.import_details[3].functions[21].rva == 297512 and
        pe.import_details[3].functions[22].name == "AllocateAndInitializeSid" and
        pe.import_details[3].functions[22].rva == 297520 and
        pe.import_details[3].functions[23].name == "AdjustTokenPrivileges" and
        pe.import_details[3].functions[23].rva == 297528 and
        pe.import_details[3].functions[24].name == "LookupPrivilegeValueW" and
        pe.import_details[3].functions[24].rva == 297536 and
        pe.import_details[3].functions[25].name == "LookupPrivilegeNameW" and
        pe.import_details[3].functions[25].rva == 297544 and
        pe.import_details[3].functions[26].name == "RegCloseKey" and
        pe.import_details[3].functions[26].rva == 297552 and
        pe.import_details[3].functions[27].name == "RegQueryValueExW" and
        pe.import_details[3].functions[27].rva == 297560 and
        pe.import_details[3].functions[28].name == "RegOpenKeyExW" and
        pe.import_details[3].functions[28].rva == 297568 and
        pe.import_details[3].functions[29].name == "GetSidSubAuthority" and
        pe.import_details[3].functions[29].rva == 297576 and
        pe.import_details[3].functions[30].name == "GetSidIdentifierAuthority" and
        pe.import_details[3].functions[30].rva == 297584 and
        pe.import_details[3].functions[31].name == "GetSidSubAuthorityCount" and
        pe.import_details[3].functions[31].rva == 297592 and
        pe.import_details[3].functions[32].name == "GetTokenInformation" and
        pe.import_details[3].functions[32].rva == 297600 and
        pe.import_details[3].functions[33].name == "OpenProcessToken" and
        pe.import_details[3].functions[33].rva == 297608 and
        pe.import_details[3].functions[34].name == "OpenThreadToken" and
        pe.import_details[3].functions[34].rva == 297616    )
 and
    pe.import_details[3].library_name == "ADVAPI32.dll" and
    pe.import_details[3].number_of_functions == 35 and
    (
        pe.import_details[4].functions[0].name == "NtCreateFile" and
        pe.import_details[4].functions[0].rva == 299744 and
        pe.import_details[4].functions[1].name == "NtClose" and
        pe.import_details[4].functions[1].rva == 299752 and
        pe.import_details[4].functions[2].name == "RtlInitUnicodeString" and
        pe.import_details[4].functions[2].rva == 299760 and
        pe.import_details[4].functions[3].name == "NtOpenFile" and
        pe.import_details[4].functions[3].rva == 299768 and
        pe.import_details[4].functions[4].name == "RtlNtStatusToDosError" and
        pe.import_details[4].functions[4].rva == 299776 and
        pe.import_details[4].functions[5].name == "RtlFreeUnicodeString" and
        pe.import_details[4].functions[5].rva == 299784 and
        pe.import_details[4].functions[6].name == "RtlCreateUnicodeString" and
        pe.import_details[4].functions[6].rva == 299792 and
        pe.import_details[4].functions[7].name == "NtOpenDirectoryObject" and
        pe.import_details[4].functions[7].rva == 299800 and
        pe.import_details[4].functions[8].name == "RtlDecompressBuffer" and
        pe.import_details[4].functions[8].rva == 299808 and
        pe.import_details[4].functions[9].name == "NtDeviceIoControlFile" and
        pe.import_details[4].functions[9].rva == 299816 and
        pe.import_details[4].functions[10].name == "RtlReAllocateHeap" and
        pe.import_details[4].functions[10].rva == 299824 and
        pe.import_details[4].functions[11].name == "NtQuerySymbolicLinkObject" and
        pe.import_details[4].functions[11].rva == 299832 and
        pe.import_details[4].functions[12].name == "NtOpenSymbolicLinkObject" and
        pe.import_details[4].functions[12].rva == 299840 and
        pe.import_details[4].functions[13].name == "NtCreateSymbolicLinkObject" and
        pe.import_details[4].functions[13].rva == 299848 and
        pe.import_details[4].functions[14].name == "NtQuerySecurityObject" and
        pe.import_details[4].functions[14].rva == 299856 and
        pe.import_details[4].functions[15].name == "NtSetEaFile" and
        pe.import_details[4].functions[15].rva == 299864 and
        pe.import_details[4].functions[16].name == "NtQueryEaFile" and
        pe.import_details[4].functions[16].rva == 299872 and
        pe.import_details[4].functions[17].name == "NtSetVolumeInformationFile" and
        pe.import_details[4].functions[17].rva == 299880 and
        pe.import_details[4].functions[18].name == "NtQueryVolumeInformationFile" and
        pe.import_details[4].functions[18].rva == 299888 and
        pe.import_details[4].functions[19].name == "RtlCompareUnicodeString" and
        pe.import_details[4].functions[19].rva == 299896 and
        pe.import_details[4].functions[20].name == "NtQueryInformationProcess" and
        pe.import_details[4].functions[20].rva == 299904 and
        pe.import_details[4].functions[21].name == "NtQuerySystemInformation" and
        pe.import_details[4].functions[21].rva == 299912 and
        pe.import_details[4].functions[22].name == "NtFsControlFile" and
        pe.import_details[4].functions[22].rva == 299920 and
        pe.import_details[4].functions[23].name == "NtQueryAttributesFile" and
        pe.import_details[4].functions[23].rva == 299928 and
        pe.import_details[4].functions[24].name == "NtQueryDirectoryFile" and
        pe.import_details[4].functions[24].rva == 299936 and
        pe.import_details[4].functions[25].name == "NtQueryInformationFile" and
        pe.import_details[4].functions[25].rva == 299944 and
        pe.import_details[4].functions[26].name == "NtDeleteFile" and
        pe.import_details[4].functions[26].rva == 299952 and
        pe.import_details[4].functions[27].name == "NtSetInformationFile" and
        pe.import_details[4].functions[27].rva == 299960 and
        pe.import_details[4].functions[28].name == "RtlFreeSid" and
        pe.import_details[4].functions[28].rva == 299968 and
        pe.import_details[4].functions[29].name == "RtlSetDaclSecurityDescriptor" and
        pe.import_details[4].functions[29].rva == 299976 and
        pe.import_details[4].functions[30].name == "RtlAddAccessAllowedAce" and
        pe.import_details[4].functions[30].rva == 299984 and
        pe.import_details[4].functions[31].name == "RtlCreateAcl" and
        pe.import_details[4].functions[31].rva == 299992 and
        pe.import_details[4].functions[32].name == "RtlLengthSid" and
        pe.import_details[4].functions[32].rva == 300000 and
        pe.import_details[4].functions[33].name == "RtlAllocateAndInitializeSid" and
        pe.import_details[4].functions[33].rva == 300008 and
        pe.import_details[4].functions[34].name == "RtlFreeHeap" and
        pe.import_details[4].functions[34].rva == 300016 and
        pe.import_details[4].functions[35].name == "NtSetSecurityObject" and
        pe.import_details[4].functions[35].rva == 300024 and
        pe.import_details[4].functions[36].name == "RtlSetOwnerSecurityDescriptor" and
        pe.import_details[4].functions[36].rva == 300032 and
        pe.import_details[4].functions[37].name == "RtlCreateSecurityDescriptor" and
        pe.import_details[4].functions[37].rva == 300040 and
        pe.import_details[4].functions[38].name == "RtlAllocateHeap" and
        pe.import_details[4].functions[38].rva == 300048 and
        pe.import_details[4].functions[39].name == "NtQueryInformationToken" and
        pe.import_details[4].functions[39].rva == 300056 and
        pe.import_details[4].functions[40].name == "NtOpenProcessToken" and
        pe.import_details[4].functions[40].rva == 300064 and
        pe.import_details[4].functions[41].name == "NtUnmapViewOfSection" and
        pe.import_details[4].functions[41].rva == 300072 and
        pe.import_details[4].functions[42].name == "NtMapViewOfSection" and
        pe.import_details[4].functions[42].rva == 300080 and
        pe.import_details[4].functions[43].name == "NtOpenSection" and
        pe.import_details[4].functions[43].rva == 300088 and
        pe.import_details[4].functions[44].name == "NtCreateSection" and
        pe.import_details[4].functions[44].rva == 300096 and
        pe.import_details[4].functions[45].name == "NtUnlockFile" and
        pe.import_details[4].functions[45].rva == 300104 and
        pe.import_details[4].functions[46].name == "NtLockFile" and
        pe.import_details[4].functions[46].rva == 300112 and
        pe.import_details[4].functions[47].name == "NtWriteFile" and
        pe.import_details[4].functions[47].rva == 300120 and
        pe.import_details[4].functions[48].name == "NtReadFile" and
        pe.import_details[4].functions[48].rva == 300128    )
 and
    pe.import_details[4].library_name == "ntdll.dll" and
    pe.import_details[4].number_of_functions == 49 and
    (
        pe.import_details[5].functions[0].name == "CreatePropertySheetPageW" and
        pe.import_details[5].functions[0].rva == 297632 and
        pe.import_details[5].functions[1].name == "ImageList_ReplaceIcon" and
        pe.import_details[5].functions[1].rva == 297640 and
        pe.import_details[5].functions[2].name == "ord17" and
        pe.import_details[5].functions[2].ordinal == 17 and
        pe.import_details[5].functions[2].rva == 297648 and
        pe.import_details[5].functions[3].name == "PropertySheetW" and
        pe.import_details[5].functions[3].rva == 297656 and
        pe.import_details[5].functions[4].name == "ImageList_Create" and
        pe.import_details[5].functions[4].rva == 297664    )
 and
    pe.import_details[5].library_name == "COMCTL32.dll" and
    pe.import_details[5].number_of_functions == 5 and
    (
        pe.import_details[6].functions[0].name == "GetFileVersionInfoSizeW" and
        pe.import_details[6].functions[0].rva == 299712 and
        pe.import_details[6].functions[1].name == "GetFileVersionInfoW" and
        pe.import_details[6].functions[1].rva == 299720 and
        pe.import_details[6].functions[2].name == "VerQueryValueW" and
        pe.import_details[6].functions[2].rva == 299728    )
 and
    pe.import_details[6].library_name == "VERSION.dll" and
    pe.import_details[6].number_of_functions == 3 and
    (
        pe.import_details[7].functions[0].name == "GetSaveFileNameW" and
        pe.import_details[7].functions[0].rva == 297680 and
        pe.import_details[7].functions[1].name == "GetOpenFileNameW" and
        pe.import_details[7].functions[1].rva == 297688    )
 and
    pe.import_details[7].library_name == "COMDLG32.dll" and
    pe.import_details[7].number_of_functions == 2 and
    (
        pe.import_details[8].functions[0].name == "SHBrowseForFolderW" and
        pe.import_details[8].functions[0].rva == 298792 and
        pe.import_details[8].functions[1].name == "SHGetPathFromIDListW" and
        pe.import_details[8].functions[1].rva == 298800 and
        pe.import_details[8].functions[2].name == "SHGetMalloc" and
        pe.import_details[8].functions[2].rva == 298808 and
        pe.import_details[8].functions[3].name == "ShellExecuteW" and
        pe.import_details[8].functions[3].rva == 298816    )
 and
    pe.import_details[8].library_name == "SHELL32.dll" and
    pe.import_details[8].number_of_functions == 4)
 and
pe.is_pe == 1 and
pe.linker_version.major == 9 and
pe.linker_version.minor == 0 and
pe.loader_flags == 0 and
pe.machine == 34404 and
pe.number_of_delayed_imported_functions == 0 and
pe.number_of_delayed_imports == 0 and
pe.number_of_exports == 0 and
pe.number_of_imported_functions == 341 and
pe.number_of_imports == 9 and
pe.number_of_resources == 72 and
pe.number_of_rva_and_sizes == 16 and
pe.number_of_sections == 6 and
pe.number_of_symbols == 0 and
pe.number_of_version_infos == 9 and
pe.opthdr_magic == 523 and
pe.os_version.major == 5 and
pe.os_version.minor == 2 and
pe.overlay.offset == 0 and
pe.overlay.size == 0 and
pe.pdb_path == "FileTest.pdb" and
pe.pointer_to_symbol_table == 0 and
pe.resource_timestamp == 0 and
pe.resource_version.major == 0 and
pe.resource_version.minor == 0 and
(
    pe.resources[0].id == 106 and
    pe.resources[0].language == 1033 and
    pe.resources[0].length == 2 and
    pe.resources[0].offset == 703888 and
    pe.resources[0].rva == 703888 and
    pe.resources[0].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[1].id == 107 and
    pe.resources[1].language == 1033 and
    pe.resources[1].length == 2 and
    pe.resources[1].offset == 703880 and
    pe.resources[1].rva == 703880 and
    pe.resources[1].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[2].id == 111 and
    pe.resources[2].language == 1033 and
    pe.resources[2].length == 2 and
    pe.resources[2].offset == 703904 and
    pe.resources[2].rva == 703904 and
    pe.resources[2].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[3].id == 112 and
    pe.resources[3].language == 1033 and
    pe.resources[3].length == 2 and
    pe.resources[3].offset == 703896 and
    pe.resources[3].rva == 703896 and
    pe.resources[3].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[4].id == 114 and
    pe.resources[4].language == 1033 and
    pe.resources[4].length == 2 and
    pe.resources[4].offset == 703872 and
    pe.resources[4].rva == 703872 and
    pe.resources[4].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[5].id == 1 and
    pe.resources[5].language == 0 and
    pe.resources[5].length == 1640 and
    pe.resources[5].offset == 656304 and
    pe.resources[5].rva == 656304 and
    pe.resources[5].type == 3 and
    pe.resources[6].id == 2 and
    pe.resources[6].language == 0 and
    pe.resources[6].length == 296 and
    pe.resources[6].offset == 657944 and
    pe.resources[6].rva == 657944 and
    pe.resources[6].type == 3 and
    pe.resources[7].id == 3 and
    pe.resources[7].language == 0 and
    pe.resources[7].length == 744 and
    pe.resources[7].offset == 658240 and
    pe.resources[7].rva == 658240 and
    pe.resources[7].type == 3 and
    pe.resources[8].id == 4 and
    pe.resources[8].language == 0 and
    pe.resources[8].length == 1384 and
    pe.resources[8].offset == 658984 and
    pe.resources[8].rva == 658984 and
    pe.resources[8].type == 3 and
    pe.resources[9].id == 5 and
    pe.resources[9].language == 0 and
    pe.resources[9].length == 2216 and
    pe.resources[9].offset == 660368 and
    pe.resources[9].rva == 660368 and
    pe.resources[9].type == 3 and
    pe.resources[10].id == 6 and
    pe.resources[10].language == 0 and
    pe.resources[10].length == 3752 and
    pe.resources[10].offset == 662584 and
    pe.resources[10].rva == 662584 and
    pe.resources[10].type == 3 and
    pe.resources[11].id == 7 and
    pe.resources[11].language == 0 and
    pe.resources[11].length == 296 and
    pe.resources[11].offset == 666432 and
    pe.resources[11].rva == 666432 and
    pe.resources[11].type == 3 and
    pe.resources[12].id == 8 and
    pe.resources[12].language == 0 and
    pe.resources[12].length == 1384 and
    pe.resources[12].offset == 666728 and
    pe.resources[12].rva == 666728 and
    pe.resources[12].type == 3 and
    pe.resources[13].id == 9 and
    pe.resources[13].language == 0 and
    pe.resources[13].length == 296 and
    pe.resources[13].offset == 668152 and
    pe.resources[13].rva == 668152 and
    pe.resources[13].type == 3 and
    pe.resources[14].id == 10 and
    pe.resources[14].language == 0 and
    pe.resources[14].length == 1384 and
    pe.resources[14].offset == 668448 and
    pe.resources[14].rva == 668448 and
    pe.resources[14].type == 3 and
    pe.resources[15].id == 11 and
    pe.resources[15].language == 0 and
    pe.resources[15].length == 296 and
    pe.resources[15].offset == 669872 and
    pe.resources[15].rva == 669872 and
    pe.resources[15].type == 3 and
    pe.resources[16].id == 12 and
    pe.resources[16].language == 0 and
    pe.resources[16].length == 1384 and
    pe.resources[16].offset == 670168 and
    pe.resources[16].rva == 670168 and
    pe.resources[16].type == 3 and
    pe.resources[17].id == 13 and
    pe.resources[17].language == 0 and
    pe.resources[17].length == 296 and
    pe.resources[17].offset == 671592 and
    pe.resources[17].rva == 671592 and
    pe.resources[17].type == 3 and
    pe.resources[18].id == 14 and
    pe.resources[18].language == 0 and
    pe.resources[18].length == 1384 and
    pe.resources[18].offset == 671888 and
    pe.resources[18].rva == 671888 and
    pe.resources[18].type == 3 and
    pe.resources[19].id == 15 and
    pe.resources[19].language == 0 and
    pe.resources[19].length == 1128 and
    pe.resources[19].offset == 673312 and
    pe.resources[19].rva == 673312 and
    pe.resources[19].type == 3 and
    pe.resources[20].id == 123 and
    pe.resources[20].language == 1033 and
    pe.resources[20].length == 248 and
    pe.resources[20].offset == 675352 and
    pe.resources[20].rva == 675352 and
    pe.resources[20].type == 4 and
    pe.resources[21].id == 129 and
    pe.resources[21].language == 1033 and
    pe.resources[21].length == 164 and
    pe.resources[21].offset == 675600 and
    pe.resources[21].rva == 675600 and
    pe.resources[21].type == 4 and
    pe.resources[22].id == 139 and
    pe.resources[22].language == 1033 and
    pe.resources[22].length == 648 and
    pe.resources[22].offset == 675768 and
    pe.resources[22].rva == 675768 and
    pe.resources[22].type == 4 and
    pe.resources[23].id == 141 and
    pe.resources[23].language == 1033 and
    pe.resources[23].length == 312 and
    pe.resources[23].offset == 676416 and
    pe.resources[23].rva == 676416 and
    pe.resources[23].type == 4 and
    pe.resources[24].id == 144 and
    pe.resources[24].language == 1033 and
    pe.resources[24].length == 136 and
    pe.resources[24].offset == 676728 and
    pe.resources[24].rva == 676728 and
    pe.resources[24].type == 4 and
    pe.resources[25].id == 145 and
    pe.resources[25].language == 1033 and
    pe.resources[25].length == 128 and
    pe.resources[25].offset == 677024 and
    pe.resources[25].rva == 677024 and
    pe.resources[25].type == 4 and
    pe.resources[26].id == 146 and
    pe.resources[26].language == 1033 and
    pe.resources[26].length == 156 and
    pe.resources[26].offset == 676864 and
    pe.resources[26].rva == 676864 and
    pe.resources[26].type == 4 and
    pe.resources[27].id == 102 and
    pe.resources[27].language == 1033 and
    pe.resources[27].length == 1320 and
    pe.resources[27].offset == 677336 and
    pe.resources[27].rva == 677336 and
    pe.resources[27].type == 5 and
    pe.resources[28].id == 103 and
    pe.resources[28].language == 1033 and
    pe.resources[28].length == 1940 and
    pe.resources[28].offset == 678656 and
    pe.resources[28].rva == 678656 and
    pe.resources[28].type == 5 and
    pe.resources[29].id == 104 and
    pe.resources[29].language == 1033 and
    pe.resources[29].length == 2464 and
    pe.resources[29].offset == 680600 and
    pe.resources[29].rva == 680600 and
    pe.resources[29].type == 5 and
    pe.resources[30].id == 105 and
    pe.resources[30].language == 1033 and
    pe.resources[30].length == 1450 and
    pe.resources[30].offset == 683064 and
    pe.resources[30].rva == 683064 and
    pe.resources[30].type == 5 and
    pe.resources[31].id == 106 and
    pe.resources[31].language == 1033 and
    pe.resources[31].length == 2368 and
    pe.resources[31].offset == 694576 and
    pe.resources[31].rva == 694576 and
    pe.resources[31].type == 5 and
    pe.resources[32].id == 107 and
    pe.resources[32].language == 1033 and
    pe.resources[32].length == 2172 and
    pe.resources[32].offset == 684520 and
    pe.resources[32].rva == 684520 and
    pe.resources[32].type == 5 and
    pe.resources[33].id == 108 and
    pe.resources[33].language == 1033 and
    pe.resources[33].length == 1076 and
    pe.resources[33].offset == 686696 and
    pe.resources[33].rva == 686696 and
    pe.resources[33].type == 5 and
    pe.resources[34].id == 109 and
    pe.resources[34].language == 1033 and
    pe.resources[34].length == 928 and
    pe.resources[34].offset == 687776 and
    pe.resources[34].rva == 687776 and
    pe.resources[34].type == 5 and
    pe.resources[35].id == 110 and
    pe.resources[35].language == 1033 and
    pe.resources[35].length == 764 and
    pe.resources[35].offset == 688704 and
    pe.resources[35].rva == 688704 and
    pe.resources[35].type == 5 and
    pe.resources[36].id == 111 and
    pe.resources[36].language == 1033 and
    pe.resources[36].length == 1112 and
    pe.resources[36].offset == 689472 and
    pe.resources[36].rva == 689472 and
    pe.resources[36].type == 5 and
    pe.resources[37].id == 112 and
    pe.resources[37].language == 1033 and
    pe.resources[37].length == 1544 and
    pe.resources[37].offset == 690584 and
    pe.resources[37].rva == 690584 and
    pe.resources[37].type == 5 and
    pe.resources[38].id == 113 and
    pe.resources[38].language == 1033 and
    pe.resources[38].length == 644 and
    pe.resources[38].offset == 692128 and
    pe.resources[38].rva == 692128 and
    pe.resources[38].type == 5 and
    pe.resources[39].id == 114 and
    pe.resources[39].language == 1033 and
    pe.resources[39].length == 1500 and
    pe.resources[39].offset == 698384 and
    pe.resources[39].rva == 698384 and
    pe.resources[39].type == 5 and
    pe.resources[40].id == 118 and
    pe.resources[40].language == 1033 and
    pe.resources[40].length == 240 and
    pe.resources[40].offset == 702976 and
    pe.resources[40].rva == 702976 and
    pe.resources[40].type == 5 and
    pe.resources[41].id == 119 and
    pe.resources[41].language == 1033 and
    pe.resources[41].length == 266 and
    pe.resources[41].offset == 692776 and
    pe.resources[41].rva == 692776 and
    pe.resources[41].type == 5 and
    pe.resources[42].id == 124 and
    pe.resources[42].language == 1033 and
    pe.resources[42].length == 452 and
    pe.resources[42].offset == 693048 and
    pe.resources[42].rva == 693048 and
    pe.resources[42].type == 5 and
    pe.resources[43].id == 128 and
    pe.resources[43].language == 1033 and
    pe.resources[43].length == 532 and
    pe.resources[43].offset == 693504 and
    pe.resources[43].rva == 693504 and
    pe.resources[43].type == 5 and
    pe.resources[44].id == 132 and
    pe.resources[44].language == 1033 and
    pe.resources[44].length == 180 and
    pe.resources[44].offset == 677152 and
    pe.resources[44].rva == 677152 and
    pe.resources[44].type == 5 and
    pe.resources[45].id == 133 and
    pe.resources[45].language == 1033 and
    pe.resources[45].length == 530 and
    pe.resources[45].offset == 694040 and
    pe.resources[45].rva == 694040 and
    pe.resources[45].type == 5 and
    pe.resources[46].id == 137 and
    pe.resources[46].language == 1033 and
    pe.resources[46].length == 214 and
    pe.resources[46].offset == 696944 and
    pe.resources[46].rva == 696944 and
    pe.resources[46].type == 5 and
    pe.resources[47].id == 138 and
    pe.resources[47].language == 1033 and
    pe.resources[47].length == 466 and
    pe.resources[47].offset == 697160 and
    pe.resources[47].rva == 697160 and
    pe.resources[47].type == 5 and
    pe.resources[48].id == 140 and
    pe.resources[48].language == 1033 and
    pe.resources[48].length == 312 and
    pe.resources[48].offset == 697632 and
    pe.resources[48].rva == 697632 and
    pe.resources[48].type == 5 and
    pe.resources[49].id == 143 and
    pe.resources[49].language == 1033 and
    pe.resources[49].length == 438 and
    pe.resources[49].offset == 697944 and
    pe.resources[49].rva == 697944 and
    pe.resources[49].type == 5 and
    pe.resources[50].id == 144 and
    pe.resources[50].language == 1033 and
    pe.resources[50].length == 798 and
    pe.resources[50].offset == 699888 and
    pe.resources[50].rva == 699888 and
    pe.resources[50].type == 5 and
    pe.resources[51].id == 145 and
    pe.resources[51].language == 1033 and
    pe.resources[51].length == 826 and
    pe.resources[51].offset == 700688 and
    pe.resources[51].rva == 700688 and
    pe.resources[51].type == 5 and
    pe.resources[52].id == 146 and
    pe.resources[52].language == 1033 and
    pe.resources[52].length == 806 and
    pe.resources[52].offset == 701520 and
    pe.resources[52].rva == 701520 and
    pe.resources[52].type == 5 and
    pe.resources[53].id == 147 and
    pe.resources[53].language == 1033 and
    pe.resources[53].length == 648 and
    pe.resources[53].offset == 702328 and
    pe.resources[53].rva == 702328 and
    pe.resources[53].type == 5 and
    pe.resources[54].id == 10 and
    pe.resources[54].language == 1033 and
    pe.resources[54].length == 62 and
    pe.resources[54].offset == 709384 and
    pe.resources[54].rva == 709384 and
    pe.resources[54].type == 6 and
    pe.resources[55].id == 251 and
    pe.resources[55].language == 1033 and
    pe.resources[55].length == 968 and
    pe.resources[55].offset == 703912 and
    pe.resources[55].rva == 703912 and
    pe.resources[55].type == 6 and
    pe.resources[56].id == 252 and
    pe.resources[56].language == 1033 and
    pe.resources[56].length == 702 and
    pe.resources[56].offset == 704880 and
    pe.resources[56].rva == 704880 and
    pe.resources[56].type == 6 and
    pe.resources[57].id == 253 and
    pe.resources[57].language == 1033 and
    pe.resources[57].length == 1066 and
    pe.resources[57].offset == 705584 and
    pe.resources[57].rva == 705584 and
    pe.resources[57].type == 6 and
    pe.resources[58].id == 254 and
    pe.resources[58].language == 1033 and
    pe.resources[58].length == 710 and
    pe.resources[58].offset == 706656 and
    pe.resources[58].rva == 706656 and
    pe.resources[58].type == 6 and
    pe.resources[59].id == 255 and
    pe.resources[59].language == 1033 and
    pe.resources[59].length == 1444 and
    pe.resources[59].offset == 707368 and
    pe.resources[59].rva == 707368 and
    pe.resources[59].type == 6 and
    pe.resources[60].id == 256 and
    pe.resources[60].language == 1033 and
    pe.resources[60].length == 568 and
    pe.resources[60].offset == 708816 and
    pe.resources[60].rva == 708816 and
    pe.resources[60].type == 6 and
    pe.resources[61].id == 121 and
    pe.resources[61].language == 0 and
    pe.resources[61].length == 8 and
    pe.resources[61].offset == 654512 and
    pe.resources[61].rva == 654512 and
    pe.resources[61].type == 9 and
    pe.resources[62].id == 101 and
    pe.resources[62].language == 0 and
    pe.resources[62].length == 90 and
    pe.resources[62].offset == 666336 and
    pe.resources[62].rva == 666336 and
    pe.resources[62].type == 14 and
    pe.resources[63].id == 125 and
    pe.resources[63].language == 0 and
    pe.resources[63].length == 34 and
    pe.resources[63].offset == 668112 and
    pe.resources[63].rva == 668112 and
    pe.resources[63].type == 14 and
    pe.resources[64].id == 126 and
    pe.resources[64].language == 0 and
    pe.resources[64].length == 34 and
    pe.resources[64].offset == 669832 and
    pe.resources[64].rva == 669832 and
    pe.resources[64].type == 14 and
    pe.resources[65].id == 127 and
    pe.resources[65].language == 0 and
    pe.resources[65].length == 34 and
    pe.resources[65].offset == 671552 and
    pe.resources[65].rva == 671552 and
    pe.resources[65].type == 14 and
    pe.resources[66].id == 140 and
    pe.resources[66].language == 0 and
    pe.resources[66].length == 34 and
    pe.resources[66].offset == 673272 and
    pe.resources[66].rva == 673272 and
    pe.resources[66].type == 14 and
    pe.resources[67].id == 143 and
    pe.resources[67].language == 0 and
    pe.resources[67].length == 20 and
    pe.resources[67].offset == 674440 and
    pe.resources[67].rva == 674440 and
    pe.resources[67].type == 14 and
    pe.resources[68].id == 1 and
    pe.resources[68].language == 1033 and
    pe.resources[68].length == 888 and
    pe.resources[68].offset == 674464 and
    pe.resources[68].rva == 674464 and
    pe.resources[68].type == 16 and
    pe.resources[69].id == 1 and
    pe.resources[69].language == 0 and
    pe.resources[69].length == 1779 and
    pe.resources[69].offset == 654520 and
    pe.resources[69].rva == 654520 and
    pe.resources[69].type == 24 and
    pe.resources[70].id == 103 and
    pe.resources[70].language == 1033 and
    pe.resources[70].length == 282 and
    pe.resources[70].offset == 703584 and
    pe.resources[70].rva == 703584 and
    pe.resources[70].type == 240 and
    pe.resources[71].id == 104 and
    pe.resources[71].language == 1033 and
    pe.resources[71].length == 363 and
    pe.resources[71].offset == 703216 and
    pe.resources[71].rva == 703216 and
    pe.resources[71].type == 240)
 and
pe.rich_signature.clear_data == "\x44\x61\x6e\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x78\x83\x00\x6d\x00\x00\x00\x09\x78\x95\x00\x0a\x00\x00\x00\x09\x78\x84\x00\x3e\x00\x00\x00\x27\xc6\x7b\x00\x13\x00\x00\x00\x00\x00\x01\x00\x79\x01\x00\x00\x09\x78\x8a\x00\x1d\x00\x00\x00\x1e\x52\x94\x00\x01\x00\x00\x00\x09\x78\x91\x00\x01\x00\x00\x00" and
pe.rich_signature.key == 3773202274 and
pe.rich_signature.length == 80 and
pe.rich_signature.offset == 128 and
pe.rich_signature.raw_data == "\x26\x1e\x88\xb3\x62\x7f\xe6\xe0\x62\x7f\xe6\xe0\x62\x7f\xe6\xe0\x6b\x07\x65\xe0\x0f\x7f\xe6\xe0\x6b\x07\x73\xe0\x68\x7f\xe6\xe0\x6b\x07\x62\xe0\x5c\x7f\xe6\xe0\x45\xb9\x9d\xe0\x71\x7f\xe6\xe0\x62\x7f\xe7\xe0\x1b\x7e\xe6\xe0\x6b\x07\x6c\xe0\x7f\x7f\xe6\xe0\x7c\x2d\x72\xe0\x63\x7f\xe6\xe0\x6b\x07\x77\xe0\x63\x7f\xe6\xe0" and
true
 and
true
 and
pe.section_alignment == 64 and
(
    pe.sections[0].characteristics == 1610612768 and
    pe.sections[0].full_name == ".text" and
    pe.sections[0].name == ".text" and
    pe.sections[0].number_of_line_numbers == 0 and
    pe.sections[0].number_of_relocations == 0 and
    pe.sections[0].pointer_to_line_numbers == 0 and
    pe.sections[0].pointer_to_relocations == 0 and
    pe.sections[0].raw_data_offset == 768 and
    pe.sections[0].raw_data_size == 296576 and
    pe.sections[0].virtual_address == 768 and
    pe.sections[0].virtual_size == 296514 and
    pe.sections[1].characteristics == 1073741888 and
    pe.sections[1].full_name == ".rdata" and
    pe.sections[1].name == ".rdata" and
    pe.sections[1].number_of_line_numbers == 0 and
    pe.sections[1].number_of_relocations == 0 and
    pe.sections[1].pointer_to_line_numbers == 0 and
    pe.sections[1].pointer_to_relocations == 0 and
    pe.sections[1].raw_data_offset == 297344 and
    pe.sections[1].raw_data_size == 254144 and
    pe.sections[1].virtual_address == 297344 and
    pe.sections[1].virtual_size == 254118 and
    pe.sections[2].characteristics == 3221225536 and
    pe.sections[2].full_name == ".data" and
    pe.sections[2].name == ".data" and
    pe.sections[2].number_of_line_numbers == 0 and
    pe.sections[2].number_of_relocations == 0 and
    pe.sections[2].pointer_to_line_numbers == 0 and
    pe.sections[2].pointer_to_relocations == 0 and
    pe.sections[2].raw_data_offset == 551488 and
    pe.sections[2].raw_data_size == 85248 and
    pe.sections[2].virtual_address == 551488 and
    pe.sections[2].virtual_size == 85248 and
    pe.sections[3].characteristics == 1073741888 and
    pe.sections[3].full_name == ".pdata" and
    pe.sections[3].name == ".pdata" and
    pe.sections[3].number_of_line_numbers == 0 and
    pe.sections[3].number_of_relocations == 0 and
    pe.sections[3].pointer_to_line_numbers == 0 and
    pe.sections[3].pointer_to_relocations == 0 and
    pe.sections[3].raw_data_offset == 636736 and
    pe.sections[3].raw_data_size == 13952 and
    pe.sections[3].virtual_address == 636736 and
    pe.sections[3].virtual_size == 13932 and
    pe.sections[4].characteristics == 3221225536 and
    pe.sections[4].full_name == ".tls" and
    pe.sections[4].name == ".tls" and
    pe.sections[4].number_of_line_numbers == 0 and
    pe.sections[4].number_of_relocations == 0 and
    pe.sections[4].pointer_to_line_numbers == 0 and
    pe.sections[4].pointer_to_relocations == 0 and
    pe.sections[4].raw_data_offset == 650688 and
    pe.sections[4].raw_data_size == 64 and
    pe.sections[4].virtual_address == 650688 and
    pe.sections[4].virtual_size == 9 and
    pe.sections[5].characteristics == 1073741888 and
    pe.sections[5].full_name == ".rsrc" and
    pe.sections[5].name == ".rsrc" and
    pe.sections[5].number_of_line_numbers == 0 and
    pe.sections[5].number_of_relocations == 0 and
    pe.sections[5].pointer_to_line_numbers == 0 and
    pe.sections[5].pointer_to_relocations == 0 and
    pe.sections[5].raw_data_offset == 650752 and
    pe.sections[5].raw_data_size == 58752 and
    pe.sections[5].virtual_address == 650752 and
    pe.sections[5].virtual_size == 58696)
 and
pe.size_of_code == 296576 and
pe.size_of_headers == 768 and
pe.size_of_heap_commit == 4096 and
pe.size_of_heap_reserve == 1048576 and
pe.size_of_image == 709504 and
pe.size_of_initialized_data == 412160 and
pe.size_of_optional_header == 240 and
pe.size_of_stack_commit == 4096 and
pe.size_of_stack_reserve == 1048576 and
pe.size_of_uninitialized_data == 0 and
pe.subsystem == 2 and
pe.subsystem_version.major == 5 and
pe.subsystem_version.minor == 2 and
pe.timestamp == 1630564063 and
    pe.version_info["CompanyName"] == "Ladislav Zezula" and
    pe.version_info["FileDescription"] == "Interactive File System API Test" and
    pe.version_info["FileVersion"] == "2, 7, 0, 602" and
    pe.version_info["InternalName"] == "FileTest" and
    pe.version_info["LegalCopyright"] == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x31\x38\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info["LegalTrademarks"] == "http://www.zezula.net" and
    pe.version_info["OriginalFilename"] == "FileTest.exe" and
    pe.version_info["ProductName"] == "FileTest" and
    pe.version_info["ProductVersion"] == "2, 7, 0, 602" and
(
    pe.version_info_list[0].key == "CompanyName" and
    pe.version_info_list[0].value == "Ladislav Zezula" and
    pe.version_info_list[1].key == "FileDescription" and
    pe.version_info_list[1].value == "Interactive File System API Test" and
    pe.version_info_list[2].key == "FileVersion" and
    pe.version_info_list[2].value == "2, 7, 0, 602" and
    pe.version_info_list[3].key == "InternalName" and
    pe.version_info_list[3].value == "FileTest" and
    pe.version_info_list[4].key == "LegalCopyright" and
    pe.version_info_list[4].value == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x31\x38\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info_list[5].key == "LegalTrademarks" and
    pe.version_info_list[5].value == "http://www.zezula.net" and
    pe.version_info_list[6].key == "OriginalFilename" and
    pe.version_info_list[6].value == "FileTest.exe" and
    pe.version_info_list[7].key == "ProductName" and
    pe.version_info_list[7].value == "FileTest" and
    pe.version_info_list[8].key == "ProductVersion" and
    pe.version_info_list[8].value == "2, 7, 0, 602")
 and
pe.win32_version_value == 0
}"#,
        "tests/assets/yara_1561/x64/FileTest_alignment_40.exe",
        true,
    );
}

#[test]
fn test_coverage_1561_32_align_40() {
    check_file(
        r#"import "pe"
rule test {
    condition:
pe.base_of_code == 704 and
pe.base_of_data == 240832 and
pe.characteristics == 259 and
pe.checksum == 596640 and
(
    pe.data_directories[0].size == 0 and
    pe.data_directories[0].virtual_address == 0 and
    pe.data_directories[1].size == 200 and
    pe.data_directories[1].virtual_address == 460620 and
    pe.data_directories[2].size == 58696 and
    pe.data_directories[2].virtual_address == 521088 and
    pe.data_directories[3].size == 0 and
    pe.data_directories[3].virtual_address == 0 and
    pe.data_directories[4].size == 0 and
    pe.data_directories[4].virtual_address == 0 and
    pe.data_directories[5].size == 0 and
    pe.data_directories[5].virtual_address == 0 and
    pe.data_directories[6].size == 28 and
    pe.data_directories[6].virtual_address == 242288 and
    pe.data_directories[7].size == 0 and
    pe.data_directories[7].virtual_address == 0 and
    pe.data_directories[8].size == 0 and
    pe.data_directories[8].virtual_address == 0 and
    pe.data_directories[9].size == 24 and
    pe.data_directories[9].virtual_address == 456528 and
    pe.data_directories[10].size == 64 and
    pe.data_directories[10].virtual_address == 456456 and
    pe.data_directories[11].size == 0 and
    pe.data_directories[11].virtual_address == 0 and
    pe.data_directories[12].size == 1372 and
    pe.data_directories[12].virtual_address == 240832 and
    pe.data_directories[13].size == 0 and
    pe.data_directories[13].virtual_address == 0 and
    pe.data_directories[14].size == 0 and
    pe.data_directories[14].virtual_address == 0 and
    pe.data_directories[15].size == 0 and
    pe.data_directories[15].virtual_address == 0)
 and
true and
pe.dll_characteristics == 33024 and
pe.entry_point == 43841 and
pe.entry_point_raw == 43841 and
pe.file_alignment == 64 and
pe.image_base == 4194304 and
pe.image_version.major == 0 and
pe.image_version.minor == 0 and
(
    (
        pe.import_details[0].functions[0].name == "HeapReAlloc" and
        pe.import_details[0].functions[0].rva == 241060 and
        pe.import_details[0].functions[1].name == "GetProcessHeap" and
        pe.import_details[0].functions[1].rva == 241064 and
        pe.import_details[0].functions[2].name == "GetCurrentProcess" and
        pe.import_details[0].functions[2].rva == 241068 and
        pe.import_details[0].functions[3].name == "MultiByteToWideChar" and
        pe.import_details[0].functions[3].rva == 241072 and
        pe.import_details[0].functions[4].name == "GetCurrentDirectoryW" and
        pe.import_details[0].functions[4].rva == 241076 and
        pe.import_details[0].functions[5].name == "EnumResourceNamesW" and
        pe.import_details[0].functions[5].rva == 241080 and
        pe.import_details[0].functions[6].name == "FreeLibrary" and
        pe.import_details[0].functions[6].rva == 241084 and
        pe.import_details[0].functions[7].name == "LoadLibraryW" and
        pe.import_details[0].functions[7].rva == 241088 and
        pe.import_details[0].functions[8].name == "GlobalReAlloc" and
        pe.import_details[0].functions[8].rva == 241092 and
        pe.import_details[0].functions[9].name == "GlobalSize" and
        pe.import_details[0].functions[9].rva == 241096 and
        pe.import_details[0].functions[10].name == "GlobalFree" and
        pe.import_details[0].functions[10].rva == 241100 and
        pe.import_details[0].functions[11].name == "GlobalUnlock" and
        pe.import_details[0].functions[11].rva == 241104 and
        pe.import_details[0].functions[12].name == "GlobalLock" and
        pe.import_details[0].functions[12].rva == 241108 and
        pe.import_details[0].functions[13].name == "GlobalAlloc" and
        pe.import_details[0].functions[13].rva == 241112 and
        pe.import_details[0].functions[14].name == "OpenProcess" and
        pe.import_details[0].functions[14].rva == 241116 and
        pe.import_details[0].functions[15].name == "FlushFileBuffers" and
        pe.import_details[0].functions[15].rva == 241120 and
        pe.import_details[0].functions[16].name == "GetFileAttributesW" and
        pe.import_details[0].functions[16].rva == 241124 and
        pe.import_details[0].functions[17].name == "CreateFileA" and
        pe.import_details[0].functions[17].rva == 241128 and
        pe.import_details[0].functions[18].name == "WriteConsoleW" and
        pe.import_details[0].functions[18].rva == 241132 and
        pe.import_details[0].functions[19].name == "GetConsoleOutputCP" and
        pe.import_details[0].functions[19].rva == 241136 and
        pe.import_details[0].functions[20].name == "WriteConsoleA" and
        pe.import_details[0].functions[20].rva == 241140 and
        pe.import_details[0].functions[21].name == "SetStdHandle" and
        pe.import_details[0].functions[21].rva == 241144 and
        pe.import_details[0].functions[22].name == "GetConsoleMode" and
        pe.import_details[0].functions[22].rva == 241148 and
        pe.import_details[0].functions[23].name == "GetConsoleCP" and
        pe.import_details[0].functions[23].rva == 241152 and
        pe.import_details[0].functions[24].name == "GetLocaleInfoA" and
        pe.import_details[0].functions[24].rva == 241156 and
        pe.import_details[0].functions[25].name == "GetStringTypeW" and
        pe.import_details[0].functions[25].rva == 241160 and
        pe.import_details[0].functions[26].name == "GetCurrentThread" and
        pe.import_details[0].functions[26].rva == 241164 and
        pe.import_details[0].functions[27].name == "QueryPerformanceCounter" and
        pe.import_details[0].functions[27].rva == 241168 and
        pe.import_details[0].functions[28].name == "DeleteFileW" and
        pe.import_details[0].functions[28].rva == 241172 and
        pe.import_details[0].functions[29].name == "GetStartupInfoA" and
        pe.import_details[0].functions[29].rva == 241176 and
        pe.import_details[0].functions[30].name == "GetFileType" and
        pe.import_details[0].functions[30].rva == 241180 and
        pe.import_details[0].functions[31].name == "SetHandleCount" and
        pe.import_details[0].functions[31].rva == 241184 and
        pe.import_details[0].functions[32].name == "GetCommandLineW" and
        pe.import_details[0].functions[32].rva == 241188 and
        pe.import_details[0].functions[33].name == "GetEnvironmentStringsW" and
        pe.import_details[0].functions[33].rva == 241192 and
        pe.import_details[0].functions[34].name == "FreeEnvironmentStringsW" and
        pe.import_details[0].functions[34].rva == 241196 and
        pe.import_details[0].functions[35].name == "InitializeCriticalSectionAndSpinCount" and
        pe.import_details[0].functions[35].rva == 241200 and
        pe.import_details[0].functions[36].name == "LoadLibraryA" and
        pe.import_details[0].functions[36].rva == 241204 and
        pe.import_details[0].functions[37].name == "GetModuleFileNameA" and
        pe.import_details[0].functions[37].rva == 241208 and
        pe.import_details[0].functions[38].name == "GetStdHandle" and
        pe.import_details[0].functions[38].rva == 241212 and
        pe.import_details[0].functions[39].name == "HeapSize" and
        pe.import_details[0].functions[39].rva == 241216 and
        pe.import_details[0].functions[40].name == "LCMapStringW" and
        pe.import_details[0].functions[40].rva == 241220 and
        pe.import_details[0].functions[41].name == "LCMapStringA" and
        pe.import_details[0].functions[41].rva == 241224 and
        pe.import_details[0].functions[42].name == "TlsFree" and
        pe.import_details[0].functions[42].rva == 241228 and
        pe.import_details[0].functions[43].name == "TlsSetValue" and
        pe.import_details[0].functions[43].rva == 241232 and
        pe.import_details[0].functions[44].name == "TlsAlloc" and
        pe.import_details[0].functions[44].rva == 241236 and
        pe.import_details[0].functions[45].name == "TlsGetValue" and
        pe.import_details[0].functions[45].rva == 241240 and
        pe.import_details[0].functions[46].name == "IsValidCodePage" and
        pe.import_details[0].functions[46].rva == 241244 and
        pe.import_details[0].functions[47].name == "GetOEMCP" and
        pe.import_details[0].functions[47].rva == 241248 and
        pe.import_details[0].functions[48].name == "GetACP" and
        pe.import_details[0].functions[48].rva == 241252 and
        pe.import_details[0].functions[49].name == "InterlockedDecrement" and
        pe.import_details[0].functions[49].rva == 241256 and
        pe.import_details[0].functions[50].name == "InterlockedIncrement" and
        pe.import_details[0].functions[50].rva == 241260 and
        pe.import_details[0].functions[51].name == "GetCPInfo" and
        pe.import_details[0].functions[51].rva == 241264 and
        pe.import_details[0].functions[52].name == "RaiseException" and
        pe.import_details[0].functions[52].rva == 241268 and
        pe.import_details[0].functions[53].name == "RtlUnwind" and
        pe.import_details[0].functions[53].rva == 241272 and
        pe.import_details[0].functions[54].name == "GetStartupInfoW" and
        pe.import_details[0].functions[54].rva == 241276 and
        pe.import_details[0].functions[55].name == "ExitProcess" and
        pe.import_details[0].functions[55].rva == 241280 and
        pe.import_details[0].functions[56].name == "Sleep" and
        pe.import_details[0].functions[56].rva == 241284 and
        pe.import_details[0].functions[57].name == "SetUnhandledExceptionFilter" and
        pe.import_details[0].functions[57].rva == 241288 and
        pe.import_details[0].functions[58].name == "UnhandledExceptionFilter" and
        pe.import_details[0].functions[58].rva == 241292 and
        pe.import_details[0].functions[59].name == "TerminateProcess" and
        pe.import_details[0].functions[59].rva == 241296 and
        pe.import_details[0].functions[60].name == "SizeofResource" and
        pe.import_details[0].functions[60].rva == 241300 and
        pe.import_details[0].functions[61].name == "FreeResource" and
        pe.import_details[0].functions[61].rva == 241304 and
        pe.import_details[0].functions[62].name == "IsDebuggerPresent" and
        pe.import_details[0].functions[62].rva == 241308 and
        pe.import_details[0].functions[63].name == "GetCurrentThreadId" and
        pe.import_details[0].functions[63].rva == 241312 and
        pe.import_details[0].functions[64].name == "GetCurrentProcessId" and
        pe.import_details[0].functions[64].rva == 241316 and
        pe.import_details[0].functions[65].name == "FormatMessageW" and
        pe.import_details[0].functions[65].rva == 241320 and
        pe.import_details[0].functions[66].name == "GetVersionExW" and
        pe.import_details[0].functions[66].rva == 241324 and
        pe.import_details[0].functions[67].name == "DeleteCriticalSection" and
        pe.import_details[0].functions[67].rva == 241328 and
        pe.import_details[0].functions[68].name == "WaitForSingleObject" and
        pe.import_details[0].functions[68].rva == 241332 and
        pe.import_details[0].functions[69].name == "CreateEventW" and
        pe.import_details[0].functions[69].rva == 241336 and
        pe.import_details[0].functions[70].name == "MoveFileExW" and
        pe.import_details[0].functions[70].rva == 241340 and
        pe.import_details[0].functions[71].name == "SetEndOfFile" and
        pe.import_details[0].functions[71].rva == 241344 and
        pe.import_details[0].functions[72].name == "SetFilePointer" and
        pe.import_details[0].functions[72].rva == 241348 and
        pe.import_details[0].functions[73].name == "UnlockFile" and
        pe.import_details[0].functions[73].rva == 241352 and
        pe.import_details[0].functions[74].name == "LockFile" and
        pe.import_details[0].functions[74].rva == 241356 and
        pe.import_details[0].functions[75].name == "GetOverlappedResult" and
        pe.import_details[0].functions[75].rva == 241360 and
        pe.import_details[0].functions[76].name == "SetCurrentDirectoryW" and
        pe.import_details[0].functions[76].rva == 241364 and
        pe.import_details[0].functions[77].name == "HeapCreate" and
        pe.import_details[0].functions[77].rva == 241368 and
        pe.import_details[0].functions[78].name == "CreateDirectoryW" and
        pe.import_details[0].functions[78].rva == 241372 and
        pe.import_details[0].functions[79].name == "LockResource" and
        pe.import_details[0].functions[79].rva == 241376 and
        pe.import_details[0].functions[80].name == "LoadResource" and
        pe.import_details[0].functions[80].rva == 241380 and
        pe.import_details[0].functions[81].name == "FindResourceW" and
        pe.import_details[0].functions[81].rva == 241384 and
        pe.import_details[0].functions[82].name == "InitializeCriticalSection" and
        pe.import_details[0].functions[82].rva == 241388 and
        pe.import_details[0].functions[83].name == "SetEvent" and
        pe.import_details[0].functions[83].rva == 241392 and
        pe.import_details[0].functions[84].name == "WaitForMultipleObjects" and
        pe.import_details[0].functions[84].rva == 241396 and
        pe.import_details[0].functions[85].name == "LeaveCriticalSection" and
        pe.import_details[0].functions[85].rva == 241400 and
        pe.import_details[0].functions[86].name == "EnterCriticalSection" and
        pe.import_details[0].functions[86].rva == 241404 and
        pe.import_details[0].functions[87].name == "CreateThread" and
        pe.import_details[0].functions[87].rva == 241408 and
        pe.import_details[0].functions[88].name == "GetProcAddress" and
        pe.import_details[0].functions[88].rva == 241412 and
        pe.import_details[0].functions[89].name == "GetModuleHandleW" and
        pe.import_details[0].functions[89].rva == 241416 and
        pe.import_details[0].functions[90].name == "VirtualFree" and
        pe.import_details[0].functions[90].rva == 241420 and
        pe.import_details[0].functions[91].name == "CloseHandle" and
        pe.import_details[0].functions[91].rva == 241424 and
        pe.import_details[0].functions[92].name == "SetFileTime" and
        pe.import_details[0].functions[92].rva == 241428 and
        pe.import_details[0].functions[93].name == "VirtualAlloc" and
        pe.import_details[0].functions[93].rva == 241432 and
        pe.import_details[0].functions[94].name == "GetFileTime" and
        pe.import_details[0].functions[94].rva == 241436 and
        pe.import_details[0].functions[95].name == "GetModuleFileNameW" and
        pe.import_details[0].functions[95].rva == 241440 and
        pe.import_details[0].functions[96].name == "GetTickCount" and
        pe.import_details[0].functions[96].rva == 241444 and
        pe.import_details[0].functions[97].name == "GetLocaleInfoW" and
        pe.import_details[0].functions[97].rva == 241448 and
        pe.import_details[0].functions[98].name == "ReadFile" and
        pe.import_details[0].functions[98].rva == 241452 and
        pe.import_details[0].functions[99].name == "DeviceIoControl" and
        pe.import_details[0].functions[99].rva == 241456 and
        pe.import_details[0].functions[100].name == "GetFileSize" and
        pe.import_details[0].functions[100].rva == 241460 and
        pe.import_details[0].functions[101].name == "SetLastError" and
        pe.import_details[0].functions[101].rva == 241464 and
        pe.import_details[0].functions[102].name == "GetLastError" and
        pe.import_details[0].functions[102].rva == 241468 and
        pe.import_details[0].functions[103].name == "CreateFileW" and
        pe.import_details[0].functions[103].rva == 241472 and
        pe.import_details[0].functions[104].name == "HeapFree" and
        pe.import_details[0].functions[104].rva == 241476 and
        pe.import_details[0].functions[105].name == "WriteFile" and
        pe.import_details[0].functions[105].rva == 241480 and
        pe.import_details[0].functions[106].name == "WideCharToMultiByte" and
        pe.import_details[0].functions[106].rva == 241484 and
        pe.import_details[0].functions[107].name == "HeapAlloc" and
        pe.import_details[0].functions[107].rva == 241488 and
        pe.import_details[0].functions[108].name == "LocalFileTimeToFileTime" and
        pe.import_details[0].functions[108].rva == 241492 and
        pe.import_details[0].functions[109].name == "SystemTimeToFileTime" and
        pe.import_details[0].functions[109].rva == 241496 and
        pe.import_details[0].functions[110].name == "EnumTimeFormatsW" and
        pe.import_details[0].functions[110].rva == 241500 and
        pe.import_details[0].functions[111].name == "EnumDateFormatsW" and
        pe.import_details[0].functions[111].rva == 241504 and
        pe.import_details[0].functions[112].name == "GetSystemTimeAsFileTime" and
        pe.import_details[0].functions[112].rva == 241508 and
        pe.import_details[0].functions[113].name == "GetTimeFormatW" and
        pe.import_details[0].functions[113].rva == 241512 and
        pe.import_details[0].functions[114].name == "FileTimeToSystemTime" and
        pe.import_details[0].functions[114].rva == 241516 and
        pe.import_details[0].functions[115].name == "FileTimeToLocalFileTime" and
        pe.import_details[0].functions[115].rva == 241520 and
        pe.import_details[0].functions[116].name == "GetDateFormatW" and
        pe.import_details[0].functions[116].rva == 241524 and
        pe.import_details[0].functions[117].name == "GetStringTypeA" and
        pe.import_details[0].functions[117].rva == 241528    )
 and
    pe.import_details[0].library_name == "KERNEL32.dll" and
    pe.import_details[0].number_of_functions == 118 and
    (
        pe.import_details[1].functions[0].name == "IsCharAlphaW" and
        pe.import_details[1].functions[0].rva == 241556 and
        pe.import_details[1].functions[1].name == "GetWindowLongW" and
        pe.import_details[1].functions[1].rva == 241560 and
        pe.import_details[1].functions[2].name == "SetWindowLongW" and
        pe.import_details[1].functions[2].rva == 241564 and
        pe.import_details[1].functions[3].name == "SendMessageW" and
        pe.import_details[1].functions[3].rva == 241568 and
        pe.import_details[1].functions[4].name == "SetWindowTextW" and
        pe.import_details[1].functions[4].rva == 241572 and
        pe.import_details[1].functions[5].name == "PostMessageW" and
        pe.import_details[1].functions[5].rva == 241576 and
        pe.import_details[1].functions[6].name == "GetDlgItem" and
        pe.import_details[1].functions[6].rva == 241580 and
        pe.import_details[1].functions[7].name == "EndDialog" and
        pe.import_details[1].functions[7].rva == 241584 and
        pe.import_details[1].functions[8].name == "DialogBoxParamW" and
        pe.import_details[1].functions[8].rva == 241588 and
        pe.import_details[1].functions[9].name == "CharUpperW" and
        pe.import_details[1].functions[9].rva == 241592 and
        pe.import_details[1].functions[10].name == "IsDlgButtonChecked" and
        pe.import_details[1].functions[10].rva == 241596 and
        pe.import_details[1].functions[11].name == "EnableWindow" and
        pe.import_details[1].functions[11].rva == 241600 and
        pe.import_details[1].functions[12].name == "SetDlgItemTextW" and
        pe.import_details[1].functions[12].rva == 241604 and
        pe.import_details[1].functions[13].name == "GetWindowTextLengthW" and
        pe.import_details[1].functions[13].rva == 241608 and
        pe.import_details[1].functions[14].name == "GetWindowTextW" and
        pe.import_details[1].functions[14].rva == 241612 and
        pe.import_details[1].functions[15].name == "CheckDlgButton" and
        pe.import_details[1].functions[15].rva == 241616 and
        pe.import_details[1].functions[16].name == "SetWindowTextA" and
        pe.import_details[1].functions[16].rva == 241620 and
        pe.import_details[1].functions[17].name == "SetFocus" and
        pe.import_details[1].functions[17].rva == 241624 and
        pe.import_details[1].functions[18].name == "GetWindowTextA" and
        pe.import_details[1].functions[18].rva == 241628 and
        pe.import_details[1].functions[19].name == "CreateCursor" and
        pe.import_details[1].functions[19].rva == 241632 and
        pe.import_details[1].functions[20].name == "SetCursor" and
        pe.import_details[1].functions[20].rva == 241636 and
        pe.import_details[1].functions[21].name == "CallWindowProcW" and
        pe.import_details[1].functions[21].rva == 241640 and
        pe.import_details[1].functions[22].name == "CreateDialogIndirectParamW" and
        pe.import_details[1].functions[22].rva == 241644 and
        pe.import_details[1].functions[23].name == "SendDlgItemMessageA" and
        pe.import_details[1].functions[23].rva == 241648 and
        pe.import_details[1].functions[24].name == "DialogBoxIndirectParamW" and
        pe.import_details[1].functions[24].rva == 241652 and
        pe.import_details[1].functions[25].name == "FillRect" and
        pe.import_details[1].functions[25].rva == 241656 and
        pe.import_details[1].functions[26].name == "DeleteMenu" and
        pe.import_details[1].functions[26].rva == 241660 and
        pe.import_details[1].functions[27].name == "MessageBeep" and
        pe.import_details[1].functions[27].rva == 241664 and
        pe.import_details[1].functions[28].name == "DrawTextExW" and
        pe.import_details[1].functions[28].rva == 241668 and
        pe.import_details[1].functions[29].name == "BeginDeferWindowPos" and
        pe.import_details[1].functions[29].rva == 241672 and
        pe.import_details[1].functions[30].name == "DeferWindowPos" and
        pe.import_details[1].functions[30].rva == 241676 and
        pe.import_details[1].functions[31].name == "EndDeferWindowPos" and
        pe.import_details[1].functions[31].rva == 241680 and
        pe.import_details[1].functions[32].name == "LoadIconW" and
        pe.import_details[1].functions[32].rva == 241684 and
        pe.import_details[1].functions[33].name == "InvalidateRect" and
        pe.import_details[1].functions[33].rva == 241688 and
        pe.import_details[1].functions[34].name == "SetWindowPos" and
        pe.import_details[1].functions[34].rva == 241692 and
        pe.import_details[1].functions[35].name == "GetWindowRect" and
        pe.import_details[1].functions[35].rva == 241696 and
        pe.import_details[1].functions[36].name == "SystemParametersInfoW" and
        pe.import_details[1].functions[36].rva == 241700 and
        pe.import_details[1].functions[37].name == "SetTimer" and
        pe.import_details[1].functions[37].rva == 241704 and
        pe.import_details[1].functions[38].name == "KillTimer" and
        pe.import_details[1].functions[38].rva == 241708 and
        pe.import_details[1].functions[39].name == "MapDialogRect" and
        pe.import_details[1].functions[39].rva == 241712 and
        pe.import_details[1].functions[40].name == "GetSystemMetrics" and
        pe.import_details[1].functions[40].rva == 241716 and
        pe.import_details[1].functions[41].name == "GetSystemMenu" and
        pe.import_details[1].functions[41].rva == 241720 and
        pe.import_details[1].functions[42].name == "GetMenuItemCount" and
        pe.import_details[1].functions[42].rva == 241724 and
        pe.import_details[1].functions[43].name == "TrackPopupMenu" and
        pe.import_details[1].functions[43].rva == 241728 and
        pe.import_details[1].functions[44].name == "SetForegroundWindow" and
        pe.import_details[1].functions[44].rva == 241732 and
        pe.import_details[1].functions[45].name == "GetMenuItemInfoW" and
        pe.import_details[1].functions[45].rva == 241736 and
        pe.import_details[1].functions[46].name == "LoadStringW" and
        pe.import_details[1].functions[46].rva == 241740 and
        pe.import_details[1].functions[47].name == "InsertMenuW" and
        pe.import_details[1].functions[47].rva == 241744 and
        pe.import_details[1].functions[48].name == "GetCursorPos" and
        pe.import_details[1].functions[48].rva == 241748 and
        pe.import_details[1].functions[49].name == "LoadMenuW" and
        pe.import_details[1].functions[49].rva == 241752 and
        pe.import_details[1].functions[50].name == "LoadImageW" and
        pe.import_details[1].functions[50].rva == 241756 and
        pe.import_details[1].functions[51].name == "RegisterClassExW" and
        pe.import_details[1].functions[51].rva == 241760 and
        pe.import_details[1].functions[52].name == "LoadCursorW" and
        pe.import_details[1].functions[52].rva == 241764 and
        pe.import_details[1].functions[53].name == "GetClassInfoExW" and
        pe.import_details[1].functions[53].rva == 241768 and
        pe.import_details[1].functions[54].name == "DefWindowProcW" and
        pe.import_details[1].functions[54].rva == 241772 and
        pe.import_details[1].functions[55].name == "EndPaint" and
        pe.import_details[1].functions[55].rva == 241776 and
        pe.import_details[1].functions[56].name == "TabbedTextOutW" and
        pe.import_details[1].functions[56].rva == 241780 and
        pe.import_details[1].functions[57].name == "IntersectRect" and
        pe.import_details[1].functions[57].rva == 241784 and
        pe.import_details[1].functions[58].name == "BeginPaint" and
        pe.import_details[1].functions[58].rva == 241788 and
        pe.import_details[1].functions[59].name == "GetScrollInfo" and
        pe.import_details[1].functions[59].rva == 241792 and
        pe.import_details[1].functions[60].name == "SetCapture" and
        pe.import_details[1].functions[60].rva == 241796 and
        pe.import_details[1].functions[61].name == "DestroyCaret" and
        pe.import_details[1].functions[61].rva == 241800 and
        pe.import_details[1].functions[62].name == "HideCaret" and
        pe.import_details[1].functions[62].rva == 241804 and
        pe.import_details[1].functions[63].name == "ReleaseCapture" and
        pe.import_details[1].functions[63].rva == 241808 and
        pe.import_details[1].functions[64].name == "ShowCaret" and
        pe.import_details[1].functions[64].rva == 241812 and
        pe.import_details[1].functions[65].name == "CreateCaret" and
        pe.import_details[1].functions[65].rva == 241816 and
        pe.import_details[1].functions[66].name == "SetCaretPos" and
        pe.import_details[1].functions[66].rva == 241820 and
        pe.import_details[1].functions[67].name == "GetTabbedTextExtentW" and
        pe.import_details[1].functions[67].rva == 241824 and
        pe.import_details[1].functions[68].name == "SetScrollInfo" and
        pe.import_details[1].functions[68].rva == 241828 and
        pe.import_details[1].functions[69].name == "ReleaseDC" and
        pe.import_details[1].functions[69].rva == 241832 and
        pe.import_details[1].functions[70].name == "GetDC" and
        pe.import_details[1].functions[70].rva == 241836 and
        pe.import_details[1].functions[71].name == "GetClipboardData" and
        pe.import_details[1].functions[71].rva == 241840 and
        pe.import_details[1].functions[72].name == "IsClipboardFormatAvailable" and
        pe.import_details[1].functions[72].rva == 241844 and
        pe.import_details[1].functions[73].name == "GetDlgItemInt" and
        pe.import_details[1].functions[73].rva == 241848 and
        pe.import_details[1].functions[74].name == "ScreenToClient" and
        pe.import_details[1].functions[74].rva == 241852 and
        pe.import_details[1].functions[75].name == "EnableMenuItem" and
        pe.import_details[1].functions[75].rva == 241856 and
        pe.import_details[1].functions[76].name == "GetSubMenu" and
        pe.import_details[1].functions[76].rva == 241860 and
        pe.import_details[1].functions[77].name == "GetFocus" and
        pe.import_details[1].functions[77].rva == 241864 and
        pe.import_details[1].functions[78].name == "ClientToScreen" and
        pe.import_details[1].functions[78].rva == 241868 and
        pe.import_details[1].functions[79].name == "CloseClipboard" and
        pe.import_details[1].functions[79].rva == 241872 and
        pe.import_details[1].functions[80].name == "SetClipboardData" and
        pe.import_details[1].functions[80].rva == 241876 and
        pe.import_details[1].functions[81].name == "EmptyClipboard" and
        pe.import_details[1].functions[81].rva == 241880 and
        pe.import_details[1].functions[82].name == "OpenClipboard" and
        pe.import_details[1].functions[82].rva == 241884 and
        pe.import_details[1].functions[83].name == "IsWindowVisible" and
        pe.import_details[1].functions[83].rva == 241888 and
        pe.import_details[1].functions[84].name == "GetDlgItemTextW" and
        pe.import_details[1].functions[84].rva == 241892 and
        pe.import_details[1].functions[85].name == "GetClassNameW" and
        pe.import_details[1].functions[85].rva == 241896 and
        pe.import_details[1].functions[86].name == "GetTopWindow" and
        pe.import_details[1].functions[86].rva == 241900 and
        pe.import_details[1].functions[87].name == "IsWindowEnabled" and
        pe.import_details[1].functions[87].rva == 241904 and
        pe.import_details[1].functions[88].name == "GetWindow" and
        pe.import_details[1].functions[88].rva == 241908 and
        pe.import_details[1].functions[89].name == "GetClientRect" and
        pe.import_details[1].functions[89].rva == 241912 and
        pe.import_details[1].functions[90].name == "CreateWindowExW" and
        pe.import_details[1].functions[90].rva == 241916 and
        pe.import_details[1].functions[91].name == "LoadStringA" and
        pe.import_details[1].functions[91].rva == 241920 and
        pe.import_details[1].functions[92].name == "DestroyAcceleratorTable" and
        pe.import_details[1].functions[92].rva == 241924 and
        pe.import_details[1].functions[93].name == "DispatchMessageW" and
        pe.import_details[1].functions[93].rva == 241928 and
        pe.import_details[1].functions[94].name == "TranslateMessage" and
        pe.import_details[1].functions[94].rva == 241932 and
        pe.import_details[1].functions[95].name == "TranslateAcceleratorW" and
        pe.import_details[1].functions[95].rva == 241936 and
        pe.import_details[1].functions[96].name == "GetMessageW" and
        pe.import_details[1].functions[96].rva == 241940 and
        pe.import_details[1].functions[97].name == "IsWindow" and
        pe.import_details[1].functions[97].rva == 241944 and
        pe.import_details[1].functions[98].name == "ShowWindow" and
        pe.import_details[1].functions[98].rva == 241948 and
        pe.import_details[1].functions[99].name == "CreateDialogParamW" and
        pe.import_details[1].functions[99].rva == 241952 and
        pe.import_details[1].functions[100].name == "LoadAcceleratorsW" and
        pe.import_details[1].functions[100].rva == 241956 and
        pe.import_details[1].functions[101].name == "GetParent" and
        pe.import_details[1].functions[101].rva == 241960 and
        pe.import_details[1].functions[102].name == "IsDialogMessageW" and
        pe.import_details[1].functions[102].rva == 241964 and
        pe.import_details[1].functions[103].name == "GetAsyncKeyState" and
        pe.import_details[1].functions[103].rva == 241968 and
        pe.import_details[1].functions[104].name == "DestroyWindow" and
        pe.import_details[1].functions[104].rva == 241972 and
        pe.import_details[1].functions[105].name == "PtInRect" and
        pe.import_details[1].functions[105].rva == 241976 and
        pe.import_details[1].functions[106].name == "GetActiveWindow" and
        pe.import_details[1].functions[106].rva == 241980    )
 and
    pe.import_details[1].library_name == "USER32.dll" and
    pe.import_details[1].number_of_functions == 107 and
    (
        pe.import_details[2].functions[0].name == "SetTextAlign" and
        pe.import_details[2].functions[0].rva == 241012 and
        pe.import_details[2].functions[1].name == "GetTextMetricsW" and
        pe.import_details[2].functions[1].rva == 241016 and
        pe.import_details[2].functions[2].name == "SelectObject" and
        pe.import_details[2].functions[2].rva == 241020 and
        pe.import_details[2].functions[3].name == "GetStockObject" and
        pe.import_details[2].functions[3].rva == 241024 and
        pe.import_details[2].functions[4].name == "CreateFontIndirectW" and
        pe.import_details[2].functions[4].rva == 241028 and
        pe.import_details[2].functions[5].name == "SetTextColor" and
        pe.import_details[2].functions[5].rva == 241032 and
        pe.import_details[2].functions[6].name == "SetBkColor" and
        pe.import_details[2].functions[6].rva == 241036 and
        pe.import_details[2].functions[7].name == "GetTextExtentPoint32W" and
        pe.import_details[2].functions[7].rva == 241040 and
        pe.import_details[2].functions[8].name == "GetObjectW" and
        pe.import_details[2].functions[8].rva == 241044 and
        pe.import_details[2].functions[9].name == "TextOutW" and
        pe.import_details[2].functions[9].rva == 241048 and
        pe.import_details[2].functions[10].name == "ExtTextOutW" and
        pe.import_details[2].functions[10].rva == 241052    )
 and
    pe.import_details[2].library_name == "GDI32.dll" and
    pe.import_details[2].number_of_functions == 11 and
    (
        pe.import_details[3].functions[0].name == "CopySid" and
        pe.import_details[3].functions[0].rva == 240832 and
        pe.import_details[3].functions[1].name == "SetSecurityDescriptorSacl" and
        pe.import_details[3].functions[1].rva == 240836 and
        pe.import_details[3].functions[2].name == "SetSecurityDescriptorDacl" and
        pe.import_details[3].functions[2].rva == 240840 and
        pe.import_details[3].functions[3].name == "SetSecurityDescriptorGroup" and
        pe.import_details[3].functions[3].rva == 240844 and
        pe.import_details[3].functions[4].name == "SetSecurityDescriptorOwner" and
        pe.import_details[3].functions[4].rva == 240848 and
        pe.import_details[3].functions[5].name == "InitializeSecurityDescriptor" and
        pe.import_details[3].functions[5].rva == 240852 and
        pe.import_details[3].functions[6].name == "GetSecurityDescriptorSacl" and
        pe.import_details[3].functions[6].rva == 240856 and
        pe.import_details[3].functions[7].name == "GetSecurityDescriptorDacl" and
        pe.import_details[3].functions[7].rva == 240860 and
        pe.import_details[3].functions[8].name == "GetSecurityDescriptorGroup" and
        pe.import_details[3].functions[8].rva == 240864 and
        pe.import_details[3].functions[9].name == "GetSecurityDescriptorOwner" and
        pe.import_details[3].functions[9].rva == 240868 and
        pe.import_details[3].functions[10].name == "GetAce" and
        pe.import_details[3].functions[10].rva == 240872 and
        pe.import_details[3].functions[11].name == "AddAuditAccessAce" and
        pe.import_details[3].functions[11].rva == 240876 and
        pe.import_details[3].functions[12].name == "AddAccessDeniedAce" and
        pe.import_details[3].functions[12].rva == 240880 and
        pe.import_details[3].functions[13].name == "AddAccessAllowedAce" and
        pe.import_details[3].functions[13].rva == 240884 and
        pe.import_details[3].functions[14].name == "InitializeAcl" and
        pe.import_details[3].functions[14].rva == 240888 and
        pe.import_details[3].functions[15].name == "LookupAccountNameW" and
        pe.import_details[3].functions[15].rva == 240892 and
        pe.import_details[3].functions[16].name == "LookupAccountSidW" and
        pe.import_details[3].functions[16].rva == 240896 and
        pe.import_details[3].functions[17].name == "GetLengthSid" and
        pe.import_details[3].functions[17].rva == 240900 and
        pe.import_details[3].functions[18].name == "RegSetValueExW" and
        pe.import_details[3].functions[18].rva == 240904 and
        pe.import_details[3].functions[19].name == "FreeSid" and
        pe.import_details[3].functions[19].rva == 240908 and
        pe.import_details[3].functions[20].name == "SetTokenInformation" and
        pe.import_details[3].functions[20].rva == 240912 and
        pe.import_details[3].functions[21].name == "AllocateAndInitializeSid" and
        pe.import_details[3].functions[21].rva == 240916 and
        pe.import_details[3].functions[22].name == "AdjustTokenPrivileges" and
        pe.import_details[3].functions[22].rva == 240920 and
        pe.import_details[3].functions[23].name == "LookupPrivilegeValueW" and
        pe.import_details[3].functions[23].rva == 240924 and
        pe.import_details[3].functions[24].name == "LookupPrivilegeNameW" and
        pe.import_details[3].functions[24].rva == 240928 and
        pe.import_details[3].functions[25].name == "RegCloseKey" and
        pe.import_details[3].functions[25].rva == 240932 and
        pe.import_details[3].functions[26].name == "RegQueryValueExW" and
        pe.import_details[3].functions[26].rva == 240936 and
        pe.import_details[3].functions[27].name == "RegOpenKeyExW" and
        pe.import_details[3].functions[27].rva == 240940 and
        pe.import_details[3].functions[28].name == "GetSidSubAuthority" and
        pe.import_details[3].functions[28].rva == 240944 and
        pe.import_details[3].functions[29].name == "GetSidIdentifierAuthority" and
        pe.import_details[3].functions[29].rva == 240948 and
        pe.import_details[3].functions[30].name == "GetSidSubAuthorityCount" and
        pe.import_details[3].functions[30].rva == 240952 and
        pe.import_details[3].functions[31].name == "GetTokenInformation" and
        pe.import_details[3].functions[31].rva == 240956 and
        pe.import_details[3].functions[32].name == "OpenProcessToken" and
        pe.import_details[3].functions[32].rva == 240960 and
        pe.import_details[3].functions[33].name == "OpenThreadToken" and
        pe.import_details[3].functions[33].rva == 240964 and
        pe.import_details[3].functions[34].name == "GetUserNameW" and
        pe.import_details[3].functions[34].rva == 240968    )
 and
    pe.import_details[3].library_name == "ADVAPI32.dll" and
    pe.import_details[3].number_of_functions == 35 and
    (
        pe.import_details[4].functions[0].name == "NtCreateFile" and
        pe.import_details[4].functions[0].rva == 242004 and
        pe.import_details[4].functions[1].name == "NtClose" and
        pe.import_details[4].functions[1].rva == 242008 and
        pe.import_details[4].functions[2].name == "RtlInitUnicodeString" and
        pe.import_details[4].functions[2].rva == 242012 and
        pe.import_details[4].functions[3].name == "RtlFreeUnicodeString" and
        pe.import_details[4].functions[3].rva == 242016 and
        pe.import_details[4].functions[4].name == "RtlCreateUnicodeString" and
        pe.import_details[4].functions[4].rva == 242020 and
        pe.import_details[4].functions[5].name == "NtOpenDirectoryObject" and
        pe.import_details[4].functions[5].rva == 242024 and
        pe.import_details[4].functions[6].name == "RtlDecompressBuffer" and
        pe.import_details[4].functions[6].rva == 242028 and
        pe.import_details[4].functions[7].name == "NtDeviceIoControlFile" and
        pe.import_details[4].functions[7].rva == 242032 and
        pe.import_details[4].functions[8].name == "RtlReAllocateHeap" and
        pe.import_details[4].functions[8].rva == 242036 and
        pe.import_details[4].functions[9].name == "NtQuerySymbolicLinkObject" and
        pe.import_details[4].functions[9].rva == 242040 and
        pe.import_details[4].functions[10].name == "NtOpenSymbolicLinkObject" and
        pe.import_details[4].functions[10].rva == 242044 and
        pe.import_details[4].functions[11].name == "NtCreateSymbolicLinkObject" and
        pe.import_details[4].functions[11].rva == 242048 and
        pe.import_details[4].functions[12].name == "NtQuerySecurityObject" and
        pe.import_details[4].functions[12].rva == 242052 and
        pe.import_details[4].functions[13].name == "NtSetEaFile" and
        pe.import_details[4].functions[13].rva == 242056 and
        pe.import_details[4].functions[14].name == "NtQueryEaFile" and
        pe.import_details[4].functions[14].rva == 242060 and
        pe.import_details[4].functions[15].name == "NtSetVolumeInformationFile" and
        pe.import_details[4].functions[15].rva == 242064 and
        pe.import_details[4].functions[16].name == "NtQueryVolumeInformationFile" and
        pe.import_details[4].functions[16].rva == 242068 and
        pe.import_details[4].functions[17].name == "RtlCompareUnicodeString" and
        pe.import_details[4].functions[17].rva == 242072 and
        pe.import_details[4].functions[18].name == "NtQueryInformationProcess" and
        pe.import_details[4].functions[18].rva == 242076 and
        pe.import_details[4].functions[19].name == "NtQuerySystemInformation" and
        pe.import_details[4].functions[19].rva == 242080 and
        pe.import_details[4].functions[20].name == "NtFsControlFile" and
        pe.import_details[4].functions[20].rva == 242084 and
        pe.import_details[4].functions[21].name == "NtQueryAttributesFile" and
        pe.import_details[4].functions[21].rva == 242088 and
        pe.import_details[4].functions[22].name == "NtQueryDirectoryFile" and
        pe.import_details[4].functions[22].rva == 242092 and
        pe.import_details[4].functions[23].name == "NtQueryInformationFile" and
        pe.import_details[4].functions[23].rva == 242096 and
        pe.import_details[4].functions[24].name == "NtDeleteFile" and
        pe.import_details[4].functions[24].rva == 242100 and
        pe.import_details[4].functions[25].name == "NtSetInformationFile" and
        pe.import_details[4].functions[25].rva == 242104 and
        pe.import_details[4].functions[26].name == "RtlFreeSid" and
        pe.import_details[4].functions[26].rva == 242108 and
        pe.import_details[4].functions[27].name == "RtlSetDaclSecurityDescriptor" and
        pe.import_details[4].functions[27].rva == 242112 and
        pe.import_details[4].functions[28].name == "RtlAddAccessAllowedAce" and
        pe.import_details[4].functions[28].rva == 242116 and
        pe.import_details[4].functions[29].name == "RtlCreateAcl" and
        pe.import_details[4].functions[29].rva == 242120 and
        pe.import_details[4].functions[30].name == "RtlLengthSid" and
        pe.import_details[4].functions[30].rva == 242124 and
        pe.import_details[4].functions[31].name == "RtlAllocateAndInitializeSid" and
        pe.import_details[4].functions[31].rva == 242128 and
        pe.import_details[4].functions[32].name == "RtlFreeHeap" and
        pe.import_details[4].functions[32].rva == 242132 and
        pe.import_details[4].functions[33].name == "NtSetSecurityObject" and
        pe.import_details[4].functions[33].rva == 242136 and
        pe.import_details[4].functions[34].name == "RtlSetOwnerSecurityDescriptor" and
        pe.import_details[4].functions[34].rva == 242140 and
        pe.import_details[4].functions[35].name == "RtlCreateSecurityDescriptor" and
        pe.import_details[4].functions[35].rva == 242144 and
        pe.import_details[4].functions[36].name == "RtlAllocateHeap" and
        pe.import_details[4].functions[36].rva == 242148 and
        pe.import_details[4].functions[37].name == "NtQueryInformationToken" and
        pe.import_details[4].functions[37].rva == 242152 and
        pe.import_details[4].functions[38].name == "NtOpenProcessToken" and
        pe.import_details[4].functions[38].rva == 242156 and
        pe.import_details[4].functions[39].name == "NtUnmapViewOfSection" and
        pe.import_details[4].functions[39].rva == 242160 and
        pe.import_details[4].functions[40].name == "NtMapViewOfSection" and
        pe.import_details[4].functions[40].rva == 242164 and
        pe.import_details[4].functions[41].name == "NtOpenSection" and
        pe.import_details[4].functions[41].rva == 242168 and
        pe.import_details[4].functions[42].name == "NtCreateSection" and
        pe.import_details[4].functions[42].rva == 242172 and
        pe.import_details[4].functions[43].name == "NtUnlockFile" and
        pe.import_details[4].functions[43].rva == 242176 and
        pe.import_details[4].functions[44].name == "NtLockFile" and
        pe.import_details[4].functions[44].rva == 242180 and
        pe.import_details[4].functions[45].name == "NtWriteFile" and
        pe.import_details[4].functions[45].rva == 242184 and
        pe.import_details[4].functions[46].name == "NtReadFile" and
        pe.import_details[4].functions[46].rva == 242188 and
        pe.import_details[4].functions[47].name == "RtlNtStatusToDosError" and
        pe.import_details[4].functions[47].rva == 242192 and
        pe.import_details[4].functions[48].name == "NtOpenFile" and
        pe.import_details[4].functions[48].rva == 242196    )
 and
    pe.import_details[4].library_name == "ntdll.dll" and
    pe.import_details[4].number_of_functions == 49 and
    (
        pe.import_details[5].functions[0].name == "CreatePropertySheetPageW" and
        pe.import_details[5].functions[0].rva == 240976 and
        pe.import_details[5].functions[1].name == "ImageList_ReplaceIcon" and
        pe.import_details[5].functions[1].rva == 240980 and
        pe.import_details[5].functions[2].name == "ord17" and
        pe.import_details[5].functions[2].ordinal == 17 and
        pe.import_details[5].functions[2].rva == 240984 and
        pe.import_details[5].functions[3].name == "PropertySheetW" and
        pe.import_details[5].functions[3].rva == 240988 and
        pe.import_details[5].functions[4].name == "ImageList_Create" and
        pe.import_details[5].functions[4].rva == 240992    )
 and
    pe.import_details[5].library_name == "COMCTL32.dll" and
    pe.import_details[5].number_of_functions == 5 and
    (
        pe.import_details[6].functions[0].name == "GetFileVersionInfoSizeW" and
        pe.import_details[6].functions[0].rva == 241988 and
        pe.import_details[6].functions[1].name == "GetFileVersionInfoW" and
        pe.import_details[6].functions[1].rva == 241992 and
        pe.import_details[6].functions[2].name == "VerQueryValueW" and
        pe.import_details[6].functions[2].rva == 241996    )
 and
    pe.import_details[6].library_name == "VERSION.dll" and
    pe.import_details[6].number_of_functions == 3 and
    (
        pe.import_details[7].functions[0].name == "GetSaveFileNameW" and
        pe.import_details[7].functions[0].rva == 241000 and
        pe.import_details[7].functions[1].name == "GetOpenFileNameW" and
        pe.import_details[7].functions[1].rva == 241004    )
 and
    pe.import_details[7].library_name == "COMDLG32.dll" and
    pe.import_details[7].number_of_functions == 2 and
    (
        pe.import_details[8].functions[0].name == "SHBrowseForFolderW" and
        pe.import_details[8].functions[0].rva == 241536 and
        pe.import_details[8].functions[1].name == "SHGetPathFromIDListW" and
        pe.import_details[8].functions[1].rva == 241540 and
        pe.import_details[8].functions[2].name == "SHGetMalloc" and
        pe.import_details[8].functions[2].rva == 241544 and
        pe.import_details[8].functions[3].name == "ShellExecuteW" and
        pe.import_details[8].functions[3].rva == 241548    )
 and
    pe.import_details[8].library_name == "SHELL32.dll" and
    pe.import_details[8].number_of_functions == 4)
 and
pe.is_pe == 1 and
pe.linker_version.major == 9 and
pe.linker_version.minor == 0 and
pe.loader_flags == 0 and
pe.machine == 332 and
pe.number_of_delayed_imported_functions == 0 and
pe.number_of_delayed_imports == 0 and
pe.number_of_exports == 0 and
pe.number_of_imported_functions == 334 and
pe.number_of_imports == 9 and
pe.number_of_resources == 72 and
pe.number_of_rva_and_sizes == 16 and
pe.number_of_sections == 5 and
pe.number_of_symbols == 0 and
pe.number_of_version_infos == 9 and
pe.opthdr_magic == 267 and
pe.os_version.major == 4 and
pe.os_version.minor == 0 and
pe.overlay.offset == 0 and
pe.overlay.size == 0 and
pe.pdb_path == "FileTest.pdb" and
pe.pointer_to_symbol_table == 0 and
pe.resource_timestamp == 0 and
pe.resource_version.major == 0 and
pe.resource_version.minor == 0 and
(
    pe.resources[0].id == 106 and
    pe.resources[0].language == 1033 and
    pe.resources[0].length == 2 and
    pe.resources[0].offset == 574224 and
    pe.resources[0].rva == 574224 and
    pe.resources[0].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[1].id == 107 and
    pe.resources[1].language == 1033 and
    pe.resources[1].length == 2 and
    pe.resources[1].offset == 574216 and
    pe.resources[1].rva == 574216 and
    pe.resources[1].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[2].id == 111 and
    pe.resources[2].language == 1033 and
    pe.resources[2].length == 2 and
    pe.resources[2].offset == 574240 and
    pe.resources[2].rva == 574240 and
    pe.resources[2].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[3].id == 112 and
    pe.resources[3].language == 1033 and
    pe.resources[3].length == 2 and
    pe.resources[3].offset == 574232 and
    pe.resources[3].rva == 574232 and
    pe.resources[3].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[4].id == 114 and
    pe.resources[4].language == 1033 and
    pe.resources[4].length == 2 and
    pe.resources[4].offset == 574208 and
    pe.resources[4].rva == 574208 and
    pe.resources[4].type_string == "A\x00F\x00X\x00_\x00D\x00I\x00A\x00L\x00O\x00G\x00_\x00L\x00A\x00Y\x00O\x00U\x00T\x00" and
    pe.resources[5].id == 1 and
    pe.resources[5].language == 0 and
    pe.resources[5].length == 1640 and
    pe.resources[5].offset == 526640 and
    pe.resources[5].rva == 526640 and
    pe.resources[5].type == 3 and
    pe.resources[6].id == 2 and
    pe.resources[6].language == 0 and
    pe.resources[6].length == 296 and
    pe.resources[6].offset == 528280 and
    pe.resources[6].rva == 528280 and
    pe.resources[6].type == 3 and
    pe.resources[7].id == 3 and
    pe.resources[7].language == 0 and
    pe.resources[7].length == 744 and
    pe.resources[7].offset == 528576 and
    pe.resources[7].rva == 528576 and
    pe.resources[7].type == 3 and
    pe.resources[8].id == 4 and
    pe.resources[8].language == 0 and
    pe.resources[8].length == 1384 and
    pe.resources[8].offset == 529320 and
    pe.resources[8].rva == 529320 and
    pe.resources[8].type == 3 and
    pe.resources[9].id == 5 and
    pe.resources[9].language == 0 and
    pe.resources[9].length == 2216 and
    pe.resources[9].offset == 530704 and
    pe.resources[9].rva == 530704 and
    pe.resources[9].type == 3 and
    pe.resources[10].id == 6 and
    pe.resources[10].language == 0 and
    pe.resources[10].length == 3752 and
    pe.resources[10].offset == 532920 and
    pe.resources[10].rva == 532920 and
    pe.resources[10].type == 3 and
    pe.resources[11].id == 7 and
    pe.resources[11].language == 0 and
    pe.resources[11].length == 296 and
    pe.resources[11].offset == 536768 and
    pe.resources[11].rva == 536768 and
    pe.resources[11].type == 3 and
    pe.resources[12].id == 8 and
    pe.resources[12].language == 0 and
    pe.resources[12].length == 1384 and
    pe.resources[12].offset == 537064 and
    pe.resources[12].rva == 537064 and
    pe.resources[12].type == 3 and
    pe.resources[13].id == 9 and
    pe.resources[13].language == 0 and
    pe.resources[13].length == 296 and
    pe.resources[13].offset == 538488 and
    pe.resources[13].rva == 538488 and
    pe.resources[13].type == 3 and
    pe.resources[14].id == 10 and
    pe.resources[14].language == 0 and
    pe.resources[14].length == 1384 and
    pe.resources[14].offset == 538784 and
    pe.resources[14].rva == 538784 and
    pe.resources[14].type == 3 and
    pe.resources[15].id == 11 and
    pe.resources[15].language == 0 and
    pe.resources[15].length == 296 and
    pe.resources[15].offset == 540208 and
    pe.resources[15].rva == 540208 and
    pe.resources[15].type == 3 and
    pe.resources[16].id == 12 and
    pe.resources[16].language == 0 and
    pe.resources[16].length == 1384 and
    pe.resources[16].offset == 540504 and
    pe.resources[16].rva == 540504 and
    pe.resources[16].type == 3 and
    pe.resources[17].id == 13 and
    pe.resources[17].language == 0 and
    pe.resources[17].length == 296 and
    pe.resources[17].offset == 541928 and
    pe.resources[17].rva == 541928 and
    pe.resources[17].type == 3 and
    pe.resources[18].id == 14 and
    pe.resources[18].language == 0 and
    pe.resources[18].length == 1384 and
    pe.resources[18].offset == 542224 and
    pe.resources[18].rva == 542224 and
    pe.resources[18].type == 3 and
    pe.resources[19].id == 15 and
    pe.resources[19].language == 0 and
    pe.resources[19].length == 1128 and
    pe.resources[19].offset == 543648 and
    pe.resources[19].rva == 543648 and
    pe.resources[19].type == 3 and
    pe.resources[20].id == 123 and
    pe.resources[20].language == 1033 and
    pe.resources[20].length == 248 and
    pe.resources[20].offset == 545688 and
    pe.resources[20].rva == 545688 and
    pe.resources[20].type == 4 and
    pe.resources[21].id == 129 and
    pe.resources[21].language == 1033 and
    pe.resources[21].length == 164 and
    pe.resources[21].offset == 545936 and
    pe.resources[21].rva == 545936 and
    pe.resources[21].type == 4 and
    pe.resources[22].id == 139 and
    pe.resources[22].language == 1033 and
    pe.resources[22].length == 648 and
    pe.resources[22].offset == 546104 and
    pe.resources[22].rva == 546104 and
    pe.resources[22].type == 4 and
    pe.resources[23].id == 141 and
    pe.resources[23].language == 1033 and
    pe.resources[23].length == 312 and
    pe.resources[23].offset == 546752 and
    pe.resources[23].rva == 546752 and
    pe.resources[23].type == 4 and
    pe.resources[24].id == 144 and
    pe.resources[24].language == 1033 and
    pe.resources[24].length == 136 and
    pe.resources[24].offset == 547064 and
    pe.resources[24].rva == 547064 and
    pe.resources[24].type == 4 and
    pe.resources[25].id == 145 and
    pe.resources[25].language == 1033 and
    pe.resources[25].length == 128 and
    pe.resources[25].offset == 547360 and
    pe.resources[25].rva == 547360 and
    pe.resources[25].type == 4 and
    pe.resources[26].id == 146 and
    pe.resources[26].language == 1033 and
    pe.resources[26].length == 156 and
    pe.resources[26].offset == 547200 and
    pe.resources[26].rva == 547200 and
    pe.resources[26].type == 4 and
    pe.resources[27].id == 102 and
    pe.resources[27].language == 1033 and
    pe.resources[27].length == 1320 and
    pe.resources[27].offset == 547672 and
    pe.resources[27].rva == 547672 and
    pe.resources[27].type == 5 and
    pe.resources[28].id == 103 and
    pe.resources[28].language == 1033 and
    pe.resources[28].length == 1940 and
    pe.resources[28].offset == 548992 and
    pe.resources[28].rva == 548992 and
    pe.resources[28].type == 5 and
    pe.resources[29].id == 104 and
    pe.resources[29].language == 1033 and
    pe.resources[29].length == 2464 and
    pe.resources[29].offset == 550936 and
    pe.resources[29].rva == 550936 and
    pe.resources[29].type == 5 and
    pe.resources[30].id == 105 and
    pe.resources[30].language == 1033 and
    pe.resources[30].length == 1450 and
    pe.resources[30].offset == 553400 and
    pe.resources[30].rva == 553400 and
    pe.resources[30].type == 5 and
    pe.resources[31].id == 106 and
    pe.resources[31].language == 1033 and
    pe.resources[31].length == 2368 and
    pe.resources[31].offset == 564912 and
    pe.resources[31].rva == 564912 and
    pe.resources[31].type == 5 and
    pe.resources[32].id == 107 and
    pe.resources[32].language == 1033 and
    pe.resources[32].length == 2172 and
    pe.resources[32].offset == 554856 and
    pe.resources[32].rva == 554856 and
    pe.resources[32].type == 5 and
    pe.resources[33].id == 108 and
    pe.resources[33].language == 1033 and
    pe.resources[33].length == 1076 and
    pe.resources[33].offset == 557032 and
    pe.resources[33].rva == 557032 and
    pe.resources[33].type == 5 and
    pe.resources[34].id == 109 and
    pe.resources[34].language == 1033 and
    pe.resources[34].length == 928 and
    pe.resources[34].offset == 558112 and
    pe.resources[34].rva == 558112 and
    pe.resources[34].type == 5 and
    pe.resources[35].id == 110 and
    pe.resources[35].language == 1033 and
    pe.resources[35].length == 764 and
    pe.resources[35].offset == 559040 and
    pe.resources[35].rva == 559040 and
    pe.resources[35].type == 5 and
    pe.resources[36].id == 111 and
    pe.resources[36].language == 1033 and
    pe.resources[36].length == 1112 and
    pe.resources[36].offset == 559808 and
    pe.resources[36].rva == 559808 and
    pe.resources[36].type == 5 and
    pe.resources[37].id == 112 and
    pe.resources[37].language == 1033 and
    pe.resources[37].length == 1544 and
    pe.resources[37].offset == 560920 and
    pe.resources[37].rva == 560920 and
    pe.resources[37].type == 5 and
    pe.resources[38].id == 113 and
    pe.resources[38].language == 1033 and
    pe.resources[38].length == 644 and
    pe.resources[38].offset == 562464 and
    pe.resources[38].rva == 562464 and
    pe.resources[38].type == 5 and
    pe.resources[39].id == 114 and
    pe.resources[39].language == 1033 and
    pe.resources[39].length == 1500 and
    pe.resources[39].offset == 568720 and
    pe.resources[39].rva == 568720 and
    pe.resources[39].type == 5 and
    pe.resources[40].id == 118 and
    pe.resources[40].language == 1033 and
    pe.resources[40].length == 240 and
    pe.resources[40].offset == 573312 and
    pe.resources[40].rva == 573312 and
    pe.resources[40].type == 5 and
    pe.resources[41].id == 119 and
    pe.resources[41].language == 1033 and
    pe.resources[41].length == 266 and
    pe.resources[41].offset == 563112 and
    pe.resources[41].rva == 563112 and
    pe.resources[41].type == 5 and
    pe.resources[42].id == 124 and
    pe.resources[42].language == 1033 and
    pe.resources[42].length == 452 and
    pe.resources[42].offset == 563384 and
    pe.resources[42].rva == 563384 and
    pe.resources[42].type == 5 and
    pe.resources[43].id == 128 and
    pe.resources[43].language == 1033 and
    pe.resources[43].length == 532 and
    pe.resources[43].offset == 563840 and
    pe.resources[43].rva == 563840 and
    pe.resources[43].type == 5 and
    pe.resources[44].id == 132 and
    pe.resources[44].language == 1033 and
    pe.resources[44].length == 180 and
    pe.resources[44].offset == 547488 and
    pe.resources[44].rva == 547488 and
    pe.resources[44].type == 5 and
    pe.resources[45].id == 133 and
    pe.resources[45].language == 1033 and
    pe.resources[45].length == 530 and
    pe.resources[45].offset == 564376 and
    pe.resources[45].rva == 564376 and
    pe.resources[45].type == 5 and
    pe.resources[46].id == 137 and
    pe.resources[46].language == 1033 and
    pe.resources[46].length == 214 and
    pe.resources[46].offset == 567280 and
    pe.resources[46].rva == 567280 and
    pe.resources[46].type == 5 and
    pe.resources[47].id == 138 and
    pe.resources[47].language == 1033 and
    pe.resources[47].length == 466 and
    pe.resources[47].offset == 567496 and
    pe.resources[47].rva == 567496 and
    pe.resources[47].type == 5 and
    pe.resources[48].id == 140 and
    pe.resources[48].language == 1033 and
    pe.resources[48].length == 312 and
    pe.resources[48].offset == 567968 and
    pe.resources[48].rva == 567968 and
    pe.resources[48].type == 5 and
    pe.resources[49].id == 143 and
    pe.resources[49].language == 1033 and
    pe.resources[49].length == 438 and
    pe.resources[49].offset == 568280 and
    pe.resources[49].rva == 568280 and
    pe.resources[49].type == 5 and
    pe.resources[50].id == 144 and
    pe.resources[50].language == 1033 and
    pe.resources[50].length == 798 and
    pe.resources[50].offset == 570224 and
    pe.resources[50].rva == 570224 and
    pe.resources[50].type == 5 and
    pe.resources[51].id == 145 and
    pe.resources[51].language == 1033 and
    pe.resources[51].length == 826 and
    pe.resources[51].offset == 571024 and
    pe.resources[51].rva == 571024 and
    pe.resources[51].type == 5 and
    pe.resources[52].id == 146 and
    pe.resources[52].language == 1033 and
    pe.resources[52].length == 806 and
    pe.resources[52].offset == 571856 and
    pe.resources[52].rva == 571856 and
    pe.resources[52].type == 5 and
    pe.resources[53].id == 147 and
    pe.resources[53].language == 1033 and
    pe.resources[53].length == 648 and
    pe.resources[53].offset == 572664 and
    pe.resources[53].rva == 572664 and
    pe.resources[53].type == 5 and
    pe.resources[54].id == 10 and
    pe.resources[54].language == 1033 and
    pe.resources[54].length == 62 and
    pe.resources[54].offset == 579720 and
    pe.resources[54].rva == 579720 and
    pe.resources[54].type == 6 and
    pe.resources[55].id == 251 and
    pe.resources[55].language == 1033 and
    pe.resources[55].length == 968 and
    pe.resources[55].offset == 574248 and
    pe.resources[55].rva == 574248 and
    pe.resources[55].type == 6 and
    pe.resources[56].id == 252 and
    pe.resources[56].language == 1033 and
    pe.resources[56].length == 702 and
    pe.resources[56].offset == 575216 and
    pe.resources[56].rva == 575216 and
    pe.resources[56].type == 6 and
    pe.resources[57].id == 253 and
    pe.resources[57].language == 1033 and
    pe.resources[57].length == 1066 and
    pe.resources[57].offset == 575920 and
    pe.resources[57].rva == 575920 and
    pe.resources[57].type == 6 and
    pe.resources[58].id == 254 and
    pe.resources[58].language == 1033 and
    pe.resources[58].length == 710 and
    pe.resources[58].offset == 576992 and
    pe.resources[58].rva == 576992 and
    pe.resources[58].type == 6 and
    pe.resources[59].id == 255 and
    pe.resources[59].language == 1033 and
    pe.resources[59].length == 1444 and
    pe.resources[59].offset == 577704 and
    pe.resources[59].rva == 577704 and
    pe.resources[59].type == 6 and
    pe.resources[60].id == 256 and
    pe.resources[60].language == 1033 and
    pe.resources[60].length == 568 and
    pe.resources[60].offset == 579152 and
    pe.resources[60].rva == 579152 and
    pe.resources[60].type == 6 and
    pe.resources[61].id == 121 and
    pe.resources[61].language == 0 and
    pe.resources[61].length == 8 and
    pe.resources[61].offset == 524848 and
    pe.resources[61].rva == 524848 and
    pe.resources[61].type == 9 and
    pe.resources[62].id == 101 and
    pe.resources[62].language == 0 and
    pe.resources[62].length == 90 and
    pe.resources[62].offset == 536672 and
    pe.resources[62].rva == 536672 and
    pe.resources[62].type == 14 and
    pe.resources[63].id == 125 and
    pe.resources[63].language == 0 and
    pe.resources[63].length == 34 and
    pe.resources[63].offset == 538448 and
    pe.resources[63].rva == 538448 and
    pe.resources[63].type == 14 and
    pe.resources[64].id == 126 and
    pe.resources[64].language == 0 and
    pe.resources[64].length == 34 and
    pe.resources[64].offset == 540168 and
    pe.resources[64].rva == 540168 and
    pe.resources[64].type == 14 and
    pe.resources[65].id == 127 and
    pe.resources[65].language == 0 and
    pe.resources[65].length == 34 and
    pe.resources[65].offset == 541888 and
    pe.resources[65].rva == 541888 and
    pe.resources[65].type == 14 and
    pe.resources[66].id == 140 and
    pe.resources[66].language == 0 and
    pe.resources[66].length == 34 and
    pe.resources[66].offset == 543608 and
    pe.resources[66].rva == 543608 and
    pe.resources[66].type == 14 and
    pe.resources[67].id == 143 and
    pe.resources[67].language == 0 and
    pe.resources[67].length == 20 and
    pe.resources[67].offset == 544776 and
    pe.resources[67].rva == 544776 and
    pe.resources[67].type == 14 and
    pe.resources[68].id == 1 and
    pe.resources[68].language == 1033 and
    pe.resources[68].length == 888 and
    pe.resources[68].offset == 544800 and
    pe.resources[68].rva == 544800 and
    pe.resources[68].type == 16 and
    pe.resources[69].id == 1 and
    pe.resources[69].language == 0 and
    pe.resources[69].length == 1779 and
    pe.resources[69].offset == 524856 and
    pe.resources[69].rva == 524856 and
    pe.resources[69].type == 24 and
    pe.resources[70].id == 103 and
    pe.resources[70].language == 1033 and
    pe.resources[70].length == 282 and
    pe.resources[70].offset == 573920 and
    pe.resources[70].rva == 573920 and
    pe.resources[70].type == 240 and
    pe.resources[71].id == 104 and
    pe.resources[71].language == 1033 and
    pe.resources[71].length == 363 and
    pe.resources[71].offset == 573552 and
    pe.resources[71].rva == 573552 and
    pe.resources[71].type == 240)
 and
pe.rich_signature.clear_data == "\x44\x61\x6e\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x78\x95\x00\x17\x00\x00\x00\x09\x78\x83\x00\x70\x00\x00\x00\x09\x78\x84\x00\x3d\x00\x00\x00\x27\xc6\x7b\x00\x13\x00\x00\x00\x00\x00\x01\x00\x73\x01\x00\x00\x09\x78\x8a\x00\x1d\x00\x00\x00\x1e\x52\x94\x00\x01\x00\x00\x00\x09\x78\x91\x00\x01\x00\x00\x00" and
pe.rich_signature.key == 2021520790 and
pe.rich_signature.length == 80 and
pe.rich_signature.offset == 128 and
pe.rich_signature.raw_data == "\xd2\x94\x13\x2b\x96\xf5\x7d\x78\x96\xf5\x7d\x78\x96\xf5\x7d\x78\x9f\x8d\xe8\x78\x81\xf5\x7d\x78\x9f\x8d\xfe\x78\xe6\xf5\x7d\x78\x9f\x8d\xf9\x78\xab\xf5\x7d\x78\xb1\x33\x06\x78\x85\xf5\x7d\x78\x96\xf5\x7c\x78\xe5\xf4\x7d\x78\x9f\x8d\xf7\x78\x8b\xf5\x7d\x78\x88\xa7\xe9\x78\x97\xf5\x7d\x78\x9f\x8d\xec\x78\x97\xf5\x7d\x78" and
true
 and
true
 and
pe.section_alignment == 64 and
(
    pe.sections[0].characteristics == 1610612768 and
    pe.sections[0].full_name == ".text" and
    pe.sections[0].name == ".text" and
    pe.sections[0].number_of_line_numbers == 0 and
    pe.sections[0].number_of_relocations == 0 and
    pe.sections[0].pointer_to_line_numbers == 0 and
    pe.sections[0].pointer_to_relocations == 0 and
    pe.sections[0].raw_data_offset == 704 and
    pe.sections[0].raw_data_size == 240128 and
    pe.sections[0].virtual_address == 704 and
    pe.sections[0].virtual_size == 240083 and
    pe.sections[1].characteristics == 1073741888 and
    pe.sections[1].full_name == ".rdata" and
    pe.sections[1].name == ".rdata" and
    pe.sections[1].number_of_line_numbers == 0 and
    pe.sections[1].number_of_relocations == 0 and
    pe.sections[1].pointer_to_line_numbers == 0 and
    pe.sections[1].pointer_to_relocations == 0 and
    pe.sections[1].raw_data_offset == 240832 and
    pe.sections[1].raw_data_size == 227776 and
    pe.sections[1].virtual_address == 240832 and
    pe.sections[1].virtual_size == 227720 and
    pe.sections[2].characteristics == 3221225536 and
    pe.sections[2].full_name == ".data" and
    pe.sections[2].name == ".data" and
    pe.sections[2].number_of_line_numbers == 0 and
    pe.sections[2].number_of_relocations == 0 and
    pe.sections[2].pointer_to_line_numbers == 0 and
    pe.sections[2].pointer_to_relocations == 0 and
    pe.sections[2].raw_data_offset == 468608 and
    pe.sections[2].raw_data_size == 52416 and
    pe.sections[2].virtual_address == 468608 and
    pe.sections[2].virtual_size == 52356 and
    pe.sections[3].characteristics == 3221225536 and
    pe.sections[3].full_name == ".tls" and
    pe.sections[3].name == ".tls" and
    pe.sections[3].number_of_line_numbers == 0 and
    pe.sections[3].number_of_relocations == 0 and
    pe.sections[3].pointer_to_line_numbers == 0 and
    pe.sections[3].pointer_to_relocations == 0 and
    pe.sections[3].raw_data_offset == 521024 and
    pe.sections[3].raw_data_size == 64 and
    pe.sections[3].virtual_address == 521024 and
    pe.sections[3].virtual_size == 9 and
    pe.sections[4].characteristics == 1073741888 and
    pe.sections[4].full_name == ".rsrc" and
    pe.sections[4].name == ".rsrc" and
    pe.sections[4].number_of_line_numbers == 0 and
    pe.sections[4].number_of_relocations == 0 and
    pe.sections[4].pointer_to_line_numbers == 0 and
    pe.sections[4].pointer_to_relocations == 0 and
    pe.sections[4].raw_data_offset == 521088 and
    pe.sections[4].raw_data_size == 58752 and
    pe.sections[4].virtual_address == 521088 and
    pe.sections[4].virtual_size == 58696)
 and
pe.size_of_code == 240128 and
pe.size_of_headers == 704 and
pe.size_of_heap_commit == 4096 and
pe.size_of_heap_reserve == 1048576 and
pe.size_of_image == 579840 and
pe.size_of_initialized_data == 339008 and
pe.size_of_optional_header == 224 and
pe.size_of_stack_commit == 4096 and
pe.size_of_stack_reserve == 1048576 and
pe.size_of_uninitialized_data == 0 and
pe.subsystem == 2 and
pe.subsystem_version.major == 4 and
pe.subsystem_version.minor == 0 and
pe.timestamp == 1630564065 and
    pe.version_info["CompanyName"] == "Ladislav Zezula" and
    pe.version_info["FileDescription"] == "Interactive File System API Test" and
    pe.version_info["FileVersion"] == "2, 7, 0, 602" and
    pe.version_info["InternalName"] == "FileTest" and
    pe.version_info["LegalCopyright"] == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x31\x38\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info["LegalTrademarks"] == "http://www.zezula.net" and
    pe.version_info["OriginalFilename"] == "FileTest.exe" and
    pe.version_info["ProductName"] == "FileTest" and
    pe.version_info["ProductVersion"] == "2, 7, 0, 602" and
(
    pe.version_info_list[0].key == "CompanyName" and
    pe.version_info_list[0].value == "Ladislav Zezula" and
    pe.version_info_list[1].key == "FileDescription" and
    pe.version_info_list[1].value == "Interactive File System API Test" and
    pe.version_info_list[2].key == "FileVersion" and
    pe.version_info_list[2].value == "2, 7, 0, 602" and
    pe.version_info_list[3].key == "InternalName" and
    pe.version_info_list[3].value == "FileTest" and
    pe.version_info_list[4].key == "LegalCopyright" and
    pe.version_info_list[4].value == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x31\x38\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info_list[5].key == "LegalTrademarks" and
    pe.version_info_list[5].value == "http://www.zezula.net" and
    pe.version_info_list[6].key == "OriginalFilename" and
    pe.version_info_list[6].value == "FileTest.exe" and
    pe.version_info_list[7].key == "ProductName" and
    pe.version_info_list[7].value == "FileTest" and
    pe.version_info_list[8].key == "ProductVersion" and
    pe.version_info_list[8].value == "2, 7, 0, 602")
 and
pe.win32_version_value == 0
}"#,
        "tests/assets/yara_1561/Win32/FileTest_Alignment_40.exe",
        true,
    );
}

#[test]
fn test_coverage_1561_32_section1() {
    check_file(
        r#"import "pe"
rule test {
    condition:
pe.base_of_code == 4096 and
pe.base_of_data == 225280 and
pe.characteristics == 259 and
pe.checksum == 126903 and
(
    pe.data_directories[0].size == 0 and
    pe.data_directories[0].virtual_address == 0 and
    pe.data_directories[1].size == 180 and
    pe.data_directories[1].virtual_address == 238736 and
    pe.data_directories[2].size == 13200 and
    pe.data_directories[2].virtual_address == 225280 and
    pe.data_directories[3].size == 0 and
    pe.data_directories[3].virtual_address == 0 and
    pe.data_directories[4].size == 0 and
    pe.data_directories[4].virtual_address == 0 and
    pe.data_directories[5].size == 0 and
    pe.data_directories[5].virtual_address == 0 and
    pe.data_directories[6].size == 0 and
    pe.data_directories[6].virtual_address == 0 and
    pe.data_directories[7].size == 0 and
    pe.data_directories[7].virtual_address == 0 and
    pe.data_directories[8].size == 0 and
    pe.data_directories[8].virtual_address == 0 and
    pe.data_directories[9].size == 0 and
    pe.data_directories[9].virtual_address == 0 and
    pe.data_directories[10].size == 0 and
    pe.data_directories[10].virtual_address == 0 and
    pe.data_directories[11].size == 0 and
    pe.data_directories[11].virtual_address == 0 and
    pe.data_directories[12].size == 0 and
    pe.data_directories[12].virtual_address == 0 and
    pe.data_directories[13].size == 0 and
    pe.data_directories[13].virtual_address == 0 and
    pe.data_directories[14].size == 0 and
    pe.data_directories[14].virtual_address == 0 and
    pe.data_directories[15].size == 0 and
    pe.data_directories[15].virtual_address == 0)
 and
true and
pe.dll_characteristics == 0 and
pe.entry_point == 27 and
pe.entry_point_raw == 4123 and
pe.file_alignment == 512 and
pe.image_base == 4194304 and
pe.image_version.major == 0 and
pe.image_version.minor == 0 and
(
    (
        pe.import_details[0].functions[0].name == "LoadLibraryA" and
        pe.import_details[0].functions[0].rva == 238652 and
        pe.import_details[0].functions[1].name == "GetProcAddress" and
        pe.import_details[0].functions[1].rva == 238656 and
        pe.import_details[0].functions[2].name == "VirtualProtect" and
        pe.import_details[0].functions[2].rva == 238660 and
        pe.import_details[0].functions[3].name == "VirtualAlloc" and
        pe.import_details[0].functions[3].rva == 238664 and
        pe.import_details[0].functions[4].name == "VirtualFree" and
        pe.import_details[0].functions[4].rva == 238668 and
        pe.import_details[0].functions[5].name == "ExitProcess" and
        pe.import_details[0].functions[5].rva == 238672    )
 and
    pe.import_details[0].library_name == "KERNEL32.DLL" and
    pe.import_details[0].number_of_functions == 6 and
    (
        pe.import_details[1].functions[0].name == "DestroyAcceleratorTable" and
        pe.import_details[1].functions[0].rva == 238680    )
 and
    pe.import_details[1].library_name == "USER32.DLL" and
    pe.import_details[1].number_of_functions == 1 and
    (
        pe.import_details[2].functions[0].name == "GetUserNameW" and
        pe.import_details[2].functions[0].rva == 238688    )
 and
    pe.import_details[2].library_name == "ADVAPI32.DLL" and
    pe.import_details[2].number_of_functions == 1 and
    (
        pe.import_details[3].functions[0].name == "NtQueryEaFile" and
        pe.import_details[3].functions[0].rva == 238696    )
 and
    pe.import_details[3].library_name == "NTDLL.DLL" and
    pe.import_details[3].number_of_functions == 1 and
    (
        pe.import_details[4].functions[0].name == "PropertySheetW" and
        pe.import_details[4].functions[0].rva == 238704    )
 and
    pe.import_details[4].library_name == "COMCTL32.DLL" and
    pe.import_details[4].number_of_functions == 1 and
    (
        pe.import_details[5].functions[0].name == "GetFileVersionInfoSizeW" and
        pe.import_details[5].functions[0].rva == 238712    )
 and
    pe.import_details[5].library_name == "VERSION.DLL" and
    pe.import_details[5].number_of_functions == 1 and
    (
        pe.import_details[6].functions[0].name == "GetOpenFileNameW" and
        pe.import_details[6].functions[0].rva == 238720    )
 and
    pe.import_details[6].library_name == "COMDLG32.DLL" and
    pe.import_details[6].number_of_functions == 1 and
    (
        pe.import_details[7].functions[0].name == "SHGetPathFromIDListW" and
        pe.import_details[7].functions[0].rva == 238728    )
 and
    pe.import_details[7].library_name == "SHELL32.DLL" and
    pe.import_details[7].number_of_functions == 1)
 and
pe.is_pe == 1 and
pe.linker_version.major == 8 and
pe.linker_version.minor == 0 and
pe.loader_flags == 0 and
pe.machine == 332 and
pe.number_of_delayed_imported_functions == 0 and
pe.number_of_delayed_imports == 0 and
pe.number_of_exports == 0 and
pe.number_of_imported_functions == 13 and
pe.number_of_imports == 8 and
pe.number_of_resources == 29 and
pe.number_of_rva_and_sizes == 16 and
pe.number_of_sections == 2 and
pe.number_of_symbols == 0 and
pe.number_of_version_infos == 9 and
pe.opthdr_magic == 267 and
pe.os_version.major == 4 and
pe.os_version.minor == 0 and
pe.overlay.offset == 0 and
pe.overlay.size == 0 and
pe.pointer_to_symbol_table == 0 and
pe.resource_timestamp == 0 and
pe.resource_version.major == 0 and
pe.resource_version.minor == 0 and
(
    pe.resources[0].id == 7 and
    pe.resources[0].language == 1033 and
    pe.resources[0].length == 308 and
    pe.resources[0].rva == 209808 and
    pe.resources[0].type == 1 and
    pe.resources[1].id == 8 and
    pe.resources[1].language == 1033 and
    pe.resources[1].length == 308 and
    pe.resources[1].rva == 210116 and
    pe.resources[1].type == 1 and
    pe.resources[2].id == 1 and
    pe.resources[2].language == 1033 and
    pe.resources[2].length == 1640 and
    pe.resources[2].offset == 3680 and
    pe.resources[2].rva == 228448 and
    pe.resources[2].type == 3 and
    pe.resources[3].id == 2 and
    pe.resources[3].language == 1033 and
    pe.resources[3].length == 296 and
    pe.resources[3].offset == 5320 and
    pe.resources[3].rva == 230088 and
    pe.resources[3].type == 3 and
    pe.resources[4].id == 3 and
    pe.resources[4].language == 1033 and
    pe.resources[4].length == 744 and
    pe.resources[4].offset == 5616 and
    pe.resources[4].rva == 230384 and
    pe.resources[4].type == 3 and
    pe.resources[5].id == 4 and
    pe.resources[5].language == 1033 and
    pe.resources[5].length == 1384 and
    pe.resources[5].offset == 6360 and
    pe.resources[5].rva == 231128 and
    pe.resources[5].type == 3 and
    pe.resources[6].id == 5 and
    pe.resources[6].language == 1033 and
    pe.resources[6].length == 2216 and
    pe.resources[6].offset == 7744 and
    pe.resources[6].rva == 232512 and
    pe.resources[6].type == 3 and
    pe.resources[7].id == 6 and
    pe.resources[7].language == 1033 and
    pe.resources[7].length == 3752 and
    pe.resources[7].offset == 9960 and
    pe.resources[7].rva == 234728 and
    pe.resources[7].type == 3 and
    pe.resources[8].id == 101 and
    pe.resources[8].language == 1033 and
    pe.resources[8].length == 1438 and
    pe.resources[8].rva == 210424 and
    pe.resources[8].type == 5 and
    pe.resources[9].id == 109 and
    pe.resources[9].language == 1033 and
    pe.resources[9].length == 1976 and
    pe.resources[9].rva == 211864 and
    pe.resources[9].type == 5 and
    pe.resources[10].id == 111 and
    pe.resources[10].language == 1033 and
    pe.resources[10].length == 132 and
    pe.resources[10].rva == 213840 and
    pe.resources[10].type == 5 and
    pe.resources[11].id == 112 and
    pe.resources[11].language == 1033 and
    pe.resources[11].length == 806 and
    pe.resources[11].rva == 213972 and
    pe.resources[11].type == 5 and
    pe.resources[12].id == 113 and
    pe.resources[12].language == 1033 and
    pe.resources[12].length == 1054 and
    pe.resources[12].rva == 214780 and
    pe.resources[12].type == 5 and
    pe.resources[13].id == 115 and
    pe.resources[13].language == 1033 and
    pe.resources[13].length == 1934 and
    pe.resources[13].rva == 215836 and
    pe.resources[13].type == 5 and
    pe.resources[14].id == 117 and
    pe.resources[14].language == 1033 and
    pe.resources[14].length == 768 and
    pe.resources[14].rva == 217772 and
    pe.resources[14].type == 5 and
    pe.resources[15].id == 118 and
    pe.resources[15].language == 1033 and
    pe.resources[15].length == 452 and
    pe.resources[15].rva == 218540 and
    pe.resources[15].type == 5 and
    pe.resources[16].id == 119 and
    pe.resources[16].language == 1033 and
    pe.resources[16].length == 972 and
    pe.resources[16].rva == 218992 and
    pe.resources[16].type == 5 and
    pe.resources[17].id == 120 and
    pe.resources[17].language == 1033 and
    pe.resources[17].length == 1420 and
    pe.resources[17].rva == 219964 and
    pe.resources[17].type == 5 and
    pe.resources[18].id == 251 and
    pe.resources[18].language == 1033 and
    pe.resources[18].length == 374 and
    pe.resources[18].rva == 221384 and
    pe.resources[18].type == 6 and
    pe.resources[19].id == 252 and
    pe.resources[19].language == 1033 and
    pe.resources[19].length == 846 and
    pe.resources[19].rva == 221760 and
    pe.resources[19].type == 6 and
    pe.resources[20].id == 253 and
    pe.resources[20].language == 1033 and
    pe.resources[20].length == 1230 and
    pe.resources[20].rva == 222608 and
    pe.resources[20].type == 6 and
    pe.resources[21].id == 115 and
    pe.resources[21].language == 0 and
    pe.resources[21].length == 8 and
    pe.resources[21].rva == 223840 and
    pe.resources[21].type == 9 and
    pe.resources[22].id == 103 and
    pe.resources[22].language == 1033 and
    pe.resources[22].length == 20 and
    pe.resources[22].rva == 223848 and
    pe.resources[22].type == 12 and
    pe.resources[23].id == 104 and
    pe.resources[23].language == 1033 and
    pe.resources[23].length == 20 and
    pe.resources[23].rva == 223868 and
    pe.resources[23].type == 12 and
    pe.resources[24].id == 102 and
    pe.resources[24].language == 1033 and
    pe.resources[24].length == 90 and
    pe.resources[24].offset == 2160 and
    pe.resources[24].rva == 226928 and
    pe.resources[24].type == 14 and
    pe.resources[25].id == 1 and
    pe.resources[25].language == 1029 and
    pe.resources[25].length == 880 and
    pe.resources[25].offset == 2252 and
    pe.resources[25].rva == 227020 and
    pe.resources[25].type == 16 and
    pe.resources[26].id == 1 and
    pe.resources[26].language == 1033 and
    pe.resources[26].length == 545 and
    pe.resources[26].offset == 3132 and
    pe.resources[26].rva == 227900 and
    pe.resources[26].type == 24 and
    pe.resources[27].id == 101 and
    pe.resources[27].language == 1033 and
    pe.resources[27].length == 261 and
    pe.resources[27].rva == 223888 and
    pe.resources[27].type == 240 and
    pe.resources[28].id == 109 and
    pe.resources[28].language == 1033 and
    pe.resources[28].length == 339 and
    pe.resources[28].rva == 224152 and
    pe.resources[28].type == 240)
 and
pe.section_alignment == 4096 and
(
    pe.sections[0].characteristics == 3758096480 and
    pe.sections[0].full_name == "nsp0" and
    pe.sections[0].name == "nsp0" and
    pe.sections[0].number_of_line_numbers == 0 and
    pe.sections[0].number_of_relocations == 0 and
    pe.sections[0].pointer_to_line_numbers == 0 and
    pe.sections[0].pointer_to_relocations == 0 and
    pe.sections[0].raw_data_offset == 303 and
    pe.sections[0].raw_data_size == 60 and
    pe.sections[0].virtual_address == 4096 and
    pe.sections[0].virtual_size == 221184 and
    pe.sections[1].characteristics == 3758096480 and
    pe.sections[1].full_name == "nsp1" and
    pe.sections[1].name == "nsp1" and
    pe.sections[1].number_of_line_numbers == 0 and
    pe.sections[1].number_of_relocations == 0 and
    pe.sections[1].pointer_to_line_numbers == 0 and
    pe.sections[1].pointer_to_relocations == 0 and
    pe.sections[1].raw_data_offset == 512 and
    pe.sections[1].raw_data_size == 71285 and
    pe.sections[1].virtual_address == 225280 and
    pe.sections[1].virtual_size == 79380)
 and
pe.size_of_code == 0 and
pe.size_of_headers == 4096 and
pe.size_of_heap_commit == 4096 and
pe.size_of_heap_reserve == 1048576 and
pe.size_of_image == 307200 and
pe.size_of_initialized_data == 73728 and
pe.size_of_optional_header == 224 and
pe.size_of_stack_commit == 4096 and
pe.size_of_stack_reserve == 1048576 and
pe.size_of_uninitialized_data == 221184 and
pe.subsystem == 2 and
pe.subsystem_version.major == 4 and
pe.subsystem_version.minor == 0 and
pe.timestamp == 1165587907 and
    pe.version_info["CompanyName"] == "Ladislav Zezula" and
    pe.version_info["FileDescription"] == "Interactive File System Test" and
    pe.version_info["FileVersion"] == "1, 7, 0, 129" and
    pe.version_info["InternalName"] == "FileTest" and
    pe.version_info["LegalCopyright"] == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x30\x35\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info["LegalTrademarks"] == "http://www.zezula.net" and
    pe.version_info["OriginalFilename"] == "FileTest.exe" and
    pe.version_info["ProductName"] == "FileTest" and
    pe.version_info["ProductVersion"] == "1, 7, 0, 129" and
(
    pe.version_info_list[0].key == "CompanyName" and
    pe.version_info_list[0].value == "Ladislav Zezula" and
    pe.version_info_list[1].key == "FileDescription" and
    pe.version_info_list[1].value == "Interactive File System Test" and
    pe.version_info_list[2].key == "FileVersion" and
    pe.version_info_list[2].value == "1, 7, 0, 129" and
    pe.version_info_list[3].key == "InternalName" and
    pe.version_info_list[3].value == "FileTest" and
    pe.version_info_list[4].key == "LegalCopyright" and
    pe.version_info_list[4].value == "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\xa9\x20\x32\x30\x30\x34\x20\x2d\x20\x32\x30\x30\x35\x20\x4c\x61\x64\x69\x73\x6c\x61\x76\x20\x5a\x65\x7a\x75\x6c\x61" and
    pe.version_info_list[5].key == "LegalTrademarks" and
    pe.version_info_list[5].value == "http://www.zezula.net" and
    pe.version_info_list[6].key == "OriginalFilename" and
    pe.version_info_list[6].value == "FileTest.exe" and
    pe.version_info_list[7].key == "ProductName" and
    pe.version_info_list[7].value == "FileTest" and
    pe.version_info_list[8].key == "ProductVersion" and
    pe.version_info_list[8].value == "1, 7, 0, 129")
 and
pe.win32_version_value == 0
}"#,
        "tests/assets/yara_1561/Win32/FileTest_Section1_Starts_at_header.exe",
        true,
    );
}
