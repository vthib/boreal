use boreal::module::Pe;

use crate::utils::{check_file, compare_module_values_on_file};

#[test]
// FIXME: Broken compat with YARA 4.5.1
#[ignore]
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
    test(file1, r#"pe.imports("user32.dll", "killtimer") == 1"#);
    test(file1, r#"pe.imports("user32.dll", 3) == 0"#);
    // delayed imports are not found
    test(file2, r#"pe.imports("OLEAUT32.dll", "VariantInit") == 0"#);

    // dll_name, ordinal
    test(file1, r#"pe.imports("PtDMDecode.dll", 3) == 1"#);
    test(file1, r#"pe.imports("PtDMDecode.dll", 2) == 0"#);
    test(file1, r#"pe.imports("KERNEL32.dll", 2) == 0"#);
    test(file1, r#"pe.imports("PtImageRW.dll", 7) == 1"#);
    test(file1, r#"pe.imports("ptimagerW.dLL", 7) == 1"#);
    // delayed imports are not found
    test(file2, r#"pe.imports("OLEAUT32.dll", 8) == 0"#);

    // dll_name
    test(file1, r#"pe.imports("KERNEL32.dll") == 127"#);
    test(file1, r#"pe.imports("kernel32.DLL") == 127"#);
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
        r#"pe.imports(pe.IMPORT_STANDARD, "kerNEL32.Dll", "exitPRocesS") == 1"#,
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
        r#"pe.imports(pe.IMPORT_DELAYED, "oleaut32.DLL", "VariantINIT") == 1"#,
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
    test(
        file2,
        r#"pe.imports(pe.IMPORT_STANDARD, "kernel32.DLL") == 69"#,
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
        r#"pe.imports(pe.IMPORT_DELAYED, "OLEaut32.DLL", 8) == 1"#,
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
fn test_import_rva() {
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
    test(
        file1,
        r#"pe.import_rva("KERNEL32.dll", "ExitProcess") == 254348"#,
    );
    test(
        file1,
        r#"not defined pe.import_rva("USER32.dll", "ExitProcess")"#,
    );
    test(
        file1,
        r#"pe.import_rva("USER32.dll", "KillTimer") == 255012"#,
    );
    test(
        file1,
        r#"pe.import_rva("user32.dll", "killtimer") == 255012"#,
    );
    test(file1, r#"not defined pe.import_rva("user32.dll", 3)"#);
    // delayed imports are not found
    test(
        file2,
        r#"not defined pe.import_rva("OLEAUT32.dll", "VariantInit")"#,
    );

    // dll_name, ordinal
    test(file1, r#"pe.import_rva("PtDMDecode.dll", 3) == 254904"#);
    test(file1, r#"not defined pe.import_rva("PtDMDecode.dll", 2)"#);
    test(file1, r#"not defined pe.import_rva("KERNEL32.dll", 2)"#);
    test(file1, r#"pe.import_rva("PtImageRW.dll", 7) == 254928"#);
    test(file1, r#"pe.import_rva("ptimagerW.dLL", 7) == 254928"#);
    // delayed imports are not found
    test(file2, r#"not defined pe.import_rva("OLEAUT32.dll", 8)"#);

    // delayed dll_name, function_name
    test(
        file1,
        r#"not defined pe.delayed_import_rva("KERNEL32.dll", "ExitProcess")"#,
    );
    test(
        file2,
        r#"pe.delayed_import_rva("OLEAUT32.dll", "VariantInit") == 80000"#,
    );
    test(
        file2,
        r#"pe.delayed_import_rva("oleaut32.DLL", "VariantINIT") == 80000"#,
    );
    test(
        file2,
        r#"not defined pe.delayed_import_rva("oleaut32.DLL", "VariantINI")"#,
    );
    test(
        file2,
        r#"not defined pe.delayed_import_rva("oleaut32", "VariantInit")"#,
    );

    // import_flag, dll_name, ordinal
    test(
        file2,
        r#"pe.delayed_import_rva("OLEAUT32.dll", 411) == 80004"#,
    );
    test(
        file2,
        r#"not defined pe.delayed_import_rva("OLEAUT32.dll", 7)"#,
    );
    test(
        file2,
        r#"pe.delayed_import_rva("OLEAUT32.dll", 8) == 80000"#,
    );
    test(
        file2,
        r#"pe.delayed_import_rva("OLEaut32.DLL", 8) == 80000"#,
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

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_ord_and_delay() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/pe/ord_and_delay.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_resources_only() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/pe/resources_only.dll";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_079a472d() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.signatures",
        #[cfg(not(feature = "authenticode-verify"))]
        "pe.is_signed",
        #[cfg(all(feature = "authenticode", not(feature = "authenticode-verify")))]
        "pe.signatures[0].verified",
        #[cfg(all(feature = "authenticode", not(feature = "authenticode-verify")))]
        "pe.signatures[0].countersignatures[0].verified",
    ];
    let path = "tests/assets/libyara/data/\
        079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885";

    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_079a472d_upx() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/\
        079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.upx";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_0ca09bde() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/\
        0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_33fc70f9() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/\
        33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_3b8b9015() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.signatures",
        #[cfg(not(feature = "authenticode-verify"))]
        "pe.is_signed",
        #[cfg(all(feature = "authenticode", not(feature = "authenticode-verify")))]
        "pe.signatures[0].verified",
        #[cfg(all(feature = "authenticode", not(feature = "authenticode-verify")))]
        "pe.signatures[1].verified",
        #[cfg(all(feature = "authenticode", not(feature = "authenticode-verify")))]
        "pe.signatures[0].countersignatures[0].verified",
        #[cfg(all(feature = "authenticode", not(feature = "authenticode-verify")))]
        "pe.signatures[1].countersignatures[0].verified",
    ];
    let path = "tests/assets/libyara/data/\
        3b8b90159fa9b6048cc5410c5d53f116943564e4d05b04a843f9b3d0540d0c1c";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_ca21e1c32() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/\
        ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_mtxex() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/mtxex.dll";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_mtxex_modified() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/mtxex_modified_rsrc_rva.dll";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &[]);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_pe_imports() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/pe_imports";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_pe_mingw() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/pe_mingw";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_tiny() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/tiny";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_tiny_51ff() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/tiny-idata-51ff";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_tiny_5200() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/tiny-idata-5200";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_libyara_tiny_overlay() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/tiny-overlay";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_1561_std() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/yara_1561/x64/FileTest.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_1561_align_40() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/yara_1561/x64/FileTest_alignment_40.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_1561_32_align_40() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/yara_1561/Win32/FileTest_Alignment_40.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_1561_32_section1() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/yara_1561/Win32/FileTest_Section1_Starts_at_header.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_c6f9709f() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/libyara/data/\
         c6f9709feccf42f2d9e22057182fe185f177fb9daaa2649b4669a24f2ee7e3ba_0h_410h";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_long_name_exporter() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/pe/long_name_exporter.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_long_dll_name() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/pe/long_dll_name.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_long_name_importer() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/pe/long_name_importer.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
}

#[test]
#[cfg(feature = "hash")]
fn test_coverage_pe_invalid_dll_names() {
    let diffs = [
        #[cfg(not(feature = "authenticode"))]
        "pe.number_of_signatures",
        #[cfg(not(feature = "authenticode"))]
        "pe.is_signed",
    ];
    let path = "tests/assets/pe/invalid_dll_names.exe";
    compare_module_values_on_file(Pe, path, false, &diffs);
    compare_module_values_on_file(Pe, path, true, &diffs);
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
#[cfg(feature = "authenticode-verify")]
fn test_signatures_verify() {
    let mut checker = crate::utils::Checker::new(
        "import \"pe\"
      rule test {
        condition: pe.is_signed
      }",
    );

    let diffs = [];

    for name in [
        // DSA
        "dsa_sha1",
        "dsa_sha256",
        // elliptic curves
        "ec_p256_sha1",
        "ec_p256_sha256",
        "ec_p256_sha384",
        "ec_p256_sha512",
        // TODO: this one does not verify, investigate why
        // "ec_p384_sha1",
        "ec_p384_sha256",
        "ec_p384_sha384",
        "ec_p384_sha512",
        // Not supported by the p521 crate yet, next release probably
        // "ec_p521_sha1",
        // "ec_p521_sha256",
        // "ec_p521_sha384",
        // "ec_p521_sha512",
        // RSA
        "rsa_md5",
        "rsa_sha1",
        "rsa_sha256",
        "rsa_sha384",
        "rsa_sha512",
    ] {
        let path = format!("tests/assets/pe/signed/{name}.exe");

        let mem = std::fs::read(&path).unwrap();

        println!("checking {}...", &path);
        // File should be considered signed
        checker.check(&mem, true);

        // Check full coverage
        compare_module_values_on_file(Pe, &path, false, &diffs);
    }
}
