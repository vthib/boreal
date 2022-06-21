use crate::utils::{check, check_file};

#[test]
fn test_pe() {
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "assets/libyara/data/tiny",
        true,
    );

    // TODO: handle malformed section offsets */
    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\")
    //   }",
    //     "assets/libyara/data/tiny-idata-51ff",
    //     true,
    // );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "assets/libyara/data/tiny-idata-5200",
        false,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(/.*/, /.*CriticalSection/) == 4
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(/kernel32\\.dll/i, /.*/) == 21
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(/.*/, /.*/)
      }",
        "assets/libyara/data/tiny-idata-5200",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(/.*/, /.*CriticalSection/)
      }",
        "assets/libyara/data/tiny-idata-5200",
        false,
    );

    ///////////////////////////////

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, \"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "assets/libyara/data/tiny",
        true,
    );

    // TODO: handle malformed section offsets */
    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_STANDARD, \"KERNEL32.dll\", \"DeleteCriticalSection\")
    //   }",
    //     "assets/libyara/data/tiny-idata-51ff",
    //     true,
    // );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, \"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "assets/libyara/data/tiny-idata-5200",
        false,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, /.*/, /.*CriticalSection/) == 4
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, /kernel32\\.dll/i, /.*/) == 21
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, /.*/, /.*/)
      }",
        "assets/libyara/data/tiny-idata-5200",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, /.*/, /.*CriticalSection/)
      }",
        "assets/libyara/data/tiny-idata-5200",
        false,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_imports == 2 and
          pe.number_of_imported_functions == 48
      }",
        "assets/libyara/data/tiny",
        true,
    );

    // TODO: handle delayed imports
    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_DELAYED, \"USER32.dll\", \"MessageBoxA\")
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //         pe.imports(pe.IMPORT_DELAYED, \"KERNEL32.dll\", \"DeleteCriticalSection\")
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     false,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_DELAYED, /.*/, /Message.*/) == 2
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_DELAYED, /USER32\\.dll/i, /.*BoxA/) == 1
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_DELAYED, /.*/, /.*CriticalSection/)
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     false,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.number_of_delayed_imports == 1 and
    //       pe.number_of_delayed_imported_functions == 2
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, \"KERNEL32.dll\", \"DeleteCriticalSection\") and
    //       pe.imports(pe.IMPORT_ANY, \"USER32.dll\", \"MessageBoxA\")
    //   }",
    //     "assets/libyara/data/pe_imports",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, \"KERNEL32.dll\", \"DeleteCriticalSection\")
    //   }",
    //     "assets/libyara/data/tiny-idata-51ff",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, \"KERNEL32.dll\", \"DeleteCriticalSection\")
    //   }",
    //     "assets/libyara/data/tiny-idata-5200",
    //     false,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, /.*/, /.*CriticalSection/) == 4
    //   }",
    //     "assets/libyara/data/tiny",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, /kernel32\\.dll/i, /.*/) == 21
    //   }",
    //     "assets/libyara/data/tiny",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, /.*/, /.*/)
    //   }",
    //     "assets/libyara/data/tiny-idata-5200",
    //     true,
    // );

    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.imports(pe.IMPORT_ANY, /.*/, /.*CriticalSection/)
    //   }",
    //     "assets/libyara/data/tiny-idata-5200",
    //     false,
    // );

    check(
        "import \"pe\"
      rule test {
        condition:
          (
            pe.IMPORT_ANY & (pe.IMPORT_STANDARD | pe.IMPORT_DELAYED)
          ) == (pe.IMPORT_STANDARD | pe.IMPORT_DELAYED)
      }",
        b"",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_sections == 7
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.entry_point == 0x14E0
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.entry_point_raw == 0x1380
      }",
        "assets/libyara/data/mtxex.dll",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.linker_version.major == 2 and
          pe.linker_version.minor == 26
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.sections[0].name == \".text\" and
          pe.sections[1].name == \".data\" and
          pe.sections[2].name == \".rdata\" and
          pe.sections[3].name == \".bss\" and
          pe.sections[4].name == \".idata\" and
          pe.sections[5].name == \".CRT\" and
          pe.sections[6].name == \".tls\"
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.imphash() == \"1720bf764274b7a4052bbef0a71adc0d\"
        }",
        "assets/libyara/data/tiny",
        true,
    );

    // TODO: thumbprint
    /*
    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.number_of_signatures == 1 and
            pe.signatures[0].thumbprint == \"c1bf1b8f751bf97626ed77f755f0a393106f2454\" and
            pe.signatures[0].subject == \"/C=US/ST=California/L=Menlo Park/O=Quicken, Inc./OU=Operations/CN=Quicken, Inc.\"
        }",
        "assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885", true);

    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.number_of_signatures == 2
        }",
        "assets/libyara/data/3b8b90159fa9b6048cc5410c5d53f116943564e4d05b04a843f9b3d0540d0c1c", true);
      */

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.section_index(\".text\") == 0
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.section_index(pe.entry_point) == 0
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.is_32bit() and not pe.is_64bit()
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.checksum == 0xA8DC
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.checksum == pe.calculate_checksum()
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.overlay.offset == 0x8000 and pe.overlay.size == 7
      }",
        "assets/libyara/data/tiny-overlay",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.overlay.offset == 0 and pe.overlay.size == 0
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        r#"import "pe"
      rule test {
        condition:
          pe.pdb_path == "D:\\workspace\\2018_R9_RelBld\\target\\checkout\\custprof\\Release\\custprof.pdb"
      }"#,
        "assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    // TODO: improve handling of debug directory
    // check_file(
    //   "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.pdb_path == \"/Users/runner/work/OpenCorePkg/OpenCorePkg/UDK/Build/OpenCorePkg/DEBUG_XCODE5/X64/OpenCorePkg/Application/ChipTune/ChipTune/DEBUG/ChipTune.dll\"
    //   }",
    //   "assets/libyara/data/ChipTune.efi", true);

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.checksum == pe.calculate_checksum()
      }",
        "assets/libyara/data/tiny-idata-51ff",
        false,
    );

    /*
     * mtxex.dll is
     * 23e72ce7e9cdbc80c0095484ebeb02f56b21e48fd67044e69e7a2ae76db631e5, which was
     * taken from a Windows 10 install. The details of which are: export_timestamp
     * = 1827812126 dll_name = "mtxex.dll" number_of_exports = 4 export_details
     *            [0]
     *                    offset = 1072
     *                    name = "DllGetClassObject"
     *                    forward_name = YR_UNDEFINED
     *                    ordinal = 1
     *            [1]
     *                    offset = YR_UNDEFINED
     *                    name = "GetObjectContext"
     *                    forward_name = "COMSVCS.GetObjectContext"
     *                    ordinal = 2
     *            [2]
     *                    offset = YR_UNDEFINED
     *                    name = "MTSCreateActivity"
     *                    forward_name = "COMSVCS.MTSCreateActivity"
     *                    ordinal = 3
     *            [3]
     *                    offset = YR_UNDEFINED
     *                    name = "SafeRef"
     *                    forward_name = "COMSVCS.SafeRef"
     *                    ordinal = 4
     */
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_exports == 4 and
          pe.dll_name == \"mtxex.dll\" and
          pe.export_timestamp == 1827812126 and
          pe.export_details[0].offset == 1072 and
          pe.export_details[0].name == \"DllGetClassObject\" and
          pe.export_details[0].ordinal == 1 and
          pe.export_details[1].forward_name == \"COMSVCS.GetObjectContext\"
      }",
        "assets/libyara/data/mtxex.dll",
        true,
    );
    /*
     * mtxex_modified_rsrc_rva.dll is a modified copy of mtxex.dll from a Windows
     * 10 install. The modification was to change the RVA of the only resource to
     * be invalid (it was changed to be 0x41585300), to ensure we are still
     * parsing resources even if the RVA does not have a corresponding file
     * offset.
     */
    // TODO: handle this
    // check_file(
    //     "import \"pe\"
    //   rule test {
    //     condition:
    //       pe.number_of_resources == 1 and
    //       pe.resources[0].rva == 5462081 and
    //       pe.resources[0].length == 888
    //   }",
    //     "assets/libyara/data/mtxex_modified_rsrc_rva.dll",
    //     true,
    // );

    // Make sure exports function is case insensitive (historically this has been
    // the case) and supports ordinals...
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.exports(\"saferef\") and
          pe.exports(4) and
          pe.exports(/mtscreateactivity/i)
      }",
        "assets/libyara/data/mtxex.dll",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.exports_index(\"MTSCreateActivity\") == 2 and
          pe.exports_index(3) == 2 and
          pe.exports_index(/mtscreateactivity/i) == 2
      }",
        "assets/libyara/data/mtxex.dll",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.export_details[0].name == \"CP_PutItem\"
      }",
        "assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.upx",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.rich_signature.toolid(157, 40219) == 1 and
          pe.rich_signature.toolid(1, 0) > 40 and pe.rich_signature.toolid(1, 0) < 45 and
          pe.rich_signature.version(30319) and
          pe.rich_signature.version(40219, 170) == 11
      }",
        "assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    // This is the first 840 bytes (just enough to make sure the rich header is
    // parsed) of
    // 3593d3d08761d8ddc269dde945c0cb07e5cef5dd46ad9eefc22d17901f542093.
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.rich_signature.offset == 0x200 and
          pe.rich_signature.length == 64 and
          pe.rich_signature.key == 0x9f1d8511 and
          pe.rich_signature.clear_data == \"DanS\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\
\\x00\\x00\\x00\\x00\\x01\\x00\\x11\\x00\\x00\\x00\\xc3\\x0f]\\x00\\x03\\x00\\x00\\x00\\x09x\\x95\
\\x00\\x01\\x00\\x00\\x00\\x09x\\x83\\x00\\x05\\x00\\x00\\x00\\x09x\\x94\\x00\\x01\\x00\\x00\\x00\
\\x09x\\x91\\x00\\x01\\x00\\x00\\x00\"
      }",
        "assets/libyara/data/weird_rich",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.language(0x09) and pe.locale(0x0409)
      }",
        "assets/libyara/data/mtxex.dll",
        true,
    );

    check_file(
        "import \"pe\"
      rule version_info_catch
      {
          condition:
            pe.number_of_version_infos  > 2 and
            for any version in pe.version_info_list : (
              version.key == \"FileVersion\" and
              version.value == \"27.1.9.33\"
          )
      }",
        "assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    check_file(
        "import \"pe\"
      rule iequals_comparison {
        condition:
          pe.sections[0].name != \".TEXT\" and
          pe.sections[0].name iequals \".TEXT\"
      }",
        "assets/libyara/data/tiny",
        true,
    );

    // TODO: handle imbricated iterators
    // check_file(
    //     "import \"pe\"

    //   rule import_details_catch
    //   {
    //       condition:
    //         for any import_detail in pe.import_details: (
    //             import_detail.library_name == \"MSVCR100.dll\" and
    //             for any function in import_detail.functions : (
    //                 function.name == \"_initterm\"
    //             )
    //         )
    //   }",
    //     "assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
    //     true,
    // );

    check_file(
        "import \"pe\"

      rule zero_length_version_info_value
      {
          condition:
            pe.number_of_version_infos == 12 and
            pe.version_info[\"Comments\"] == \"\" and
            pe.version_info[\"CompanyName\"] == \"\" and
            pe.version_info[\"LegalTrademarks\"] == \"\" and
            pe.version_info[\"PrivateBuild\"] == \"\" and
            pe.version_info[\"SpecialBuild\"] == \"\"
      }",
        "assets/libyara/data/ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386",
        true,
    );

    check_file(
        "import \"pe\"
      rule section_name_comparison {
        condition:
          for all section in pe.sections : (
              section.name == section.full_name
          )
      }",
        "assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule section_name_comparison {
        condition:
          for any section in pe.sections : (
              section.name == \"/4\" and
              section.full_name == \".debug_aranges\"
          )
      }",
        "assets/libyara/data/pe_mingw",
        true,
    );
}
