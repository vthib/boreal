use crate::utils::{check, check_file};

#[test]
fn test_pe() {
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(\"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "tests/assets/libyara/data/tiny-idata-51ff",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_imports == 0 and pe.number_of_imported_functions == 0
      }",
        "tests/assets/libyara/data/tiny-idata-5200",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(/.*/, /.*CriticalSection/) == 4
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(/kernel32\\.dll/i, /.*/) == 21
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    ///////////////////////////////

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, \"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, \"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "tests/assets/libyara/data/tiny-idata-51ff",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, /.*/, /.*CriticalSection/) == 4
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_STANDARD, /kernel32\\.dll/i, /.*/) == 21
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_imports == 2 and
          pe.number_of_imported_functions == 48
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_DELAYED, \"USER32.dll\", \"MessageBoxA\")
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
            pe.imports(pe.IMPORT_DELAYED, \"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "tests/assets/libyara/data/pe_imports",
        false,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_DELAYED, /.*/, /Message.*/) == 2
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_DELAYED, /USER32\\.dll/i, /.*BoxA/) == 1
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_DELAYED, /.*/, /.*CriticalSection/)
      }",
        "tests/assets/libyara/data/pe_imports",
        false,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_delayed_imports == 1 and
          pe.number_of_delayed_imported_functions == 2
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_ANY, \"KERNEL32.dll\", \"DeleteCriticalSection\") and
          pe.imports(pe.IMPORT_ANY, \"USER32.dll\", \"MessageBoxA\")
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_ANY, \"KERNEL32.dll\", \"DeleteCriticalSection\")
      }",
        "tests/assets/libyara/data/tiny-idata-51ff",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_ANY, /.*/, /.*CriticalSection/) == 4
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imports(pe.IMPORT_ANY, /kernel32\\.dll/i, /.*/) == 21
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

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
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.entry_point == 0x14E0
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.entry_point_raw == 0x1380
      }",
        "tests/assets/libyara/data/mtxex.dll",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.linker_version.major == 2 and
          pe.linker_version.minor == 26
      }",
        "tests/assets/libyara/data/tiny",
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
        "tests/assets/libyara/data/tiny",
        true,
    );

    #[cfg(feature = "hash")]
    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.imphash() == \"1720bf764274b7a4052bbef0a71adc0d\"
        }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    // Make sure imports with no ordinal and an empty name are skipped. This is
    // consistent with the behavior of pefile.
    #[cfg(feature = "hash")]
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.imphash() == \"b441b7fd09648ae6a06cea0e090128d6\"
      }",
        "tests/assets/libyara/data/tiny_empty_import_name",
        true,
    );

    #[cfg(feature = "hash")]
    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.imphash() == \"d49b7870cb53f29ec3f42b11cc8bea8b\"
        }",
        "tests/assets/libyara/data/e3d45a2865818756068757d7e319258fef40dad54532ee4355b86bc129f27345",
        true
    ) ;

    #[cfg(feature = "authenticode-verify")]
    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.is_signed and
            pe.number_of_signatures == 1 and
            pe.signatures[0].thumbprint == \"c1bf1b8f751bf97626ed77f755f0a393106f2454\" and
            pe.signatures[0].subject == \"/C=US/ST=California/L=Menlo Park/O=Quicken, Inc./OU=Operations/CN=Quicken, Inc.\" and
            pe.signatures[0].verified and
            pe.signatures[0].digest_alg == \"sha1\" and
            pe.signatures[0].digest == \"f4ca190ec9052243b8882d492b1c12d04da7817f\" and
            pe.signatures[0].algorithm == \"sha256WithRSAEncryption\" and
            pe.signatures[0].algorithm_oid == \"1.2.840.113549.1.1.11\" and
            pe.signatures[0].file_digest == \"f4ca190ec9052243b8882d492b1c12d04da7817f\" and
            pe.signatures[0].number_of_certificates == 4 and
            pe.signatures[0].certificates[0].not_after == 1609372799 and
            pe.signatures[0].certificates[0].not_before == 1356048000 and
            pe.signatures[0].certificates[0].version == 3 and
            pe.signatures[0].certificates[0].serial == \"7e:93:eb:fb:7c:c6:4e:59:ea:4b:9a:77:d4:06:fc:3b\"  and
            pe.signatures[0].certificates[0].algorithm == \"sha1WithRSAEncryption\"  and
            pe.signatures[0].certificates[0].algorithm_oid == \"1.2.840.113549.1.1.5\" and
            pe.signatures[0].certificates[0].thumbprint == \"6c07453ffdda08b83707c09b82fb3d15f35336b1\"  and
            pe.signatures[0].certificates[0].issuer == \"/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA\"  and
            pe.signatures[0].certificates[0].subject == \"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2\"  and
            pe.signatures[0].certificates[1].not_after == 1609286399 and
            pe.signatures[0].certificates[1].not_before == 1350518400 and
            pe.signatures[0].certificates[1].version == 3 and
            pe.signatures[0].certificates[1].serial == \"0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50\"  and
            pe.signatures[0].certificates[1].algorithm == \"sha1WithRSAEncryption\"  and
            pe.signatures[0].certificates[1].algorithm_oid == \"1.2.840.113549.1.1.5\" and
            pe.signatures[0].certificates[1].thumbprint == \"65439929b67973eb192d6ff243e6767adf0834e4\"  and
            pe.signatures[0].certificates[1].issuer == \"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2\"  and
            pe.signatures[0].certificates[1].subject == \"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4\"  and
            pe.signatures[0].certificates[2].not_after == 1559692799 and
            pe.signatures[0].certificates[2].not_before == 1491955200 and
            pe.signatures[0].certificates[2].version == 3 and
            pe.signatures[0].certificates[2].serial == \"21:bd:b2:cb:ec:e5:43:1e:24:f7:56:74:d6:0e:9c:1d\"  and
            pe.signatures[0].certificates[2].algorithm == \"sha256WithRSAEncryption\"  and
            pe.signatures[0].certificates[2].algorithm_oid == \"1.2.840.113549.1.1.11\" and
            pe.signatures[0].certificates[2].thumbprint == \"c1bf1b8f751bf97626ed77f755f0a393106f2454\"  and
            pe.signatures[0].certificates[2].issuer == \"/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code Signing CA\"  and
            pe.signatures[0].certificates[2].subject == \"/C=US/ST=California/L=Menlo Park/O=Quicken, Inc./OU=Operations/CN=Quicken, Inc.\"  and
            pe.signatures[0].certificates[3].not_after == 1702166399 and
            pe.signatures[0].certificates[3].not_before == 1386633600 and
            pe.signatures[0].certificates[3].version == 3 and
            pe.signatures[0].certificates[3].serial == \"3d:78:d7:f9:76:49:60:b2:61:7d:f4:f0:1e:ca:86:2a\"  and
            pe.signatures[0].certificates[3].algorithm == \"sha256WithRSAEncryption\"  and
            pe.signatures[0].certificates[3].algorithm_oid == \"1.2.840.113549.1.1.11\" and
            pe.signatures[0].certificates[3].thumbprint == \"007790f6561dad89b0bcd85585762495e358f8a5\"  and
            pe.signatures[0].certificates[3].issuer == \"/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5\"  and
            pe.signatures[0].certificates[3].subject == \"/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code Signing CA\"  and
            pe.signatures[0].signer_info.digest == \"845555fec6e472a43b0714911d6c452a092e9632\"  and
            pe.signatures[0].signer_info.digest_alg == \"sha1\"  and
            pe.signatures[0].signer_info.length_of_chain == 2  and
            pe.signatures[0].signer_info.chain[0].not_after == 1559692799 and
            pe.signatures[0].signer_info.chain[0].not_before == 1491955200 and
            pe.signatures[0].signer_info.chain[0].version == 3 and
            pe.signatures[0].signer_info.chain[0].serial == \"21:bd:b2:cb:ec:e5:43:1e:24:f7:56:74:d6:0e:9c:1d\"  and
            pe.signatures[0].signer_info.chain[0].algorithm == \"sha256WithRSAEncryption\"  and
            pe.signatures[0].signer_info.chain[0].algorithm_oid == \"1.2.840.113549.1.1.11\" and
            pe.signatures[0].signer_info.chain[0].thumbprint == \"c1bf1b8f751bf97626ed77f755f0a393106f2454\"  and
            pe.signatures[0].signer_info.chain[0].issuer == \"/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code Signing CA\"  and
            pe.signatures[0].signer_info.chain[0].subject == \"/C=US/ST=California/L=Menlo Park/O=Quicken, Inc./OU=Operations/CN=Quicken, Inc.\"  and
            pe.signatures[0].signer_info.chain[1].not_after == 1702166399 and
            pe.signatures[0].signer_info.chain[1].not_before == 1386633600 and
            pe.signatures[0].signer_info.chain[1].version == 3 and
            pe.signatures[0].signer_info.chain[1].serial == \"3d:78:d7:f9:76:49:60:b2:61:7d:f4:f0:1e:ca:86:2a\"  and
            pe.signatures[0].signer_info.chain[1].algorithm == \"sha256WithRSAEncryption\"  and
            pe.signatures[0].signer_info.chain[1].algorithm_oid == \"1.2.840.113549.1.1.11\" and
            pe.signatures[0].signer_info.chain[1].thumbprint == \"007790f6561dad89b0bcd85585762495e358f8a5\"  and
            pe.signatures[0].signer_info.chain[1].issuer == \"/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5\"  and
            pe.signatures[0].signer_info.chain[1].subject == \"/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code Signing CA\"  and
            pe.signatures[0].number_of_countersignatures == 1  and
            pe.signatures[0].countersignatures[0].length_of_chain == 2  and
            pe.signatures[0].countersignatures[0].digest == \"9fa1188e4c656d86e2d7fa133ee8138ac1ec4ec1\"  and
            pe.signatures[0].countersignatures[0].digest_alg == \"sha1\"  and
            pe.signatures[0].countersignatures[0].sign_time == 1528216551  and
            pe.signatures[0].countersignatures[0].verified  and
            pe.signatures[0].countersignatures[0].chain[0].not_after == 1609286399 and
            pe.signatures[0].countersignatures[0].chain[0].not_before == 1350518400 and
            pe.signatures[0].countersignatures[0].chain[0].version == 3 and
            pe.signatures[0].countersignatures[0].chain[0].serial == \"0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50\"  and
            pe.signatures[0].countersignatures[0].chain[0].algorithm == \"sha1WithRSAEncryption\"  and
            pe.signatures[0].countersignatures[0].chain[0].algorithm_oid == \"1.2.840.113549.1.1.5\" and
            pe.signatures[0].countersignatures[0].chain[0].thumbprint == \"65439929b67973eb192d6ff243e6767adf0834e4\"  and
            pe.signatures[0].countersignatures[0].chain[0].issuer == \"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2\"  and
            pe.signatures[0].countersignatures[0].chain[0].subject == \"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4\"  and
            pe.signatures[0].countersignatures[0].chain[1].not_after == 1609372799 and
            pe.signatures[0].countersignatures[0].chain[1].not_before == 1356048000 and
            pe.signatures[0].countersignatures[0].chain[1].version == 3 and
            pe.signatures[0].countersignatures[0].chain[1].serial == \"7e:93:eb:fb:7c:c6:4e:59:ea:4b:9a:77:d4:06:fc:3b\"  and
            pe.signatures[0].countersignatures[0].chain[1].algorithm == \"sha1WithRSAEncryption\"  and
            pe.signatures[0].countersignatures[0].chain[1].algorithm_oid == \"1.2.840.113549.1.1.5\" and
            pe.signatures[0].countersignatures[0].chain[1].thumbprint == \"6c07453ffdda08b83707c09b82fb3d15f35336b1\"  and
            pe.signatures[0].countersignatures[0].chain[1].issuer == \"/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA\"  and
            pe.signatures[0].countersignatures[0].chain[1].subject == \"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2\"
        }",
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true
    );

    #[cfg(feature = "authenticode-verify")]
    check_file(
        "import \"pe\"
      rule test {
        condition:
          not pe.is_signed
      }",
        "tests/assets/libyara/data/e3d45a2865818756068757d7e319258fef40dad54532ee4355b86bc129f27345",
        true,
    );

    #[cfg(feature = "authenticode-verify")]
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.is_signed
      }",
        "tests/assets/libyara/data/3b8b90159fa9b6048cc5410c5d53f116943564e4d05b04a843f9b3d0540d0c1c",
        true,
    );

    #[cfg(feature = "authenticode")]
    check_file(
        "import \"pe\"
        rule test {
          condition:
            pe.number_of_signatures == 2
        }",
        "tests/assets/libyara/data/3b8b90159fa9b6048cc5410c5d53f116943564e4d05b04a843f9b3d0540d0c1c",
        true
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.section_index(\".text\") == 0
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.section_index(pe.entry_point) == 0
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.is_32bit() and not pe.is_64bit()
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.checksum == 0xA8DC
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.checksum == pe.calculate_checksum()
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.overlay.offset == 0x8000 and pe.overlay.size == 7
      }",
        "tests/assets/libyara/data/tiny-overlay",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.overlay.offset == 0 and pe.overlay.size == 0
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        r#"import "pe"
      rule test {
        condition:
          pe.pdb_path == "D:\\workspace\\2018_R9_RelBld\\target\\checkout\\custprof\\Release\\custprof.pdb"
      }"#,
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.pdb_path == \"/Users/runner/work/OpenCorePkg/OpenCorePkg/UDK/Build/OpenCorePkg/\
          DEBUG_XCODE5/X64/OpenCorePkg/Application/ChipTune/ChipTune/DEBUG/ChipTune.dll\"
      }",
        "tests/assets/libyara/data/ChipTune.efi",
        true,
    );

    check_file(
      "import \"pe\"
      rule test {
        condition:
          pe.pdb_path == \"2AC71AF3-A338-495C-834E-977A6DD5C6FD\"
      }",
      "tests/assets/libyara/data/6c2abf4b80a87e63eee2996e5cea8f004d49ec0c1806080fa72e960529cba14c",
      true);

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.checksum == pe.calculate_checksum()
      }",
        "tests/assets/libyara/data/tiny-idata-51ff",
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
          pe.export_details[0].rva == 0x1030 and
          pe.export_details[1].rva == 0x267d and
          pe.export_details[2].rva == 0x26a8 and
          pe.export_details[3].rva == 0x26ca and
          pe.export_details[1].forward_name == \"COMSVCS.GetObjectContext\"
      }",
        "tests/assets/libyara/data/mtxex.dll",
        true,
    );
    /*
     * mtxex_modified_rsrc_rva.dll is a modified copy of mtxex.dll from a Windows
     * 10 install. The modification was to change the RVA of the only resource to
     * be invalid (it was changed to be 0x41585300), to ensure we are still
     * parsing resources even if the RVA does not have a corresponding file
     * offset.
     */
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.number_of_resources == 1 and
          pe.resources[0].rva == 5462081 and
          pe.resources[0].length == 888
      }",
        "tests/assets/libyara/data/mtxex_modified_rsrc_rva.dll",
        true,
    );

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
        "tests/assets/libyara/data/mtxex.dll",
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
        "tests/assets/libyara/data/mtxex.dll",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.export_details[0].name == \"CP_PutItem\" and
          pe.export_details[0].rva == 0x106c
      }",
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.upx",
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
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    check_file(
      "import \"pe\"
      rule test {
        condition:
          pe.rich_signature.version_data == \"\\x1b\\x9d\\x9c\\x00\\x1b\\x9d\\x9e\\x00\\x1b\\x9d\
\\xaa\\x00ov\\xab\\x00\\x09x\\x93\\x00\\x00\\x00\\x01\\x00\\x1b\\x9d\\xab\\x00\\x1b\\x9d\\x9b\
\\x00\\x1b\\x9d\\x9a\\x00\\x1b\\x9d\\x9d\\x00\"
      }",
      "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
      true);

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
        "tests/assets/libyara/data/weird_rich",
        true,
    );

    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.language(0x09) and pe.locale(0x0409)
      }",
        "tests/assets/libyara/data/mtxex.dll",
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
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    check_file(
        "import \"pe\"
      rule iequals_comparison {
        condition:
          pe.sections[0].name != \".TEXT\" and
          pe.sections[0].name iequals \".TEXT\"
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

    check_file(
        "import \"pe\"

      rule import_details_catch
      {
          condition:
            for any import_detail in pe.import_details: (
                import_detail.library_name == \"MSVCR100.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"_initterm\"
                )
            )
      }",
        "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    check_file(
      "import \"pe\"

      rule import_details_rva_32_v1_catch
      {
          condition:
            for any import_detail in pe.import_details: (
                import_detail.library_name == \"MSVCR100.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"_initterm\" and
                    function.rva == 0x3084
                )
            )
      }",
      "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885", true);

    check_file(
      "import \"pe\"

      rule import_details_rva_32_v2_catch
      {
          condition:
            for any import_detail in pe.import_details: (
                import_detail.library_name == \"KERNEL32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"QueryPerformanceCounter\" and
                    function.rva == 0x3054
                )
            )
      }",
      "tests/assets/libyara/data/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885", true);

    check_file(
        "import \"pe\"

      rule import_details_rva_32_v3_catch
      {
          condition:
            for any import_detail in pe.import_details: (
                import_detail.library_name == \"KERNEL32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"CloseHandle\" and
                    function.rva == 0xd10c
                )
            )
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"

      rule import_details_rva_64_v1_catch
      {
          condition:
            for any import_detail in pe.import_details: (
                import_detail.library_name == \"KERNEL32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"LoadLibraryExW\" and
                    function.rva == 0x2118
                )
            )
      }",
        "tests/assets/libyara/data/mtxex_modified_rsrc_rva.dll",
        true,
    );

    check_file(
        "import \"pe\"

      rule import_details_rva_64_v2_catch
      {
          condition:
            for any import_detail in pe.import_details: (
                import_detail.library_name == \"KERNEL32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"GetCurrentProcessId\" and
                    function.rva == 0x21a0
                )
            )
      }",
        "tests/assets/libyara/data/mtxex_modified_rsrc_rva.dll",
        true,
    );

    check_file(
        "import \"pe\"

      rule delayed_import_details_rva_32_v1_catch
      {
          condition:
            for any import_detail in pe.delayed_import_details: (
                import_detail.library_name == \"USER32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"MessageBoxA\" and
                    function.rva == 0x13884
                )
            )
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"

      rule delayed_import_details_rva_32_v2_catch
      {
          condition:
            for any import_detail in pe.delayed_import_details: (
                import_detail.library_name == \"USER32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"MessageBeep\" and
                    function.rva == 0x13880
                )
            )
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"

      rule import_delayed_import_details
      {
          condition:
            for any import_detail in pe.delayed_import_details : (
                import_detail.number_of_functions == 2 and
                import_detail.library_name == \"USER32.dll\" and
                for any function in import_detail.functions : (
                    function.name == \"MessageBoxA\"
                )
            )
      }",
        "tests/assets/libyara/data/pe_imports",
        true,
    );

    check_file(
        "import \"pe\"

      rule import_details
      {
          condition:
            pe.number_of_imports == 2 and
            pe.import_details[0].library_name == \"KERNEL32.dll\" and
            pe.import_details[0].number_of_functions == 21 and
            pe.import_details[0].functions[20].name == \"VirtualQuery\" and
            pe.import_details[1].library_name == \"msvcrt.dll\" and
            pe.import_details[1].number_of_functions == 27 and
            pe.import_details[1].functions[26].name == \"vfprintf\"
      }",
        "tests/assets/libyara/data/tiny",
        true,
    );

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
        "tests/assets/libyara/data/ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386",
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
        "tests/assets/libyara/data/tiny",
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
        "tests/assets/libyara/data/pe_mingw",
        true,
    );

    // These are intentionally using DLL and function names with incorrect case
    // to be sure the string compare is case insensitive.
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.import_rva(\"ptimagerw.dll\", \"ORD4\") == 254924 and
          pe.import_rva(\"ptPDF417decode.dll\", 4) == 254948
      }",
        "tests/assets/libyara/data/\
      ca21e1c32065352d352be6cde97f89c141d7737ea92434831f998080783d5386",
        true,
    );

    // These are intentionally using DLL and function names with incorrect case
    // to be sure the string compare is case insensitive.
    check_file(
        "import \"pe\"
      rule test {
        condition:
          pe.delayed_import_rva(\"qdb.dll\", \"ORD116\") ==
          pe.delayed_import_rva(\"qdb.dll\", 116)
      }",
        "tests/assets/libyara/data/\
      079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885",
        true,
    );

    // The first 0x410 bytes of
    // c6f9709feccf42f2d9e22057182fe185f177fb9daaa2649b4669a24f2ee7e3ba are enough
    // to trigger the bug in https://github.com/VirusTotal/yara/pull/1561
    check_file(
        "import \"pe\"
      rule rva_to_offset_weird_sections {
        condition:
          pe.rva_to_offset(4096) == 1024
      }",
        "tests/assets/libyara/data/\
      c6f9709feccf42f2d9e22057182fe185f177fb9daaa2649b4669a24f2ee7e3ba_0h_410h",
        true,
    );

    check_file(
        "import \"pe\"
      rule invalid_offset {
        condition:
          not defined pe.export_details[0].offset and
          not defined pe.export_details[7].offset and
          not defined pe.export_details[15].offset and
          not defined pe.export_details[21].offset
      }",
        "tests/assets/libyara/data/\
        05cd06e6a202e12be22a02700ed6f1604e803ca8867277d852e8971efded0650",
        true,
    );
}
