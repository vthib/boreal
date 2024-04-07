use boreal::module::Dotnet;

use crate::utils::{check_file, compare_module_values_on_file, Checker};

#[test]
fn test_not_dotnet() {
    // On a non PE file, nothing is set
    check_file(
        r#"
import "dotnet"
rule test {
    condition:
        not defined dotnet.is_dotnet
}"#,
        "tests/assets/libyara/data/tiny-macho",
        true,
    );

    // On a PE file that is not dotnet, the is_dotnet field is set
    check_file(
        r#"
import "dotnet"
rule test {
    condition:
        dotnet.is_dotnet == 0
}"#,
        "tests/assets/libyara/data/pe_mingw",
        true,
    );
}

#[test]
fn test_streams() {
    check_file(
        r##"
import "dotnet"
rule test {
    condition:
        dotnet.version == "v2.0.50727" and
        dotnet.number_of_streams == 5 and

        dotnet.streams[0].name == "#~" and
        dotnet.streams[0].offset == 1012 and
        dotnet.streams[0].size == 244 and

        dotnet.streams[1].name == "#Strings" and
        dotnet.streams[1].offset == 1256 and
        dotnet.streams[1].size == 316 and

        dotnet.streams[2].name == "#US" and
        dotnet.streams[2].offset == 1572 and
        dotnet.streams[2].size == 8 and

        dotnet.streams[3].name == "#GUID" and
        dotnet.streams[3].offset == 1580 and
        dotnet.streams[3].size == 16 and

        dotnet.streams[4].name == "#Blob" and
        dotnet.streams[4].offset == 1596 and
        dotnet.streams[4].size == 204
}"##,
        "tests/assets/libyara/data/\
         0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171",
        true,
    );
}

#[test]
fn test_assembly() {
    let mut checker = Checker::new(
        r##"
import "dotnet"
rule assembly {
    condition:
        dotnet.assembly.name == "?iD.gabu.Zo$.@mEu" and
        dotnet.assembly.culture == "de-ch" and
        dotnet.assembly.version.major == 57 and
        dotnet.assembly.version.minor == 239 and
        dotnet.assembly.version.build_number == 120 and
        dotnet.assembly.version.revision_number == 17706
}

rule ar0 {
    condition:
        dotnet.assembly_refs[0].name == "Kwee" and
        dotnet.assembly_refs[0].version.major == 0 and
        dotnet.assembly_refs[0].version.minor == 0 and
        dotnet.assembly_refs[0].version.build_number == 0 and
        dotnet.assembly_refs[0].version.revision_number == 0 and
        not defined dotnet.assembly_refs[0].public_key_or_token
}

rule ar1 {
    condition:
        dotnet.assembly_refs[1].name == "one.two.three" and
        dotnet.assembly_refs[1].version.major == 0 and
        dotnet.assembly_refs[1].version.minor == 0 and
        dotnet.assembly_refs[1].version.build_number == 0 and
        dotnet.assembly_refs[1].version.revision_number == 0 and
        not defined dotnet.assembly_refs[1].public_key_or_token
}

rule ar2 {
    condition:
        dotnet.assembly_refs[2].name == "four.five" and
        dotnet.assembly_refs[2].public_key_or_token ==
            "\xde\x45\x23\x89\x82\x06\x07\xa6\xbb\xaa\xbb\xee\x11\x22\x33\x00" and
        dotnet.assembly_refs[2].version.major == 0 and
        dotnet.assembly_refs[2].version.minor == 0 and
        dotnet.assembly_refs[2].version.build_number == 0 and
        dotnet.assembly_refs[2].version.revision_number == 0
}

rule ar3 {
    condition:
        dotnet.assembly_refs[3].name == "muwu" and
        dotnet.assembly_refs[3].version.major == 0 and
        dotnet.assembly_refs[3].version.minor == 0 and
        dotnet.assembly_refs[3].version.build_number == 0 and
        dotnet.assembly_refs[3].version.revision_number == 0 and
        not defined dotnet.assembly_refs[3].public_key_or_token
}

rule ar4 {
    condition:
        dotnet.assembly_refs[4].name == "in external.Assembly@" and
        dotnet.assembly_refs[4].public_key_or_token ==
            "\xbb\xaa\xbb\xee\x11\x22\x33\x00" and
        dotnet.assembly_refs[4].version.major == 912 and
        dotnet.assembly_refs[4].version.minor == 35720 and
        dotnet.assembly_refs[4].version.build_number == 283 and
        dotnet.assembly_refs[4].version.revision_number == 212
}"##,
    );

    let mem = std::fs::read("tests/assets/dotnet/assembly.dll").unwrap();
    checker.check_rule_matches(
        &mem,
        &[
            "default:assembly",
            "default:ar0",
            "default:ar1",
            "default:ar2",
            "default:ar3",
            "default:ar4",
        ],
    );
}

#[test]
fn test_types_exe() {
    // Split checks in multiple rules so that if one fails, we at least know a bit
    // more precisely which part of the check failed.
    let mut checker = Checker::new(
        r#"import "dotnet"
    rule c0 {
      condition:
        dotnet.is_dotnet == 1 and
        dotnet.module_name == "types.exe" and
        dotnet.number_of_classes == 4 and
        dotnet.classes[0].fullname == "Container" and
        dotnet.classes[0].number_of_generic_parameters == 2 and
        dotnet.classes[0].generic_parameters[0] == "C" and
        dotnet.classes[0].generic_parameters[1] == "D" and
        dotnet.classes[0].number_of_methods == 10
    }

    rule c0m0 {
      condition:
        dotnet.classes[0].methods[0].name == "simple" and
        dotnet.classes[0].methods[0].return_type == "void" and
        dotnet.classes[0].methods[0].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[0].number_of_parameters == 13 and

        dotnet.classes[0].methods[0].parameters[0].name == "a" and
        dotnet.classes[0].methods[0].parameters[0].type == "sbyte" and

        dotnet.classes[0].methods[0].parameters[1].name == "b" and
        dotnet.classes[0].methods[0].parameters[1].type == "byte" and

        dotnet.classes[0].methods[0].parameters[2].name == "c" and
        dotnet.classes[0].methods[0].parameters[2].type == "short" and

        dotnet.classes[0].methods[0].parameters[3].name == "d" and
        dotnet.classes[0].methods[0].parameters[3].type == "ushort" and

        dotnet.classes[0].methods[0].parameters[4].name == "e" and
        dotnet.classes[0].methods[0].parameters[4].type == "int" and

        dotnet.classes[0].methods[0].parameters[5].name == "f" and
        dotnet.classes[0].methods[0].parameters[5].type == "uint" and

        dotnet.classes[0].methods[0].parameters[6].name == "g" and
        dotnet.classes[0].methods[0].parameters[6].type == "long" and

        dotnet.classes[0].methods[0].parameters[7].name == "h" and
        dotnet.classes[0].methods[0].parameters[7].type == "ulong" and

        dotnet.classes[0].methods[0].parameters[8].name == "i" and
        dotnet.classes[0].methods[0].parameters[8].type == "char" and

        dotnet.classes[0].methods[0].parameters[9].name == "j" and
        dotnet.classes[0].methods[0].parameters[9].type == "float" and

        dotnet.classes[0].methods[0].parameters[10].name == "k" and
        dotnet.classes[0].methods[0].parameters[10].type == "double" and

        dotnet.classes[0].methods[0].parameters[11].name == "m" and
        dotnet.classes[0].methods[0].parameters[11].type == "bool" and

        dotnet.classes[0].methods[0].parameters[12].name == "n" and
        dotnet.classes[0].methods[0].parameters[12].type == "System.Decimal"
    }

    rule c0m1 {
      condition:
        dotnet.classes[0].methods[1].name == "tptr" and
        dotnet.classes[0].methods[1].return_type == "void" and
        dotnet.classes[0].methods[1].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[1].number_of_parameters == 4 and

        dotnet.classes[0].methods[1].parameters[0].name == "i" and
        dotnet.classes[0].methods[1].parameters[0].type == "IntPtr" and

        dotnet.classes[0].methods[1].parameters[1].name == "u" and
        dotnet.classes[0].methods[1].parameters[1].type == "UIntPtr" and

        dotnet.classes[0].methods[1].parameters[2].name == "o" and
        dotnet.classes[0].methods[1].parameters[2].type == "object" and

        dotnet.classes[0].methods[1].parameters[3].name == "tr" and
        dotnet.classes[0].methods[1].parameters[3].type == "TypedReference"
    }

    rule c0m2 {
      condition:
        dotnet.classes[0].methods[2].name == "tenum" and
        dotnet.classes[0].methods[2].return_type == "void" and
        dotnet.classes[0].methods[2].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[2].number_of_parameters == 1 and

        dotnet.classes[0].methods[2].parameters[0].name == "color" and
        dotnet.classes[0].methods[2].parameters[0].type == "Color"
    }

    rule c0m3 {
      condition:
        dotnet.classes[0].methods[3].name == "ttuple" and
        dotnet.classes[0].methods[3].return_type == "sbyte" and
        dotnet.classes[0].methods[3].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[3].number_of_parameters == 1 and

        dotnet.classes[0].methods[3].parameters[0].name == "tuple" and
        dotnet.classes[0].methods[3].parameters[0].type == "System.ValueTuple<int,string>"
    }

    rule c0m4 {
      condition:
        dotnet.classes[0].methods[4].name == "topt" and
        dotnet.classes[0].methods[4].return_type == "void" and
        dotnet.classes[0].methods[4].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[4].number_of_parameters == 1 and

        dotnet.classes[0].methods[4].parameters[0].name == "b" and
        dotnet.classes[0].methods[4].parameters[0].type == "System.Nullable<bool>"
    }

    rule c0m5 {
      condition:
        dotnet.classes[0].methods[5].name == "generic" and
        dotnet.classes[0].methods[5].return_type == "B" and
        dotnet.classes[0].methods[5].number_of_generic_parameters == 2 and
        dotnet.classes[0].methods[5].generic_parameters[0] == "A" and
        dotnet.classes[0].methods[5].generic_parameters[1] == "B" and
        dotnet.classes[0].methods[5].number_of_parameters == 4 and

        dotnet.classes[0].methods[5].parameters[0].name == "b" and
        dotnet.classes[0].methods[5].parameters[0].type == "B" and
        dotnet.classes[0].methods[5].parameters[1].name == "d" and
        dotnet.classes[0].methods[5].parameters[1].type == "D" and
        dotnet.classes[0].methods[5].parameters[2].name == "a" and
        dotnet.classes[0].methods[5].parameters[2].type == "A" and
        dotnet.classes[0].methods[5].parameters[3].name == "c" and
        dotnet.classes[0].methods[5].parameters[3].type == "C"
    }

    rule c0m6 {
      condition:
        dotnet.classes[0].methods[6].name == "arr" and
        dotnet.classes[0].methods[6].return_type == "object" and
        dotnet.classes[0].methods[6].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[6].number_of_parameters == 4 and

        dotnet.classes[0].methods[6].parameters[0].name == "a" and
        dotnet.classes[0].methods[6].parameters[0].type == "int[]" and
        dotnet.classes[0].methods[6].parameters[1].name == "b" and
        dotnet.classes[0].methods[6].parameters[1].type == "short[,]" and
        dotnet.classes[0].methods[6].parameters[2].name == "c" and
        dotnet.classes[0].methods[6].parameters[2].type == "sbyte[,,]" and
        dotnet.classes[0].methods[6].parameters[3].name == "d" and
        dotnet.classes[0].methods[6].parameters[3].type == "bool[,,,][][,,][,,,,][,]"
    }

    rule c0m7 {
      condition:
        dotnet.classes[0].methods[7].name == "tunsafe" and
        dotnet.classes[0].methods[7].return_type == "void" and
        dotnet.classes[0].methods[7].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[7].number_of_parameters == 2 and

        dotnet.classes[0].methods[7].parameters[0].name == "pi1" and
        dotnet.classes[0].methods[7].parameters[0].type == "Ptr<int>" and
        dotnet.classes[0].methods[7].parameters[1].name == "pi2" and
        dotnet.classes[0].methods[7].parameters[1].type == "ref Ptr<int>"
    }

    rule c0m8 {
      condition:
        dotnet.classes[0].methods[8].name == "tfnptr" and
        dotnet.classes[0].methods[8].return_type == "void" and
        dotnet.classes[0].methods[8].number_of_generic_parameters == 0 and
        dotnet.classes[0].methods[8].number_of_parameters == 3 and

        dotnet.classes[0].methods[8].parameters[0].name == "ip" and
        dotnet.classes[0].methods[8].parameters[0].type == "FnPtr<void()>" and
        dotnet.classes[0].methods[8].parameters[1].name == "fp" and
        dotnet.classes[0].methods[8].parameters[1].type == "Ptr<FnPtr<void()>>" and
        dotnet.classes[0].methods[8].parameters[2].name == "fp2" and
        dotnet.classes[0].methods[8].parameters[2].type == "Ptr<FnPtr<IntPtr(sbyte, ref Ptr<int>)>>"
    }

    rule c1 {
      condition:
        dotnet.classes[1].name == "Child" and
        dotnet.classes[1].namespace == "" and
        dotnet.classes[1].number_of_base_types == 1 and
        dotnet.classes[1].base_types[0] == "Container<Color,IntPtr>"
    }
    "#,
    );

    let mem = std::fs::read("tests/assets/dotnet/types.exe").unwrap();
    checker.check_rule_matches(
        &mem,
        &[
            "default:c0",
            "default:c0m0",
            "default:c0m1",
            "default:c0m2",
            "default:c0m3",
            "default:c0m4",
            "default:c0m5",
            "default:c0m6",
            "default:c0m7",
            "default:c0m8",
            "default:c1",
        ],
    );
}

#[test]
fn test_types2_dll() {
    // Split checks in multiple rules so that if one fails, we at least know a bit
    // more precisely which part of the check failed.
    // TODO: fix this in YARA
    let mut checker = Checker::new_without_yara(
        r#"import "dotnet"
    rule aa {
      condition:
        dotnet.is_dotnet == 1 and
        dotnet.module_name == "types2.dll" and
        dotnet.number_of_classes == 2 and
        dotnet.classes[0].fullname == "Cmk" and
        dotnet.classes[1].fullname == "VolatileMethods" and
        dotnet.classes[1].number_of_generic_parameters == 0 and
        dotnet.classes[1].number_of_methods == 3
    }

    // CModReq and CModOpt
    rule c1m0 {
      condition:
        dotnet.classes[1].methods[0].name == "withCmod" and
        dotnet.classes[1].methods[0].return_type == "void" and
        dotnet.classes[1].methods[0].number_of_generic_parameters == 0 and
        dotnet.classes[1].methods[0].number_of_parameters == 2 and

        dotnet.classes[1].methods[0].parameters[0].name == "i" and
        dotnet.classes[1].methods[0].parameters[0].type == "Ptr<int>" and

        dotnet.classes[1].methods[0].parameters[1].name == "j" and
        dotnet.classes[1].methods[0].parameters[1].type == "int"
    }

    rule c1m1 {
      condition:
        dotnet.classes[1].methods[1].name == "withArrays" and
        dotnet.classes[1].methods[1].return_type == "void" and
        dotnet.classes[1].methods[1].number_of_generic_parameters == 0 and
        dotnet.classes[1].methods[1].number_of_parameters == 7 and

        dotnet.classes[1].methods[1].parameters[0].name == "a" and
        dotnet.classes[1].methods[1].parameters[0].type == "int[3]" and

        dotnet.classes[1].methods[1].parameters[1].name == "b" and
        dotnet.classes[1].methods[1].parameters[1].type == "uint[4,1...2,0,,,]" and

        dotnet.classes[1].methods[1].parameters[2].name == "c" and
        dotnet.classes[1].methods[1].parameters[2].type == "short[1...2,6...8]" and

        dotnet.classes[1].methods[1].parameters[3].name == "d" and
        dotnet.classes[1].methods[1].parameters[3].type == "ulong[5,3...5,,]" and

        dotnet.classes[1].methods[1].parameters[4].name == "e" and
        dotnet.classes[1].methods[1].parameters[4].type == "byte[8...23,0,5,2...2,-5...8,3...4]" and

        dotnet.classes[1].methods[1].parameters[5].name == "f" and
        dotnet.classes[1].methods[1].parameters[5].type == "sbyte[53...,-34...]" and

        dotnet.classes[1].methods[1].parameters[6].name == "g" and
        dotnet.classes[1].methods[1].parameters[6].type ==
          "ushort[1032...8388608,-1032...512,-8388608...-1032]"
    }

    rule c1m2 {
      condition:
        dotnet.classes[1].methods[2].name == "compressionValues" and
        dotnet.classes[1].methods[2].return_type == "void" and
        dotnet.classes[1].methods[2].number_of_generic_parameters == 0 and
        dotnet.classes[1].methods[2].number_of_parameters == 4 and

        dotnet.classes[1].methods[2].parameters[0].name == "a" and
        dotnet.classes[1].methods[2].parameters[0].type == "sbyte[-65...,-64...,63...,64...]" and

        dotnet.classes[1].methods[2].parameters[1].name == "b" and
        dotnet.classes[1].methods[2].parameters[1].type == "sbyte[-8193...,-8192...,8191...,8192...]" and

        dotnet.classes[1].methods[2].parameters[2].name == "c" and
        dotnet.classes[1].methods[2].parameters[2].type == "sbyte[-268435456...,268435455...]" and

        dotnet.classes[1].methods[2].parameters[3].name == "d" and
        dotnet.classes[1].methods[2].parameters[3].type == "sbyte[0,127,128,256,16383,16384,268435455]"
    }
    "#,
    );

    let mem = std::fs::read("tests/assets/dotnet/types2.dll").unwrap();
    checker.check_rule_matches(
        &mem,
        &["default:aa", "default:c1m0", "default:c1m1", "default:c1m2"],
    );
}

#[test]
fn test_classes() {
    // Split checks in multiple rules so that if one fails, we at least know a bit
    // more precisely which part of the check failed.
    let mut checker = Checker::new(
        r#"import "dotnet"
    rule c0 {
      condition:
        dotnet.number_of_classes == 14 and
        dotnet.classes[0].name == "Public" and
        dotnet.classes[0].namespace == "" and
        dotnet.classes[0].fullname == "Public" and
        dotnet.classes[0].type == "class" and
        dotnet.classes[0].visibility == "public" and
        dotnet.classes[0].number_of_base_types == 1 and
        dotnet.classes[0].base_types[0] == "System.Object"
    }

    rule c1 {
      condition:
        dotnet.classes[1].name == "Outer" and
        dotnet.classes[1].namespace == "" and
        dotnet.classes[1].fullname == "Outer" and
        dotnet.classes[1].type == "class" and
        dotnet.classes[1].visibility == "internal" and
        dotnet.classes[1].number_of_base_types == 1 and
        dotnet.classes[1].base_types[0] == "System.Object"
    }

    rule c2 {
      condition:
        dotnet.classes[2].name == "All" and
        dotnet.classes[2].namespace == "" and
        dotnet.classes[2].fullname == "All" and
        dotnet.classes[2].type == "class" and
        dotnet.classes[2].visibility == "internal" and
        dotnet.classes[2].number_of_base_types == 1 and
        dotnet.classes[2].base_types[0] == "Public"
    }

    rule c3 {
      condition:
        dotnet.classes[3].name == "NestedNaked" and
        dotnet.classes[3].namespace == "Outer" and
        dotnet.classes[3].fullname == "Outer.NestedNaked" and
        dotnet.classes[3].type == "class" and
        dotnet.classes[3].visibility == "private" and
        dotnet.classes[3].number_of_base_types == 1 and
        dotnet.classes[3].base_types[0] == "System.Object" and
        dotnet.classes[3].abstract == 0
    }

    rule c4 {
      condition:
        dotnet.classes[4].name == "NestedPublic" and
        dotnet.classes[4].namespace == "Outer" and
        dotnet.classes[4].fullname == "Outer.NestedPublic" and
        dotnet.classes[4].type == "class" and
        dotnet.classes[4].visibility == "public" and
        dotnet.classes[4].number_of_base_types == 1 and
        dotnet.classes[4].base_types[0] == "System.Object" and
        dotnet.classes[4].sealed == 0 and
        dotnet.classes[4].abstract == 1
    }

    rule c5 {
      condition:
        dotnet.classes[5].name == "NestedPrivate" and
        dotnet.classes[5].namespace == "Outer" and
        dotnet.classes[5].fullname == "Outer.NestedPrivate" and
        dotnet.classes[5].type == "interface" and
        dotnet.classes[5].visibility == "private" and
        dotnet.classes[5].number_of_base_types == 0 and
        dotnet.classes[5].sealed == 0 and
        dotnet.classes[5].abstract == 1
    }

    rule c6 {
      condition:
        dotnet.classes[6].name == "NestedInternal" and
        dotnet.classes[6].namespace == "Outer" and
        dotnet.classes[6].fullname == "Outer.NestedInternal" and
        dotnet.classes[6].type == "class" and
        dotnet.classes[6].visibility == "internal" and
        dotnet.classes[6].number_of_base_types == 1 and
        dotnet.classes[6].base_types[0] == "System.Object" and
        dotnet.classes[6].sealed == 1 and
        dotnet.classes[6].abstract == 0
    }

    rule c7 {
      condition:
        dotnet.classes[7].name == "Inner" and
        dotnet.classes[7].namespace == "Outer" and
        dotnet.classes[7].fullname == "Outer.Inner" and
        dotnet.classes[7].type == "class" and
        dotnet.classes[7].visibility == "private" and
        dotnet.classes[7].number_of_base_types == 1 and
        dotnet.classes[7].base_types[0] == "System.Object"
    }

    rule c8 {
      condition:
        dotnet.classes[8].name == "Iface1" and
        dotnet.classes[8].namespace == "Outer" and
        dotnet.classes[8].fullname == "Outer.Iface1" and
        dotnet.classes[8].type == "interface" and
        dotnet.classes[8].visibility == "private" and
        dotnet.classes[8].number_of_base_types == 0
    }

    rule c9 {
      condition:
        dotnet.classes[9].name == "Iface2" and
        dotnet.classes[9].namespace == "Outer" and
        dotnet.classes[9].fullname == "Outer.Iface2" and
        dotnet.classes[9].type == "interface" and
        dotnet.classes[9].visibility == "private" and
        dotnet.classes[9].number_of_base_types == 0
    }

    rule c10 {
      condition:
        dotnet.classes[10].name == "Grandchild" and
        dotnet.classes[10].namespace == "Outer" and
        dotnet.classes[10].fullname == "Outer.Grandchild" and
        dotnet.classes[10].type == "class" and
        dotnet.classes[10].visibility == "private" and
        dotnet.classes[10].number_of_base_types == 3 and
        dotnet.classes[10].base_types[0] == "Outer.NestedNaked" and
        dotnet.classes[10].base_types[1] == "Outer.Iface2" and
        dotnet.classes[10].base_types[2] == "Outer.Iface1"
    }

    rule c11 {
      condition:
        dotnet.classes[11].name == "NestedProtected" and
        dotnet.classes[11].namespace == "Outer.Inner" and
        dotnet.classes[11].fullname == "Outer.Inner.NestedProtected" and
        dotnet.classes[11].type == "interface" and
        dotnet.classes[11].visibility == "protected"
    }

    rule c12 {
      condition:
        dotnet.classes[12].name == "NestedPrivateProtected" and
        dotnet.classes[12].namespace == "Outer.Inner" and
        dotnet.classes[12].fullname == "Outer.Inner.NestedPrivateProtected" and
        dotnet.classes[12].type == "class" and
        dotnet.classes[12].visibility == "private protected"
    }

    rule c13 {
      condition:
        dotnet.classes[13].name == "NestedProtectedInternal" and
        dotnet.classes[13].namespace == "Outer.Inner" and
        dotnet.classes[13].fullname == "Outer.Inner.NestedProtectedInternal" and
        dotnet.classes[13].type == "interface" and
        dotnet.classes[13].visibility == "protected internal"
    }
    "#,
    );

    let mem = std::fs::read("tests/assets/dotnet/classes.dll").unwrap();
    checker.check_rule_matches(
        &mem,
        &[
            "default:c0",
            "default:c1",
            "default:c2",
            "default:c3",
            "default:c4",
            "default:c5",
            "default:c6",
            "default:c7",
            "default:c8",
            "default:c9",
            "default:c10",
            "default:c11",
            "default:c12",
            "default:c13",
        ],
    );
}

#[test]
fn test_methods() {
    // Split checks in multiple rules so that if one fails, we at least know a bit
    // more precisely which part of the check failed.
    let mut checker = Checker::new(
        r#"import "dotnet"
    rule main {
      condition:
        dotnet.classes[2].name == "All" and
        dotnet.classes[2].number_of_methods == 9
    }

    rule m0 {
      condition:
        dotnet.classes[2].methods[0].name == ".cctor" and
        dotnet.classes[2].methods[0].abstract == 0 and
        dotnet.classes[2].methods[0].final == 0 and
        dotnet.classes[2].methods[0].static == 1 and
        dotnet.classes[2].methods[0].virtual == 0 and
        dotnet.classes[2].methods[0].visibility == "private" and
        not defined dotnet.classes[2].methods[0].return_type
    }

    rule m1 {
      condition:
        dotnet.classes[2].methods[1].name == ".ctor" and
        dotnet.classes[2].methods[1].abstract == 0 and
        dotnet.classes[2].methods[1].final == 0 and
        dotnet.classes[2].methods[1].static == 0 and
        dotnet.classes[2].methods[1].virtual == 0 and
        dotnet.classes[2].methods[1].visibility == "private" and
        not defined dotnet.classes[2].methods[1].return_type
    }

    rule m2 {
      condition:
        dotnet.classes[2].methods[2].name == "mNaked" and
        dotnet.classes[2].methods[2].abstract == 0 and
        dotnet.classes[2].methods[2].final == 0 and
        dotnet.classes[2].methods[2].static == 1 and
        dotnet.classes[2].methods[2].virtual == 0 and
        dotnet.classes[2].methods[2].visibility == "private" and
        dotnet.classes[2].methods[2].return_type == "void"
    }

    rule m3 {
      condition:
        dotnet.classes[2].methods[3].name == "mPublic" and
        dotnet.classes[2].methods[3].abstract == 0 and
        dotnet.classes[2].methods[3].final == 1 and
        dotnet.classes[2].methods[3].static == 0 and
        dotnet.classes[2].methods[3].virtual == 1 and
        dotnet.classes[2].methods[3].visibility == "public"
    }

    rule m4 {
      condition:
        dotnet.classes[2].methods[4].name == "mPrivate" and
        dotnet.classes[2].methods[4].abstract == 0 and
        dotnet.classes[2].methods[4].final == 0 and
        dotnet.classes[2].methods[4].static == 0 and
        dotnet.classes[2].methods[4].virtual == 0 and
        dotnet.classes[2].methods[4].visibility == "private"
    }

    rule m5 {
      condition:
        dotnet.classes[2].methods[5].name == "mInternal" and
        dotnet.classes[2].methods[5].abstract == 1 and
        dotnet.classes[2].methods[5].final == 0 and
        dotnet.classes[2].methods[5].static == 0 and
        dotnet.classes[2].methods[5].virtual == 1 and
        dotnet.classes[2].methods[5].visibility == "internal"
    }

    rule m6 {
      condition:
        dotnet.classes[2].methods[6].name == "mProtected" and
        dotnet.classes[2].methods[6].abstract == 0 and
        dotnet.classes[2].methods[6].final == 0 and
        dotnet.classes[2].methods[6].static == 0 and
        dotnet.classes[2].methods[6].virtual == 1 and
        dotnet.classes[2].methods[6].visibility == "protected"
    }

    rule m7 {
      condition:
        dotnet.classes[2].methods[7].name == "mPrivateProtected" and
        dotnet.classes[2].methods[7].abstract == 0 and
        dotnet.classes[2].methods[7].final == 0 and
        dotnet.classes[2].methods[7].static == 0 and
        dotnet.classes[2].methods[7].virtual == 0 and
        dotnet.classes[2].methods[7].visibility == "private protected"
    }

    rule m8 {
      condition:
        dotnet.classes[2].methods[8].name == "mProtectedInternal" and
        dotnet.classes[2].methods[8].abstract == 0 and
        dotnet.classes[2].methods[8].final == 0 and
        dotnet.classes[2].methods[8].static == 1 and
        dotnet.classes[2].methods[8].virtual == 0 and
        dotnet.classes[2].methods[8].visibility == "protected internal"
    }
    "#,
    );

    let mem = std::fs::read("tests/assets/dotnet/classes.dll").unwrap();
    checker.check_rule_matches(
        &mem,
        &[
            "default:main",
            "default:m0",
            "default:m1",
            "default:m2",
            "default:m3",
            "default:m4",
            "default:m5",
            "default:m6",
            "default:m7",
            "default:m8",
        ],
    );
}

#[test]
fn test_constants() {
    check_file(
        r#"import "dotnet"
    rule main {
      condition:
        dotnet.number_of_user_strings == 3 and
        dotnet.user_strings[0] == "I\x00 \x00A\x00M\x00 \x00S\x00T\x00A\x00T\x00I\x00C\x00" and
        dotnet.user_strings[1] == "I\x00 \x00A\x00M\x00 \x00r\x00e\x00a\x00d\x00o\x00n\x00l\x00y\x00" and
        dotnet.user_strings[2] == "a\x00b\x00c\x00" and
        dotnet.number_of_constants == 1 and
        dotnet.constants[0] == "t\x00o\x00t\x00o\x00"
    }
    "#,
        "tests/assets/dotnet/constants.exe",
        true,
    );
}

#[test]
fn test_module_refs() {
    check_file(
        r#"import "dotnet"
    rule main {
      condition:
        dotnet.number_of_modulerefs == 2 and
        dotnet.modulerefs[0] == "Counter.dll" and
        dotnet.modulerefs[1] == "Strike.dll"
    }
    "#,
        "tests/assets/dotnet/assembly.dll",
        true,
    );
}

#[test]
fn test_coverage_0ca09bde() {
    let diffs = [];
    let path = "tests/assets/libyara/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}

#[test]
fn test_coverage_756684f4() {
    let diffs = [];
    let path = "tests/assets/libyara/data/756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}

#[test]
fn test_coverage_bad_dotnet_pe() {
    let diffs = [];
    let path = "tests/assets/libyara/data/bad_dotnet_pe";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}

#[test]
fn test_coverage_types() {
    let diffs = [];
    let path = "tests/assets/dotnet/types.exe";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}

#[test]
fn test_coverage_types2() {
    // TODO: fix this in YARA
    let diffs = [
        "dotnet.classes[1].methods[1].parameters[1].type",
        "dotnet.classes[1].methods[1].parameters[2].type",
        "dotnet.classes[1].methods[1].parameters[3].type",
        "dotnet.classes[1].methods[1].parameters[4].type",
        "dotnet.classes[1].methods[1].parameters[6].type",
        "dotnet.classes[1].methods[2].parameters[0].type",
        "dotnet.classes[1].methods[2].parameters[1].type",
        "dotnet.classes[1].methods[2].parameters[2].type",
        "dotnet.classes[1].methods[2].parameters[3].type",
    ];
    let path = "tests/assets/dotnet/types2.dll";
    compare_module_values_on_file(Dotnet, path, false, &diffs);

    // DLL so not considered when scanning as a process memory
    compare_module_values_on_file(Dotnet, path, true, &[]);
}

#[test]
fn test_coverage_assembly() {
    let diffs = [];
    let path = "tests/assets/dotnet/assembly.dll";
    compare_module_values_on_file(Dotnet, path, false, &diffs);

    // DLL so not considered when scanning as a process memory
    compare_module_values_on_file(Dotnet, path, true, &[]);
}

#[test]
fn test_coverage_classes() {
    let diffs = [];
    let path = "tests/assets/dotnet/classes.dll";
    compare_module_values_on_file(Dotnet, path, false, &diffs);

    // DLL so not considered when scanning as a process memory
    compare_module_values_on_file(Dotnet, path, true, &[]);
}

#[test]
fn test_coverage_constants() {
    let diffs = [];
    let path = "tests/assets/dotnet/constants.exe";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}
