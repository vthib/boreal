use boreal::module::Dotnet;

use crate::utils::{compare_module_values_on_file, Checker};

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
        dotnet.number_of_classes == 3 and
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
