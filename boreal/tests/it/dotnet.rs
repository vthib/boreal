use boreal::module::Dotnet;

use crate::utils::compare_module_values_on_file;

#[test]
fn test_coverage_0ca09bde() {
    let diffs = [
        "dotnet.field_offsets",
        "dotnet.constants",
        "dotnet.assembly_refs",
        "dotnet.is_dotnet",
        "dotnet.modulerefs",
        "dotnet.assembly",
        "dotnet.version",
        "dotnet.number_of_modulerefs",
        "dotnet.number_of_field_offsets",
        "dotnet.number_of_assembly_refs",
        "dotnet.classes",
        "dotnet.number_of_classes",
        "dotnet.number_of_resources",
        "dotnet.user_strings",
        "dotnet.number_of_user_strings",
        "dotnet.number_of_streams",
        "dotnet.streams",
        "dotnet.module_name",
        "dotnet.resources",
    ];
    let path = "tests/assets/libyara/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}

#[test]
fn test_coverage_756684f4() {
    let diffs = [
        "dotnet.field_offsets",
        "dotnet.constants",
        "dotnet.number_of_constants",
        "dotnet.assembly_refs",
        "dotnet.modulerefs",
        "dotnet.assembly",
        "dotnet.number_of_modulerefs",
        "dotnet.number_of_field_offsets",
        "dotnet.number_of_assembly_refs",
        "dotnet.classes",
        "dotnet.number_of_classes",
        "dotnet.number_of_resources",
        "dotnet.user_strings",
        "dotnet.number_of_user_strings",
        "dotnet.module_name",
        "dotnet.resources",
    ];
    let path = "tests/assets/libyara/data/756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}

#[test]
fn test_coverage_bad_dotnet_pe() {
    let diffs = [
        "dotnet.field_offsets",
        "dotnet.constants",
        "dotnet.assembly_refs",
        "dotnet.is_dotnet",
        "dotnet.modulerefs",
        "dotnet.assembly",
        "dotnet.version",
        "dotnet.number_of_modulerefs",
        "dotnet.number_of_field_offsets",
        "dotnet.number_of_assembly_refs",
        "dotnet.classes",
        "dotnet.number_of_classes",
        "dotnet.number_of_resources",
        "dotnet.user_strings",
        "dotnet.number_of_user_strings",
        "dotnet.number_of_streams",
        "dotnet.streams",
        "dotnet.module_name",
        "dotnet.resources",
    ];
    let path = "tests/assets/libyara/data/bad_dotnet_pe";
    compare_module_values_on_file(Dotnet, path, false, &diffs);
    compare_module_values_on_file(Dotnet, path, true, &diffs);
}
