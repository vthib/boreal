use boreal::module::Dotnet;

use crate::utils::compare_module_values_on_file;

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
