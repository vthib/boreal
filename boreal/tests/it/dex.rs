use boreal::module::Dex;

use crate::libyara_compat::util::DEX_FILE;
use crate::utils::{check, compare_module_values_on_mem};

#[test]
fn test_coverage_dex_file() {
    let diffs = [
        // All those differences are fixed in
        // <https://github.com/VirusTotal/yara/pull/2069>
        "dex.DEX_FILE_MAGIC_035",
        "dex.DEX_FILE_MAGIC_036",
        "dex.DEX_FILE_MAGIC_037",
        "dex.DEX_FILE_MAGIC_038",
        "dex.DEX_FILE_MAGIC_039",
        "dex.field[0].static",
        "dex.field[0].instance",
        "dex.field[1].instance",
        "dex.field[1].static",
        "dex.header.signature",
        "dex.header.magic",
    ];
    compare_module_values_on_mem(Dex, "DEX_FILE", DEX_FILE, false, &diffs);
    compare_module_values_on_mem(Dex, "DEX_FILE", DEX_FILE, true, &diffs);
}

#[track_caller]
fn test_dex_file(cond: &str) {
    check(
        &format!("import \"dex\" rule test {{ condition: {cond} }}"),
        DEX_FILE,
        true,
    );
}

#[test]
fn test_has_method() {
    // class_name, method_name
    test_dex_file(r#"dex.has_method("Lcom/android/tools/ir/server/AppInfo;", "<clinit>") == 1"#);
    test_dex_file(r#"dex.has_method("LCOM/android/tools/ir/server/AppInfo;", "<clinit>") == 0"#);
    test_dex_file(r#"dex.has_method("Lcom/android/tools/ir/server/AppInfo;", "<CLINIT>") == 0"#);
    test_dex_file(r#"dex.has_method("Lcom", "<clinit>") == 0"#);
    test_dex_file(r#"dex.has_method("Lcom", "<init>") == 0"#);
    test_dex_file(r#"dex.has_method("Lcom/android/tools/ir/server/AppInfo;", "<init>") == 1"#);
    test_dex_file(r#"dex.has_method("Lcom/android/tools/ir/server/AppInfo;", "<it>") == 0"#);

    // method_name
    test_dex_file(r#"dex.has_method("<clinit>") == 1"#);
    test_dex_file(r#"dex.has_method("<linit>") == 0"#);
    test_dex_file(r#"dex.has_method("<init>") == 1"#);
    test_dex_file(r#"dex.has_method("<init") == 0"#);

    // class_name_regex, method_name_regex
    test_dex_file(r#"dex.has_method(/Lcom\/.*/, /<\w+>/) == 1"#);
    test_dex_file(r#"dex.has_method(/lcom\/.*/, /<\w+>/) == 0"#);
    test_dex_file(r#"dex.has_method(/Lcom\//, /<\w+/) == 1"#);

    // method_name_regex
    test_dex_file(r#"dex.has_method(/<\w+>/) == 1"#);
    test_dex_file(r#"dex.has_method(/<cl.*/) == 1"#);
    test_dex_file(r#"dex.has_method(/<\w+/) == 1"#);
    test_dex_file(r#"dex.has_method(/foo/) == 0"#);
}

#[test]
fn test_has_class() {
    // class_name
    test_dex_file(r#"dex.has_class("Lcom/android/tools/ir/server/AppInfo;") == 1"#);
    test_dex_file(r#"dex.has_class("LCOM/android/tools/ir/server/AppInfo;") == 0"#);
    test_dex_file(r#"dex.has_class("Lcom/") == 0"#);

    // class_name_regex
    test_dex_file(r#"dex.has_class(/^Lcom/) == 1"#);
    test_dex_file(r#"dex.has_class(/^lcom/) == 0"#);
    test_dex_file(r#"dex.has_class(/\w{7}\/\w{5}/) == 1"#);
    test_dex_file(r#"dex.has_class(/\/\w{3}\//) == 0"#);
}
