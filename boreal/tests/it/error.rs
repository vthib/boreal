use crate::utils::{check_err, check_err_without_yara};

#[test]
fn test_invalid_files() {
    // Those files are not inlined here, so that they can be used to check how is the "pretty"
    // display of errors. This provides a nice way to check spans and stuff on those errors...
    for file in glob::glob("tests/assets/invalid_files/**/*.yar").unwrap() {
        let file = file.unwrap();

        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read file {:?}: {}", file, e));

        println!("checking file {:?}", file);
        if file.to_string_lossy().contains("str_to_int_range") {
            // Disable this test against yara because of
            // https://github.com/VirusTotal/yara/issues/1791, yara returning an error depends
            // on the platform
            check_err_without_yara(&contents, "");
        } else {
            // Maybe including the expected prefix in each file (as a comment) would be a nice
            // addition.
            check_err(&contents, "");
        }
    }
}
