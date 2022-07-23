use crate::utils::check_err;

#[test]
fn test_invalid_files() {
    // Those files are not inlined here, so that they can be used to check how is the "pretty"
    // display of errors. This provides a nice way to check spans and stuff on those errors...
    for file in glob::glob("assets/invalid_files/**/*.yar").unwrap() {
        let file = file.unwrap();
        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read file {:?}: {}", file, e));

        println!("checking file {:?}", file);
        // Maybe including the expected prefix in each file (as a comment) would be a nice
        // addition.
        check_err(&contents, "");
    }
}
