use crate::utils::{check_err, Compiler};

#[test]
fn test_invalid_files() {
    // Those files are not inlined here, so that they can be used to check how is the "pretty"
    // display of errors. This provides a nice way to check spans and stuff on those errors...
    for file in glob::glob("tests/assets/invalid_files/**/*.yar").unwrap() {
        let file = file.unwrap();

        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read file {file:?}: {e}"));

        println!("checking file {file:?}");
        if contents.starts_with("// [no libyara conformance]") {
            #[cfg(debug_assertions)]
            let compiler = {
                let mut compiler = Compiler::new_without_yara();
                let params = boreal::compiler::CompilerParams::default().max_condition_depth(15);
                compiler.set_params(params);
                compiler
            };
            #[cfg(not(debug_assertions))]
            let compiler = Compiler::new_without_yara();

            compiler.check_add_rules_err(&contents, "");
        } else {
            // Maybe including the expected prefix in each file (as a comment) would be a nice
            // addition.
            check_err(&contents, "");
        }
    }
}
