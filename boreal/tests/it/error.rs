use crate::utils::Compiler;

#[test]
fn test_invalid_files() {
    // Those files are not inlined here, so that they can be used to check how is the "pretty"
    // display of errors. This provides a nice way to check spans and stuff on those errors...
    for file in glob::glob("tests/assets/invalid_files/**/*.yar").unwrap() {
        let file = file.unwrap();

        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read file {file:?}: {e}"));

        // Files can start with comments that indicate directives.
        let directives = extract_directives(&contents);

        if directives.skip {
            println!("skipping file {file:?}");
            continue;
        } else {
            println!("checking file {file:?}");
        }

        let mut compiler = if directives.without_yara {
            if cfg!(debug_assertions) {
                let mut compiler = Compiler::new_without_yara();
                let params = boreal::compiler::CompilerParams::default().max_condition_depth(15);
                compiler.set_params(params);
                compiler
            } else {
                Compiler::new_without_yara()
            }
        } else {
            Compiler::new()
        };

        if directives.disable_includes {
            let params = compiler.params().clone();
            compiler.set_params(params.disable_includes(true));
        }

        compiler.check_add_rules_err(&contents, "");
    }
}

#[derive(Default)]
struct Directives {
    without_yara: bool,
    disable_includes: bool,
    skip: bool,
}

fn extract_directives(contents: &str) -> Directives {
    let mut directives = Directives::default();

    for line in contents.lines() {
        let Some(dir) = line.strip_prefix("// [") else {
            break;
        };
        let Some(dir) = dir.strip_suffix("]") else {
            break;
        };
        match dir {
            "no libyara conformance" => directives.without_yara = true,
            "disable includes" => directives.disable_includes = true,
            "skip" => directives.skip = true,
            dir => panic!("unknown directive {}", dir),
        }
    }

    directives
}
