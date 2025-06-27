use boreal::compiler::CompilerParams;

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
            println!("skipping file {}", file.display());
            continue;
        } else {
            println!("checking file {}", file.display());
        }

        if directives.error.is_empty() {
            panic!("missing error directive for {}", file.display());
        }

        let mut compiler = if directives.without_yara {
            let mut compiler = Compiler::new_without_yara();
            let mut params = CompilerParams::default();
            if let Some(limit) = directives.max_strings_per_rule {
                // This is only done without yara because this is a global parameter
                // for yara, and will impact other tests...
                params = params.max_strings_per_rule(limit);
            }
            if cfg!(debug_assertions) {
                params = params.max_condition_depth(15);
            }
            compiler.set_params(params);
            compiler
        } else {
            Compiler::new()
        };

        if directives.disable_includes {
            let params = compiler.params().clone();
            compiler.set_params(params.disable_includes(true));
            if let Some(yara_compiler) = compiler.yara_compiler.as_mut() {
                yara_compiler.disable_include_directive();
            }
        }

        compiler.check_add_file_err(&file, directives.error);
    }
}

#[derive(Default)]
struct Directives<'a> {
    without_yara: bool,
    disable_includes: bool,
    error: &'a str,
    skip: bool,
    max_strings_per_rule: Option<usize>,
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
        if let Some(error) = dir.strip_prefix("error: ") {
            directives.error = error;
        } else if let Some(v) = dir.strip_prefix("max_strings_per_rule: ") {
            directives.max_strings_per_rule = Some(v.parse().unwrap());
        } else {
            match dir {
                "no libyara conformance" => directives.without_yara = true,
                "disable includes" => directives.disable_includes = true,
                "skip" => directives.skip = true,
                dir => panic!("unknown directive {dir}"),
            }
        }
    }

    directives
}

#[test]
fn test_disable_include() {
    let mut compiler = Compiler::new();
    compiler.set_params(CompilerParams::default().disable_includes(true));
    if let Some(yara_compiler) = compiler.yara_compiler.as_mut() {
        yara_compiler.disable_include_directive();
    }

    let rules = r#"include "toto.yar""#;
    compiler.check_add_rules_err(rules, "mem:1:1: error: includes are not allowed");
}
