// See src/bench.rs

use std::path::PathBuf;

use walkdir::WalkDir;

pub const RULES_SETS: [(&str, &str); 7] = [
    // 100 rules, 1998 variables
    ("panopticon", "assets/panopticon/baseline_100.yar"),
    // 4297 rules, 23630 vars
    ("signature-base", "assets/signature-base/yara"),
    // 147 rules, 644 variables
    ("orion", "assets/orion"),
    // 632 rules, 1536 variables
    ("reversinglabs", "assets/reversinglabs"),
    // 167 rules, 1408 variables
    ("atr", "assets/atr"),
    // 16431 rules, 13155 variables
    ("icewater", "assets/icewater"),
    // 121 rules, 5390 variables
    ("c0ffee", "assets/c0ffee/rules.yar"),
    // Extremely slow
    // ("assets/yara-rules/index.yar", 12771),
];

pub fn get_yara_files_from_path(path: &str) -> Vec<PathBuf> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();

            if entry.file_type().is_dir() {
                return None;
            }

            entry.path().extension().and_then(|ext| {
                let ext = ext.to_string_lossy();
                if ext == "yar" || ext == "yara" {
                    Some(path.to_path_buf())
                } else {
                    None
                }
            })
        })
        .collect()
}

pub fn build_boreal_compiler() -> boreal::Compiler {
    let mut boreal_compiler = boreal::compiler::CompilerBuilder::new()
        .profile(boreal::compiler::CompilerProfile::Speed)
        .build();
    let _ = boreal_compiler.define_symbol("owner", "owner");
    let _ = boreal_compiler.define_symbol("filename", "filename");
    let _ = boreal_compiler.define_symbol("filepath", "filepath");
    let _ = boreal_compiler.define_symbol("extension", "bin");
    let _ = boreal_compiler.define_symbol("filetype", "bin");
    boreal_compiler
}

pub fn build_yara_compiler() -> yara::Compiler {
    let mut yara_compiler = yara::Compiler::new().unwrap();
    let _ = yara_compiler.define_variable("owner", "owner");
    let _ = yara_compiler.define_variable("filename", "filename");
    let _ = yara_compiler.define_variable("filepath", "filepath");
    let _ = yara_compiler.define_variable("extension", "bin");
    let _ = yara_compiler.define_variable("filetype", "bin");
    yara_compiler
}

pub fn build_yara_x_compiler<'a>() -> yara_x::Compiler<'a> {
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    let _ = compiler.define_global("owner", "owner");
    let _ = compiler.define_global("filename", "filename");
    let _ = compiler.define_global("filepath", "filepath");
    let _ = compiler.define_global("extension", "bin");
    let _ = compiler.define_global("filetype", "bin");
    compiler
}

pub fn build_boreal_scanner(rules: &[PathBuf]) -> boreal::Scanner {
    let mut boreal_compiler = build_boreal_compiler();

    for path in rules {
        boreal_compiler.add_rules_file(path).unwrap_or_else(|err| {
            panic!(
                "cannot parse rules from {} for boreal: {:?}",
                path.display(),
                err
            )
        });
    }
    boreal_compiler.into_scanner()
}

pub fn build_yara_rules(rules: &[PathBuf]) -> yara::Rules {
    let mut yara_compiler = build_yara_compiler();
    for path in rules {
        yara_compiler = yara_compiler.add_rules_file(path).unwrap_or_else(|err| {
            panic!(
                "cannot parse rules from {} for libyara: {:?}",
                path.display(),
                err
            )
        });
    }

    yara_compiler.compile_rules().unwrap()
}

pub fn build_yara_x_rules(rules: &[PathBuf]) -> yara_x::Rules {
    let mut yara_x_compiler = build_yara_x_compiler();
    for path in rules {
        yara_x_compiler
            .add_source(&*std::fs::read_to_string(path).unwrap())
            .unwrap_or_else(|err| {
                panic!(
                    "cannot parse rules from {} for yara_x: {:?}",
                    path.display(),
                    err
                )
            });
    }

    yara_x_compiler.build()
}
