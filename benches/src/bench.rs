//! Benchmarks boreal against libyara
use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};
use walkdir::WalkDir;

const RULES_SETS: [(&str, &str); 7] = [
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

/// Bench parsing + compilation duration
fn bench_compilation(c: &mut Criterion) {
    for (name, rules_path) in &RULES_SETS {
        let rules = get_yara_files_from_path(rules_path);

        let mut group = c.benchmark_group(format!("Parse and compile {}", name));
        group.sample_size(20);
        group.bench_with_input("boreal", &rules, |b, rules| {
            b.iter_with_large_drop(|| {
                let mut compiler = build_boreal_compiler();
                for path in rules {
                    compiler.add_rules_file(path).unwrap();
                }
                compiler.into_scanner()
            })
        });
        group.bench_with_input("libyara", &rules, |b, rules| {
            b.iter_with_large_drop(|| {
                let mut compiler = build_yara_compiler();
                for path in rules {
                    compiler = compiler.add_rules_file(path).unwrap();
                }
                compiler.compile_rules().unwrap()
            })
        });

        group.finish();
    }
}

/// Bench scanning single PE files with different amount of rules
fn bench_scan_pes(c: &mut Criterion) {
    for (name, rules_path) in &RULES_SETS {
        // Test files in assets/pes
        for pe_path in glob::glob("assets/pes/*").unwrap() {
            let pe_path = pe_path.unwrap();
            let mem = std::fs::read(&pe_path).expect("can read asset file");

            let mut boreal_compiler = build_boreal_compiler();
            let yara_compiler = build_yara_compiler();

            let rules = get_yara_files_from_path(rules_path);
            let yara_compiler = add_rules(&rules, &mut boreal_compiler, yara_compiler);

            let boreal_scanner = boreal_compiler.into_scanner();
            let yara_compiled_rules = yara_compiler.compile_rules().unwrap();

            let mut group =
                c.benchmark_group(format!("Scan {} using {} rules", pe_path.display(), name));
            group.sample_size(20);
            group.bench_with_input("boreal", &(boreal_scanner, &mem), |b, (scanner, mem)| {
                b.iter(|| scanner.scan_mem(mem))
            });
            group.bench_with_input("libyara", &(yara_compiled_rules, &mem), |b, (yara, mem)| {
                b.iter(|| yara.scan_mem(mem, 30))
            });

            group.finish();
        }
    }
}

fn bench_scan_process(c: &mut Criterion) {
    // To update accordingly when benching the scan of a process.
    let pid = 19766;

    for (name, rules_path) in &RULES_SETS {
        let mut boreal_compiler = build_boreal_compiler();
        let yara_compiler = build_yara_compiler();

        let rules = get_yara_files_from_path(rules_path);
        let yara_compiler = add_rules(&rules, &mut boreal_compiler, yara_compiler);

        let boreal_scanner = boreal_compiler.into_scanner();
        let yara_compiled_rules = yara_compiler.compile_rules().unwrap();

        let mut group = c.benchmark_group(format!("Scan process {} using {} rules", pid, name));
        group.sample_size(20);
        group.bench_with_input("boreal", &boreal_scanner, |b, scanner| {
            b.iter(|| scanner.scan_process(pid))
        });
        group.bench_with_input("libyara", &yara_compiled_rules, |b, yara| {
            b.iter(|| yara.scan_process(pid, 0))
        });

        group.finish();
    }
}

fn build_boreal_compiler() -> boreal::Compiler {
    let mut boreal_compiler = boreal::Compiler::new();
    let _ = boreal_compiler.define_symbol("owner", "owner");
    let _ = boreal_compiler.define_symbol("filename", "filename");
    let _ = boreal_compiler.define_symbol("filepath", "filepath");
    let _ = boreal_compiler.define_symbol("extension", "bin");
    let _ = boreal_compiler.define_symbol("filetype", "bin");
    boreal_compiler
}

fn build_yara_compiler() -> yara::Compiler {
    let mut yara_compiler = yara::Compiler::new().unwrap();
    let _ = yara_compiler.define_variable("owner", "owner");
    let _ = yara_compiler.define_variable("filename", "filename");
    let _ = yara_compiler.define_variable("filepath", "filepath");
    let _ = yara_compiler.define_variable("extension", "bin");
    let _ = yara_compiler.define_variable("filetype", "bin");
    yara_compiler
}

fn get_yara_files_from_path(path: &str) -> Vec<PathBuf> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();

            if entry.file_type().is_dir() {
                return None;
            }

            match entry.path().extension() {
                Some(v) => {
                    let ext = v.to_string_lossy();
                    if ext != "yar" && ext != "yara" {
                        return None;
                    }
                }
                None => return None,
            }

            Some(path.to_path_buf())
        })
        .collect()
}

fn add_rules(
    rules: &[PathBuf],
    boreal_compiler: &mut boreal::Compiler,
    mut yara_compiler: yara::Compiler,
) -> yara::Compiler {
    for path in rules {
        boreal_compiler.add_rules_file(path).unwrap_or_else(|err| {
            panic!(
                "cannot parse rules from {} for boreal: {:?}",
                path.display(),
                err
            )
        });
        yara_compiler = yara_compiler.add_rules_file(path).unwrap_or_else(|err| {
            panic!(
                "cannot parse rules from {} for libyara: {:?}",
                path.display(),
                err
            )
        });
    }

    yara_compiler
}

criterion_group!(
    benches,
    bench_compilation,
    bench_scan_pes,
    bench_scan_process
);
criterion_main!(benches);
