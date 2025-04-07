//! Benchmarks boreal against libyara
use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
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

fn setup_benches(c: &mut Criterion) {
    for (name, rules_path) in &RULES_SETS {
        let rules = get_yara_files_from_path(rules_path);

        bench_compilation(c, name, &rules);

        let boreal_scanner = build_boreal_scanner(&rules);
        let mut yara_rules = build_yara_rules(&rules);
        let yara_x_rules = build_yara_x_rules(&rules);

        bench_scan_pes(c, name, &boreal_scanner, &yara_rules, &yara_x_rules);
        bench_scan_process(c, name, &boreal_scanner, &yara_rules);
        bench_serialization(c, name, &boreal_scanner, &yara_rules, &yara_x_rules);
        bench_deserialization(c, name, &boreal_scanner, &mut yara_rules, &yara_x_rules);
    }
}

/// Bench parsing + compilation duration
fn bench_compilation(c: &mut Criterion, rules_name: &str, rules: &[PathBuf]) {
    let mut group = c.benchmark_group(format!("Parse and compile {}", rules_name));
    group.sample_size(20);

    group.bench_with_input("boreal", rules, |b, rules| {
        b.iter_with_large_drop(|| {
            let mut compiler = build_boreal_compiler();
            for path in rules {
                compiler.add_rules_file(path).unwrap();
            }
            compiler.into_scanner()
        })
    });
    group.bench_with_input("libyara", rules, |b, rules| {
        b.iter_with_large_drop(|| {
            let mut compiler = build_yara_compiler();
            for path in rules {
                compiler = compiler.add_rules_file(path).unwrap();
            }
            compiler.compile_rules().unwrap()
        })
    });
    group.bench_with_input("yara-x", rules, |b, rules| {
        b.iter_with_large_drop(|| {
            let mut compiler = build_yara_x_compiler();
            for path in rules {
                compiler
                    .add_source(&*std::fs::read_to_string(path).unwrap())
                    .unwrap();
            }
            compiler.build()
        })
    });

    group.finish();
}

/// Bench scanning single PE files with different amount of rules
fn bench_scan_pes(
    c: &mut Criterion,
    rules_name: &str,
    boreal_scanner: &boreal::Scanner,
    yara_rules: &yara::Rules,
    yara_x_rules: &yara_x::Rules,
) {
    // Test files in assets/pes
    for pe_path in glob::glob("assets/pes/*").unwrap() {
        let pe_path = pe_path.unwrap();
        let mem = std::fs::read(&pe_path).expect("can read asset file");

        let mut group = c.benchmark_group(format!(
            "Scan {} using {} rules",
            pe_path.display(),
            rules_name
        ));
        group.sample_size(20);
        group.bench_with_input("boreal", &(boreal_scanner, &mem), |b, (scanner, mem)| {
            b.iter(|| scanner.scan_mem(mem))
        });
        group.bench_with_input("libyara", &(yara_rules, &mem), |b, (rules, mem)| {
            b.iter(|| rules.scan_mem(mem, 30))
        });
        group.bench_with_input("yara-x", &(yara_x_rules, &mem), |b, (rules, mem)| {
            b.iter_batched_ref(
                || yara_x::Scanner::new(rules),
                |scanner| {
                    let _r = scanner.scan(mem);
                },
                BatchSize::LargeInput,
            )
        });

        group.finish();
    }
}

fn bench_scan_process(
    c: &mut Criterion,
    rules_name: &str,
    boreal_scanner: &boreal::Scanner,
    yara_rules: &yara::Rules,
) {
    // To update accordingly when benching the scan of a process.
    let pid = 19766;

    let mut group = c.benchmark_group(format!("Scan process {} using {} rules", pid, rules_name));
    group.sample_size(20);
    group.bench_with_input("boreal", &boreal_scanner, |b, scanner| {
        b.iter(|| scanner.scan_process(pid))
    });
    group.bench_with_input("libyara", &yara_rules, |b, rules| {
        b.iter(|| rules.scan_process(pid, 0))
    });

    group.finish();
}

fn bench_serialization(
    c: &mut Criterion,
    rules_name: &str,
    boreal_scanner: &boreal::Scanner,
    yara_rules: &yara::Rules,
    yara_x_rules: &yara_x::Rules,
) {
    let mut group = c.benchmark_group(format!("Serialize {}", rules_name));
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);

    group.bench_with_input("boreal", &boreal_scanner, |b, scanner| {
        b.iter_batched_ref(
            Vec::new,
            |mut data| scanner.to_bytes(&mut data).unwrap(),
            BatchSize::LargeInput,
        )
    });

    //FIXME: serialization does not need mut
    let ptr: *mut std::ffi::c_void = std::ptr::from_ref(yara_rules).cast_mut().cast();
    group.bench_with_input("yara", &ptr, move |b, ptr| {
        b.iter_batched_ref(
            Vec::new,
            |mut data| {
                let rules: &mut yara::Rules =
                    unsafe { ptr.cast::<yara::Rules>().as_mut().unwrap() };
                rules.save_to_stream(&mut data).unwrap()
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_with_input("yara-x", yara_x_rules, move |b, rules| {
        b.iter_with_large_drop(|| rules.serialize().unwrap())
    });

    group.finish();
}

fn bench_deserialization(
    c: &mut Criterion,
    rules_name: &str,
    boreal_scanner: &boreal::Scanner,
    yara_rules: &mut yara::Rules,
    yara_x_rules: &yara_x::Rules,
) {
    let mut group = c.benchmark_group(format!("Deserialize {}", rules_name));
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);

    let mut boreal_data = Vec::new();
    boreal_scanner.to_bytes(&mut boreal_data).unwrap();
    group.bench_with_input("boreal", &boreal_data, |b, data| {
        b.iter_with_large_drop(|| {
            boreal::Scanner::from_bytes_unchecked(
                data,
                boreal::scanner::DeserializeParams::default(),
            )
        })
    });

    let mut yara_data = Vec::new();
    yara_rules.save_to_stream(&mut yara_data).unwrap();
    group.bench_with_input("yara", &yara_data, |b, data| {
        b.iter_with_large_drop(|| yara::Rules::load_from_stream(&**data).unwrap())
    });

    let yara_x_data = yara_x_rules.serialize().unwrap();
    group.bench_with_input("yara-x", &yara_x_data, move |b, data| {
        b.iter_with_large_drop(|| yara_x::Rules::deserialize(data).unwrap())
    });

    group.finish();
}

fn build_boreal_compiler() -> boreal::Compiler {
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

fn build_yara_compiler() -> yara::Compiler {
    let mut yara_compiler = yara::Compiler::new().unwrap();
    let _ = yara_compiler.define_variable("owner", "owner");
    let _ = yara_compiler.define_variable("filename", "filename");
    let _ = yara_compiler.define_variable("filepath", "filepath");
    let _ = yara_compiler.define_variable("extension", "bin");
    let _ = yara_compiler.define_variable("filetype", "bin");
    yara_compiler
}

fn build_yara_x_compiler<'a>() -> yara_x::Compiler<'a> {
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    let _ = compiler.define_global("owner", "owner");
    let _ = compiler.define_global("filename", "filename");
    let _ = compiler.define_global("filepath", "filepath");
    let _ = compiler.define_global("extension", "bin");
    let _ = compiler.define_global("filetype", "bin");
    compiler
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

fn build_boreal_scanner(rules: &[PathBuf]) -> boreal::Scanner {
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

fn build_yara_rules(rules: &[PathBuf]) -> yara::Rules {
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

fn build_yara_x_rules(rules: &[PathBuf]) -> yara_x::Rules {
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

criterion_group!(benches, setup_benches);
criterion_main!(benches);
