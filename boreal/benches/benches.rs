//! Benchmarks boreal against libyara
use criterion::{criterion_group, criterion_main, Criterion};
use walkdir::WalkDir;

/// Bench parsing + compilation duration
fn bench_compilation(c: &mut Criterion) {
    for (path, nb_rules) in &[
        ("benches/assets/panopticon/baseline_50.yar", 50),
        ("benches/assets/panopticon/baseline_100.yar", 100),
    ] {
        let rules = std::fs::read_to_string(path).unwrap();

        let mut group = c.benchmark_group(format!("Parse and compile {} rules", nb_rules));
        group.bench_with_input("boreal", &rules, |b, rules| {
            b.iter_with_large_drop(|| {
                let mut compiler = boreal::Compiler::new();
                compiler.add_rules_str(rules).unwrap();
                compiler.into_scanner()
            })
        });
        group.bench_with_input("libyara", &rules, |b, rules| {
            b.iter_with_large_drop(|| {
                let compiler = yara::Compiler::new().unwrap();
                let compiler = compiler.add_rules_str(rules).unwrap();
                compiler.compile_rules().unwrap()
            })
        });

        group.finish();
    }
}

/// Bench scanning a file filled with nul bytes
fn bench_scan_nul_file(c: &mut Criterion) {
    for (path, nb_rules) in [
        ("benches/assets/panopticon/baseline_50.yar", 50),
        ("benches/assets/panopticon/baseline_100.yar", 100),
        ("benches/assets/signature-base/yara", 5083),
    ] {
        // Test 100B, 200KB, 50MB
        for file_size in [100, 200 * 1024, 50 * 1024 * 1024] {
            let mem = vec![0; file_size];

            let mut boreal_compiler = boreal::Compiler::new();
            let yara_compiler = yara::Compiler::new().unwrap();
            let yara_compiler = add_rules(path, &mut boreal_compiler, yara_compiler);

            let boreal_scanner = boreal_compiler.into_scanner().unwrap();
            let yara_compiled_rules = yara_compiler.compile_rules().unwrap();

            let mut group =
                c.benchmark_group(format!("Scan {}B with {} rules", file_size, nb_rules));
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

fn add_rules(
    path: &str,
    boreal_compiler: &mut boreal::Compiler,
    mut yara_compiler: yara::Compiler,
) -> yara::Compiler {
    for entry in WalkDir::new(path) {
        let entry = entry.unwrap();
        let path = entry.path();

        if entry.file_type().is_dir() {
            continue;
        }

        let contents = std::fs::read_to_string(path).unwrap();

        boreal_compiler
            .add_rules_str(&contents)
            .unwrap_or_else(|err| {
                panic!(
                    "cannot parse rules from {} for boreal: {:?}",
                    path.display(),
                    err
                )
            });
        yara_compiler = yara_compiler
            .add_rules_str(&contents)
            .unwrap_or_else(|err| {
                panic!(
                    "cannot parse rules from {} for libyara: {:?}",
                    path.display(),
                    err
                )
            });
    }

    yara_compiler
}

criterion_group!(benches, bench_compilation, bench_scan_nul_file);
criterion_main!(benches);
