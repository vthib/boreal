//! Benchmarks boreal against libyara
use std::path::PathBuf;

use boreal_benches::{
    build_boreal_compiler, build_boreal_scanner, build_yara_compiler, build_yara_rules,
    build_yara_x_compiler, build_yara_x_rules, get_yara_files_from_path, RULES_SETS,
};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};

fn setup_benches(c: &mut Criterion) {
    for (name, rules_path) in &RULES_SETS {
        let rules = get_yara_files_from_path(rules_path);

        bench_compilation(c, name, &rules);

        let boreal_speed_scanner = build_boreal_scanner(&rules, true);
        let boreal_memory_scanner = build_boreal_scanner(&rules, false);
        let mut yara_rules = build_yara_rules(&rules);
        let yara_x_rules = build_yara_x_rules(&rules);

        bench_scan_pes(
            c,
            name,
            &boreal_speed_scanner,
            &boreal_memory_scanner,
            &yara_rules,
            &yara_x_rules,
        );
        bench_scan_process(
            c,
            name,
            &boreal_speed_scanner,
            &boreal_memory_scanner,
            &yara_rules,
        );
        #[cfg(feature = "serialize")]
        bench_serialization(
            c,
            name,
            &boreal_speed_scanner,
            &boreal_memory_scanner,
            &yara_rules,
            &yara_x_rules,
        );
        #[cfg(feature = "serialize")]
        bench_deserialization(
            c,
            name,
            &boreal_speed_scanner,
            &boreal_memory_scanner,
            &mut yara_rules,
            &yara_x_rules,
        );
    }
}

/// Bench parsing + compilation duration
fn bench_compilation(c: &mut Criterion, rules_name: &str, rules: &[PathBuf]) {
    let mut group = c.benchmark_group(format!("Parse and compile {}", rules_name));
    group.sample_size(20);

    group.bench_with_input("boreal-speed", rules, |b, rules| {
        b.iter_with_large_drop(|| {
            let mut compiler = build_boreal_compiler(true);
            for path in rules {
                compiler.add_rules_file(path).unwrap();
            }
            compiler.finalize()
        })
    });
    group.bench_with_input("boreal-memory", rules, |b, rules| {
        b.iter_with_large_drop(|| {
            let mut compiler = build_boreal_compiler(false);
            for path in rules {
                compiler.add_rules_file(path).unwrap();
            }
            compiler.finalize()
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
    boreal_speed_scanner: &boreal::Scanner,
    boreal_memory_scanner: &boreal::Scanner,
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
        group.bench_with_input(
            "boreal-speed",
            &(boreal_speed_scanner, &mem),
            |b, (scanner, mem)| b.iter(|| scanner.scan_mem(mem)),
        );
        group.bench_with_input(
            "boreal-memory",
            &(boreal_memory_scanner, &mem),
            |b, (scanner, mem)| b.iter(|| scanner.scan_mem(mem)),
        );
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
    boreal_speed_scanner: &boreal::Scanner,
    boreal_memory_scanner: &boreal::Scanner,
    yara_rules: &yara::Rules,
) {
    // To update accordingly when benching the scan of a process.
    let pid = 19766;

    let mut group = c.benchmark_group(format!("Scan process {} using {} rules", pid, rules_name));
    group.sample_size(20);
    group.bench_with_input("boreal-speed", &boreal_speed_scanner, |b, scanner| {
        b.iter(|| scanner.scan_process(pid))
    });
    group.bench_with_input("boreal-memory", &boreal_memory_scanner, |b, scanner| {
        b.iter(|| scanner.scan_process(pid))
    });
    group.bench_with_input("libyara", &yara_rules, |b, rules| {
        b.iter(|| rules.scan_process(pid, 0))
    });

    group.finish();
}

#[cfg(feature = "serialize")]
fn bench_serialization(
    c: &mut Criterion,
    rules_name: &str,
    boreal_speed_scanner: &boreal::Scanner,
    boreal_memory_scanner: &boreal::Scanner,
    yara_rules: &yara::Rules,
    yara_x_rules: &yara_x::Rules,
) {
    let mut group = c.benchmark_group(format!("Serialize {}", rules_name));
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);

    group.bench_with_input("boreal-speed", &boreal_speed_scanner, |b, scanner| {
        b.iter_batched_ref(
            Vec::new,
            |mut data| scanner.to_bytes(&mut data).unwrap(),
            BatchSize::LargeInput,
        )
    });
    group.bench_with_input("boreal-memory", &boreal_memory_scanner, |b, scanner| {
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

#[cfg(feature = "serialize")]
fn bench_deserialization(
    c: &mut Criterion,
    rules_name: &str,
    boreal_speed_scanner: &boreal::Scanner,
    boreal_memory_scanner: &boreal::Scanner,
    yara_rules: &mut yara::Rules,
    yara_x_rules: &yara_x::Rules,
) {
    let mut group = c.benchmark_group(format!("Deserialize {}", rules_name));
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);

    let mut boreal_data = Vec::new();
    boreal_speed_scanner.to_bytes(&mut boreal_data).unwrap();
    group.bench_with_input("boreal-speed", &boreal_data, |b, data| {
        b.iter_with_large_drop(|| {
            boreal::Scanner::from_bytes_unchecked(
                data,
                boreal::scanner::DeserializeParams::default(),
            )
        })
    });

    let mut boreal_data = Vec::new();
    boreal_memory_scanner.to_bytes(&mut boreal_data).unwrap();
    group.bench_with_input("boreal-memory", &boreal_data, |b, data| {
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

criterion_group!(benches, setup_benches);
criterion_main!(benches);
