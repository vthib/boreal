use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use boreal::compiler::CompilerParams;
use boreal::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use boreal::module::{StaticValue, Value as ModuleValue};
use boreal::scanner::{ScanError, ScanParams, ScanResult};

pub struct Checker {
    scanner: boreal::Scanner,
    yara_rules: Option<yara::Rules>,

    pub assert_success: bool,
    pub last_err: Option<ScanError>,
}

pub struct Compiler {
    pub compiler: boreal::Compiler,
    pub yara_compiler: Option<yara::Compiler>,
}

macro_rules! define_symbol_compiler_method {
    ($name:ident, $ty:ty) => {
        pub fn $name(&mut self, name: &str, v: $ty, expected_res: bool) {
            assert_eq!(self.compiler.define_symbol(name, v), expected_res);

            if let Some(compiler) = self.yara_compiler.as_mut() {
                let res = compiler.define_variable(name, v);
                assert_eq!(res.is_ok(), expected_res);
            }
        }
    };
}

impl Compiler {
    pub fn new() -> Self {
        Self::new_inner(true)
    }

    pub fn new_without_yara() -> Self {
        Self::new_inner(false)
    }

    fn new_inner(with_yara: bool) -> Self {
        let compiler = build_compiler(true);

        let mut this = Self {
            compiler,
            yara_compiler: if with_yara {
                Some(yara::Compiler::new().unwrap())
            } else {
                None
            },
        };

        // From libyara, to make some compat tests pass
        this.define_symbol_int("var_zero", 0, true);
        this.define_symbol_int("var_one", 1, true);
        this.define_symbol_bool("var_true", true, true);
        this.define_symbol_bool("var_false", false, true);

        // For our own tests
        this.define_symbol_int("sym_int", 1, true);
        this.define_symbol_bool("sym_bool", true, true);
        this.define_symbol_float("sym_float", 1.23, true);
        this.define_symbol_str("sym_str", "rge", true);

        this
    }

    pub fn add_rules(&mut self, rules: &str) {
        if let Err(err) = self.compiler.add_rules_str(rules) {
            panic!("parsing failed: {}", err);
        }
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_str(rules).unwrap());
    }

    pub fn add_rules_in_namespace(&mut self, rules: &str, ns: &str) {
        self.compiler.add_rules_str_in_namespace(rules, ns).unwrap();
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_str_with_namespace(rules, ns).unwrap());
    }

    pub fn add_file(&mut self, path: &Path) {
        if let Err(err) = self.compiler.add_rules_file(path) {
            panic!("add of file {} failed: {}", path.display(), err,);
        }
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_file(path).unwrap());
    }

    pub fn add_file_in_namespace(&mut self, path: &Path, ns: &str) {
        if let Err(err) = self.compiler.add_rules_file_in_namespace(path, ns) {
            panic!("add of file {} failed: {}", path.display(), err,);
        }
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_file_with_namespace(path, ns).unwrap());
    }

    #[track_caller]
    pub fn check_add_rules_err(mut self, rules: &str, expected_prefix: &str) {
        self.check_add_rules_err_boreal(rules, expected_prefix);

        // Check libyara also rejects it
        if let Some(compiler) = self.yara_compiler.take() {
            assert!(
                compiler.add_rules_str(rules).is_err(),
                "conformity test failed for libyara"
            );
        }
    }

    #[track_caller]
    pub fn check_add_rules_in_namespace_err(
        mut self,
        rules: &str,
        ns: &str,
        expected_prefix: &str,
    ) {
        let err = self
            .compiler
            .add_rules_str_in_namespace(rules, ns)
            .unwrap_err();
        let desc = format!("{}", err);
        assert!(
            desc.starts_with(expected_prefix),
            "error: {desc}\nexpected prefix: {expected_prefix}"
        );

        // Check libyara also rejects it
        if let Some(compiler) = self.yara_compiler.take() {
            assert!(
                compiler.add_rules_str_with_namespace(rules, ns).is_err(),
                "conformity test failed for libyara"
            );
        }
    }

    #[track_caller]
    pub fn check_add_rules_err_boreal(&mut self, rules: &str, expected_prefix: &str) {
        let err = self.compiler.add_rules_str(rules).unwrap_err();
        let desc = format!("{}", err);
        assert!(
            desc.starts_with(expected_prefix),
            "error: {desc}\nexpected prefix: {expected_prefix}"
        );
    }

    #[track_caller]
    pub fn check_add_file_err(mut self, file: &Path, expected_prefix: &str) {
        self.check_add_file_err_boreal(file, expected_prefix);

        // Check libyara also rejects it
        if let Some(compiler) = self.yara_compiler.take() {
            assert!(
                compiler.add_rules_file(file).is_err(),
                "conformity test failed for libyara"
            );
        }
    }

    #[track_caller]
    pub fn check_add_file_err_boreal(&mut self, path: &Path, expected_prefix: &str) {
        let err = self.compiler.add_rules_file(path).unwrap_err();
        let err = format!("{}", err);
        // Remove the prefix up to the "error: " string
        let desc = err.split("error: ").nth(1).unwrap();
        assert!(
            desc.starts_with(expected_prefix),
            "error: {desc}\nexpected prefix: {expected_prefix}"
        );
    }

    pub fn check_add_rules_warnings(mut self, rules: &str, expected_warnings_prefix: &[&str]) {
        let status = self.compiler.add_rules_str(rules).unwrap();
        let warnings: Vec<_> = status.warnings().map(|warn| format!("{}", warn)).collect();
        assert_eq!(warnings.len(), expected_warnings_prefix.len());
        for (desc, expected_suffix) in warnings.iter().zip(expected_warnings_prefix.iter()) {
            // Use ends_with to avoid the /tmp/... before the file path
            assert!(
                desc.ends_with(expected_suffix),
                "warning: {desc}\nexpected suffix: {expected_suffix}"
            );
        }

        // Check libyara accepts it.
        // TODO: add a way to get the warnings in yara-rust
        // For the moment, check the rule is not rejected at least.
        if let Some(compiler) = self.yara_compiler.take() {
            if let Err(err) = compiler.add_rules_str(rules) {
                panic!("conformity test failed for libyara: {err:?}");
            }
        }
    }
    pub fn set_include_callback<F>(&mut self, callback: F)
    where
        F: Fn(&str, Option<&Path>, &str) -> std::io::Result<String> + Clone + Send + Sync + 'static,
    {
        if let Some(compiler) = self.yara_compiler.as_mut() {
            let callback = callback.clone();
            compiler.set_include_callback(move |include_name, current_filename, ns| {
                callback(include_name, current_filename.map(Path::new), ns.unwrap()).ok()
            });
        }
        self.compiler.set_include_callback(callback);
    }

    define_symbol_compiler_method!(define_symbol_int, i64);
    define_symbol_compiler_method!(define_symbol_float, f64);
    define_symbol_compiler_method!(define_symbol_str, &str);
    define_symbol_compiler_method!(define_symbol_bool, bool);

    pub fn set_params(&mut self, params: CompilerParams) {
        self.compiler.set_params(params);
    }

    pub fn params(&self) -> &CompilerParams {
        self.compiler.params()
    }

    pub fn into_checker(self) -> Checker {
        Checker {
            scanner: self.compiler.finalize(),
            yara_rules: self.yara_compiler.map(|v| v.compile_rules().unwrap()),
            assert_success: true,
            last_err: None,
        }
    }
}

fn build_compiler(with_test_module: bool) -> boreal::Compiler {
    if with_test_module {
        boreal::compiler::CompilerBuilder::new()
            .add_module(super::module_tests::Tests)
            .build()
    } else {
        boreal::Compiler::new()
    }
}

impl Checker {
    pub fn new(rule: &str) -> Self {
        Self::new_inner(rule, true)
    }

    pub fn new_without_yara(rule: &str) -> Self {
        Self::new_inner(rule, false)
    }

    fn new_inner(rule: &str, with_yara: bool) -> Self {
        let mut compiler = if with_yara {
            Compiler::new()
        } else {
            Compiler::new_without_yara()
        };

        compiler.add_rules(rule);
        compiler.into_checker()
    }

    pub fn set_scan_params(&mut self, scan_params: ScanParams) {
        self.scanner.set_scan_params(scan_params);
    }

    #[track_caller]
    pub fn check(&mut self, mem: &[u8], expected_res: bool) {
        self.scanner().check(mem, expected_res);
    }

    #[track_caller]
    pub fn check_count(&mut self, mem: &[u8], count: usize) {
        let res = self.scan_mem(mem);
        assert_eq!(res.rules.len(), count, "test failed for boreal",);

        if let Some(rules) = &self.yara_rules {
            let len = rules.scan_mem(mem, 1).unwrap().len();
            assert_eq!(len, count, "conformity test failed for libyara");
        }
    }

    pub fn scan_mem(&mut self, mem: &[u8]) -> ScanResult {
        match self.scanner.scan_mem(mem) {
            Ok(v) => {
                self.last_err = None;
                v
            }
            Err((err, v)) => {
                if self.assert_success {
                    panic!("scan failed: {:?}", err);
                }
                self.last_err = Some(err);
                v
            }
        }
    }

    // Check matches against a list of "<namespace>:<rule_name>" strings.
    #[track_caller]
    pub fn check_rule_matches(&mut self, mem: &[u8], expected_matches: &[&str]) -> ScanResult {
        let mut expected: Vec<String> = expected_matches.iter().map(|v| v.to_string()).collect();
        expected.sort_unstable();

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let mut res: Vec<String> = res
                .iter()
                .map(|v| format!("{}:{}", v.namespace, v.identifier))
                .collect();
            res.sort_unstable();
            assert_eq!(res, expected, "conformity test failed for libyara");
        }

        let scan_res = self.scan_mem(mem);
        let mut res: Vec<String> = scan_res
            .rules
            .iter()
            .map(|v| format!("{}:{}", v.namespace, v.name))
            .collect();
        res.sort_unstable();
        assert_eq!(res, expected, "test failed for boreal");

        scan_res
    }

    // Check matches against a list of [("<namespace>:<rule_name>", [("var_name", [(offset, length), ...]), ...]]
    #[track_caller]
    pub fn check_full_matches(&mut self, mem: &[u8], expected: FullMatches) {
        // We need to compute the full matches for this test
        {
            let mut scanner = self.scanner.clone();
            scanner.set_scan_params(scanner.scan_params().clone().compute_full_matches(true));
            let res = scanner.scan_mem(mem).unwrap();
            let res = get_boreal_full_matches(&res);
            assert_eq!(res, expected, "test failed for boreal");
        }

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            check_yara_full_matches(&res, expected);
        }
    }

    #[track_caller]
    pub fn check_xor_matches(&mut self, mem: &[u8], expected: XorMatches) {
        // We need to compute the full matches for this test
        {
            let mut scanner = self.scanner.clone();
            scanner.set_scan_params(scanner.scan_params().clone().compute_full_matches(true));
            let res = scanner.scan_mem(mem).unwrap();
            let res = get_boreal_xor_matches(&res);
            assert_eq!(res, expected, "test failed for boreal");
        }

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let res = get_yara_xor_matches(&res);
            assert_eq!(res, expected, "conformity test failed for libyara");
        }
    }

    #[track_caller]
    #[cfg(feature = "process")]
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub fn check_process_full_matches(&mut self, pid: u32, expected: FullMatches) {
        // We need to compute the full matches for this test
        {
            let mut scanner = self.scanner.clone();
            scanner.set_scan_params(scanner.scan_params().clone().compute_full_matches(true));
            let res = scanner.scan_process(pid).unwrap();
            let res = get_boreal_full_matches(&res);
            assert_eq!(res, expected, "test failed for boreal");
        }

        if let Some(rules) = &self.yara_rules {
            let mut scanner = rules.scanner().unwrap();
            let res = scanner.scan_process(pid).unwrap();
            check_yara_full_matches(&res, expected);
        }
    }

    #[track_caller]
    pub fn check_boreal(&mut self, mem: &[u8], expected_res: bool) {
        let res = self.scan_mem(mem);
        let res = !res.rules.is_empty();
        assert_eq!(res, expected_res, "test failed for boreal");
    }

    #[track_caller]
    pub fn check_str_has_match(&mut self, mem: &[u8], expected_match: &[u8]) {
        let res = self.scan_mem(mem);
        let mut found = false;
        for r in res.rules {
            for var in r.matches {
                for mat in var.matches {
                    if &*mat.data == expected_match {
                        found = true;
                    }
                }
            }
        }
        assert!(found, "test failed for boreal");

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let mut found = false;
            for r in res {
                for var in r.strings {
                    for mat in var.matches {
                        if mat.data == expected_match {
                            found = true;
                        }
                    }
                }
            }
            assert!(found, "conformity test failed for libyara");
        }
    }

    pub fn set_process_memory_flag(&mut self) {
        let params = self.scanner.scan_params().clone();
        self.scanner.set_scan_params(params.process_memory(true));
    }

    #[track_caller]
    pub fn check_fragmented(&mut self, regions: &[(usize, Option<&[u8]>)], expected_res: bool) {
        let res = self
            .scanner
            .scan_fragmented(FragmentedSlices::new(regions))
            .unwrap();
        let res = !res.rules.is_empty();
        assert_eq!(res, expected_res, "test failed for boreal");

        if let Some(rules) = &self.yara_rules {
            let mut scanner = rules.scanner().unwrap();
            if self.scanner.scan_params().get_process_memory() {
                scanner.set_flags(yara::ScanFlags::PROCESS_MEMORY);
            }
            let res = scanner
                .scan_mem_blocks(YaraBlocks {
                    current: 0,
                    regions,
                })
                .unwrap();
            let res = !res.is_empty();
            assert_eq!(res, expected_res, "conformity test failed for libyara");
        }
    }

    #[track_caller]
    pub fn check_fragmented_full_matches(
        &self,
        regions: &[(usize, Option<&[u8]>)],
        expected: FullMatches,
    ) {
        // We need to compute the full matches for this test
        {
            let mut scanner = self.scanner.clone();
            scanner.set_scan_params(scanner.scan_params().clone().compute_full_matches(true));
            let res = scanner
                .scan_fragmented(FragmentedSlices {
                    regions,
                    current: None,
                })
                .unwrap();
            let res = get_boreal_full_matches(&res);
            assert_eq!(res, expected, "test failed for boreal");
        }

        if let Some(rules) = &self.yara_rules {
            let mut scanner = rules.scanner().unwrap();
            if self.scanner.scan_params().get_process_memory() {
                scanner.set_flags(yara::ScanFlags::PROCESS_MEMORY);
            }
            let res = scanner
                .scan_mem_blocks(YaraBlocks {
                    current: 0,
                    regions,
                })
                .unwrap();
            check_yara_full_matches(&res, expected);
        }
    }

    #[track_caller]
    #[cfg(feature = "process")]
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub fn check_process(&mut self, pid: u32, expected_res: bool) {
        let res = match self.scanner.scan_process(pid) {
            Ok(v) => {
                self.last_err = None;
                v
            }
            Err((err, v)) => {
                if self.assert_success {
                    panic!("scan failed: {:?}", err);
                }
                self.last_err = Some(err);
                v
            }
        };
        let res = !res.rules.is_empty();
        assert_eq!(res, expected_res, "test failed for boreal");

        if let Some(rules) = &self.yara_rules {
            let mut scanner = rules.scanner().unwrap();
            match scanner.scan_process(pid) {
                Ok(res) => {
                    let res = !res.is_empty();
                    assert_eq!(res, expected_res, "conformity test failed for libyara");
                }
                Err(err) => {
                    if self.assert_success {
                        panic!("yara scan failed: {:?}", err);
                    }
                }
            }
        }
    }

    pub fn scanner(&self) -> Scanner {
        Scanner {
            scanner: self.scanner.clone(),
            yara_scanner: self.yara_rules.as_ref().map(|v| v.scanner().unwrap()),
        }
    }

    pub fn capture_yara_logs(&mut self, mem: &[u8]) -> Vec<String> {
        let mut logs = Vec::new();

        let Some(rules) = &mut self.yara_rules else {
            return logs;
        };

        rules
            .scan_mem_callback(mem, 0, |msg| {
                if let yara::CallbackMsg::ConsoleLog(log) = msg {
                    logs.push(log.to_string_lossy().to_string());
                }
                yara::CallbackReturn::Continue
            })
            .unwrap();
        logs
    }
}

#[derive(Debug)]
pub struct FragmentedSlices<'a, 'b> {
    regions: &'b [(usize, Option<&'a [u8]>)],
    // Tuple of:
    // - Index to the current region
    // - offset into the region mem of the current chunk
    current: Option<(usize, usize)>,
}

impl<'a, 'b> FragmentedSlices<'a, 'b> {
    pub fn new(regions: &'b [(usize, Option<&'a [u8]>)]) -> Self {
        Self {
            regions,
            current: None,
        }
    }
}

impl FragmentedMemory for FragmentedSlices<'_, '_> {
    fn reset(&mut self) {
        self.current = None;
    }

    fn next(&mut self, params: &MemoryParams) -> Option<RegionDescription> {
        // Find next (index, offset) pair
        let (region_index, offset) = match self.current {
            Some((region_index, mut offset)) => {
                match params.memory_chunk_size {
                    // No chunking, just select the next
                    None => (region_index + 1, 0),
                    Some(chunk_size) => {
                        // Chunking, go to the next chunk of this region.
                        offset += chunk_size;
                        let next_region = match self.regions[region_index].1 {
                            None => true,
                            Some(mem) => offset >= mem.len(),
                        };
                        if next_region {
                            (region_index + 1, 0)
                        } else {
                            (region_index, offset)
                        }
                    }
                }
            }
            None => (0, 0),
        };
        self.current = Some((region_index, offset));

        if region_index < self.regions.len() {
            let region = self.regions[region_index];
            let len = region.1.map_or(10, |v| v[offset..].len());
            Some(RegionDescription {
                start: region.0,
                length: match params.memory_chunk_size {
                    Some(chunk_size) => std::cmp::min(chunk_size, len),
                    None => len,
                },
            })
        } else {
            None
        }
    }

    fn fetch(&mut self, params: &MemoryParams) -> Option<Region> {
        let (region_index, offset) = self.current?;

        self.regions.get(region_index).and_then(|(start, mem)| {
            let mem = &(*mem)?[offset..];
            let mem = match params.memory_chunk_size {
                Some(chunk_size) => &mem[..std::cmp::min(mem.len(), chunk_size)],
                None => mem,
            };
            Some(Region {
                start: *start,
                mem: &mem[..std::cmp::min(mem.len(), params.max_fetched_region_size)],
            })
        })
    }
}

pub struct Scanner<'a> {
    pub scanner: boreal::Scanner,
    pub yara_scanner: Option<yara::Scanner<'a>>,
}

macro_rules! define_symbol_scanner_method {
    ($name:ident, $ty:ty) => {
        #[track_caller]
        pub fn $name(&mut self, name: &str, v: $ty, expected_err: Option<&str>) {
            match self.scanner.define_symbol(name, v) {
                Ok(()) => assert!(expected_err.is_none(), "expected define_symbol to fail"),
                Err(err) => assert_eq!(expected_err.unwrap(), format!("{}", err)),
            };

            if let Some(scanner) = self.yara_scanner.as_mut() {
                match scanner.define_variable(name, v) {
                    Ok(()) => assert!(
                        expected_err.is_none(),
                        "expected define_symbol to fail in libyara"
                    ),
                    Err(_) => assert!(expected_err.is_some()),
                }
            }
        }
    };
}

impl Scanner<'_> {
    #[track_caller]
    pub fn check(&mut self, mem: &[u8], expected_res: bool) {
        self.check_boreal(mem, expected_res);
        self.check_libyara(mem, expected_res);
    }

    #[track_caller]
    pub fn check_boreal(&self, mem: &[u8], expected_res: bool) {
        let res = self.scanner.scan_mem(mem).unwrap();
        let res = !res.rules.is_empty();
        assert_eq!(res, expected_res, "test failed for boreal");
    }

    #[track_caller]
    pub fn check_libyara(&mut self, mem: &[u8], expected_res: bool) {
        if let Some(scanner) = &mut self.yara_scanner {
            let res = !scanner.scan_mem(mem).unwrap().is_empty();
            assert_eq!(res, expected_res, "conformity test failed for libyara");
        }
    }

    define_symbol_scanner_method!(define_symbol_int, i64);
    define_symbol_scanner_method!(define_symbol_float, f64);
    define_symbol_scanner_method!(define_symbol_str, &str);
    define_symbol_scanner_method!(define_symbol_bool, bool);
}

// Parse and compile `rule`, then for each test,
// check that when running the rule on the given byte string, the
// result is the given bool value.
#[track_caller]
pub fn check_boreal(rule: &str, mem: &[u8], expected_res: bool) {
    let mut checker = Checker::new_without_yara(rule);
    checker.check(mem, expected_res);
}

#[track_caller]
pub fn check(rule: &str, mem: &[u8], expected_res: bool) {
    let mut checker = Checker::new(rule);
    checker.check(mem, expected_res);
}

#[track_caller]
pub fn check_count(rule: &str, mem: &[u8], expected_count: usize) {
    let mut checker = Checker::new(rule);
    checker.check_count(mem, expected_count);
}

#[track_caller]
pub fn check_file(rule: &str, filepath: &str, expected_res: bool) {
    use std::io::Read;

    let mut f = std::fs::File::open(filepath).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();

    check(rule, &buffer, expected_res);
}

#[track_caller]
pub fn check_err(rule: &str, expected_prefix: &str) {
    let compiler = Compiler::new();
    compiler.check_add_rules_err(rule, expected_prefix);
}

#[track_caller]
pub fn check_warnings(rule: &str, expected_warnings: &[&str]) {
    let compiler = Compiler::new();
    compiler.check_add_rules_warnings(rule, expected_warnings);
}

pub type FullMatches<'a> = Vec<(String, Vec<(&'a str, Vec<(&'a [u8], usize, usize)>)>)>;
pub type XorMatches<'a> = Vec<(&'a str, Vec<(&'a [u8], usize, u8)>)>;

pub fn get_boreal_full_matches<'a>(res: &'a ScanResult<'a>) -> FullMatches<'a> {
    res.rules
        .iter()
        .map(|v| {
            let rule_name = format!("{}:{}", v.namespace, v.name);
            let str_matches: Vec<_> = v
                .matches
                .iter()
                .map(|str_match| {
                    (
                        str_match.name,
                        str_match
                            .matches
                            .iter()
                            .map(|m| (&*m.data, m.base + m.offset, m.length))
                            .collect(),
                    )
                })
                .collect();
            (rule_name, str_matches)
        })
        .collect()
}

fn check_yara_full_matches(res: &[yara::Rule], mut expected: FullMatches) {
    let mut res: FullMatches = res
        .iter()
        .map(|v| {
            let rule_name = format!("{}:{}", v.namespace, v.identifier);
            let str_matches: Vec<_> = v
                .strings
                .iter()
                .map(|str_match| {
                    (
                        // The identifier from yara starts with '$', not us.
                        // TODO: should we normalize this?
                        &str_match.identifier[1..],
                        str_match
                            .matches
                            .iter()
                            .map(|m| (&*m.data, m.base + m.offset, m.length))
                            .collect(),
                    )
                })
                .collect();
            (rule_name, str_matches)
        })
        .collect();
    // Yara still reports private strings, however they will always have
    // zero matches. We do not list private strings, so to really compare both,
    // we need to clean up all 0 matches in the yara results & expected results
    for s in &mut res {
        s.1.retain(|m| !m.1.is_empty());
    }
    for s in &mut expected {
        s.1.retain(|m| !m.1.is_empty());
    }
    assert_eq!(res, expected, "conformity test failed for libyara");
}

pub fn get_boreal_xor_matches<'a>(res: &'a ScanResult<'a>) -> XorMatches<'a> {
    assert_eq!(res.rules.len(), 1);
    res.rules[0]
        .matches
        .iter()
        .map(|str_match| {
            (
                str_match.name,
                str_match
                    .matches
                    .iter()
                    .map(|m| (&*m.data, m.offset, m.xor_key))
                    .collect(),
            )
        })
        .collect()
}

fn get_yara_xor_matches<'a>(res: &'a [yara::Rule]) -> XorMatches<'a> {
    assert_eq!(res.len(), 1);
    res[0]
        .strings
        .iter()
        .map(|str_match| {
            (
                // The identifier from yara starts with '$', not us.
                // TODO: should we normalize this?
                &str_match.identifier[1..],
                str_match
                    .matches
                    .iter()
                    .map(|m| (&*m.data, m.offset, m.xor_key))
                    .collect(),
            )
        })
        .collect()
}

pub fn build_rule(condition: &str) -> String {
    format!(
        r#"
import "tests"
rule a {{
    strings:
        $a0 = "a0"
        $a1 = "a1"
        $a2 = "a2"
        $b0 = "b0"
        $b1 = "b1"
        $c0 = "c0"
    condition:
        {condition}
        and for all of ($*) : (# >= 0) // this part is just to remove "unused strings" errors
}}"#
    )
}

/// Compare boreal & yara module values on a given file
pub fn compare_module_values_on_file(
    module_name: &str,
    path: &str,
    process_memory: bool,
    ignored_diffs: &[&str],
) {
    let mem = std::fs::read(path).unwrap();
    compare_module_values_on_mem(module_name, path, &mem, process_memory, ignored_diffs);
}

/// Compare boreal & yara module values on a given bytestring
pub fn compare_module_values_on_mem(
    module_name: &str,
    mem_name: &str,
    mem: &[u8],
    process_memory: bool,
    ignored_diffs: &[&str],
) {
    // Setup boreal scanner
    let mut compiler = build_compiler(false);
    compiler
        .add_rules_str(format!(
            "import \"{}\" rule a {{ condition: true }}",
            module_name
        ))
        .unwrap();
    let mut scanner = compiler.finalize();
    if process_memory {
        let params = scanner.scan_params().clone();
        scanner.set_scan_params(params.process_memory(true));
    }

    // Setup yara scanner
    let c = yara::Compiler::new().unwrap();
    let c = c
        .add_rules_str(&format!(
            "import \"{}\" rule a {{ condition: true }}",
            module_name
        ))
        .unwrap();
    let yara_rules = c.compile_rules().unwrap();
    let mut yara_scanner = yara_rules.scanner().unwrap();
    if process_memory {
        yara_scanner.set_flags(yara::ScanFlags::PROCESS_MEMORY);
    }

    // Retrieve boreal module values.
    let res = if process_memory {
        scanner
            .scan_fragmented(FragmentedSlices::new(&[(1000, Some(mem))]))
            .unwrap()
    } else {
        scanner.scan_mem(mem).unwrap()
    };

    let mut evaluated_module = res
        .modules
        .into_iter()
        .find_map(|evaluated_module| {
            if evaluated_module.module.get_name() == module_name {
                Some(evaluated_module)
            } else {
                None
            }
        })
        .unwrap();

    // Enrich value using the static values, so that it can be compared with yara's
    enrich_with_static_values(
        &mut evaluated_module.dynamic_values,
        evaluated_module.module.get_static_values(),
    );

    let yara_cb = |msg| {
        if let yara::CallbackMsg::ModuleImported(obj) = msg {
            let mut yara_value = convert_yara_obj_to_module_value(obj);

            // This is a hack to remove the "rich_signature" field from the pe module
            // when the file is not a PE. The PE module on yara has a lot of idiosyncracies,
            // but two of them conflates here: it is the only module that has values when it
            // does not parse anything (the is_pe field is set, either to 1 or 0), and it
            // always sets the rich_signature field even if it does not contain anything
            // (because it contains two functions).
            // This is very annoying to handle when comparing module values, so just remove
            // this dummy value when the file is not a pe, it serves no purpose.
            if let ModuleValue::Object(map) = &mut yara_value {
                if matches!(map.get("is_pe"), Some(ModuleValue::Integer(0))) {
                    map.remove("rich_signature");
                }
            }

            let mut diffs = Vec::new();
            compare_module_values(
                &evaluated_module.dynamic_values,
                yara_value,
                module_name,
                &mut diffs,
            );

            // Remove ignored diffs from the reported ones.
            for path in ignored_diffs {
                match diffs.iter().position(|d| &d.path == path) {
                    Some(pos) => {
                        diffs.remove(pos);
                    }
                    None => {
                        panic!("ignored diff on path {path} but there is no diff on this path",);
                    }
                }
            }

            if !diffs.is_empty() {
                panic!(
                    "found {} differences for module {} on {}{}: {:#?}",
                    diffs.len(),
                    module_name,
                    mem_name,
                    if process_memory {
                        " with process memory flag"
                    } else {
                        ""
                    },
                    diffs
                );
            }
        }
        yara::CallbackReturn::Continue
    };

    if process_memory {
        yara_scanner
            .scan_mem_blocks_callback(
                YaraBlocks {
                    current: 0,
                    regions: &[(1000, Some(mem))],
                },
                yara_cb,
            )
            .unwrap();
    } else {
        yara_scanner.scan_mem_callback(mem, yara_cb).unwrap();
    }
}

fn enrich_with_static_values(
    value: &mut ModuleValue,
    static_values: HashMap<&'static str, StaticValue>,
) {
    match value {
        ModuleValue::Object(obj) => {
            for (k, v) in static_values {
                if obj.insert(k, static_value_to_value(v)).is_some() {
                    panic!("collision on key {k}");
                }
            }
        }
        _ => unreachable!(),
    }
}

fn static_value_to_value(value: StaticValue) -> ModuleValue {
    match value {
        StaticValue::Integer(v) => ModuleValue::Integer(v),
        StaticValue::Float(v) => ModuleValue::Float(v),
        StaticValue::Bytes(v) => ModuleValue::Bytes(v),
        StaticValue::Boolean(v) => ModuleValue::Boolean(v),
        StaticValue::Object(v) => ModuleValue::Object(
            v.into_iter()
                .map(|(k, v)| (k, static_value_to_value(v)))
                .collect(),
        ),
        StaticValue::Function { fun, .. } => ModuleValue::Function(Arc::new(fun)),
    }
}

fn convert_yara_obj_to_module_value(obj: yara::YrObject) -> ModuleValue {
    use yara::YrObjectValue;

    match obj.value() {
        YrObjectValue::Integer(v) => ModuleValue::Integer(v),
        YrObjectValue::Float(v) => ModuleValue::Float(v),
        YrObjectValue::String(v) => ModuleValue::Bytes(v.to_vec()),
        YrObjectValue::Array(vec) => ModuleValue::Array(
            vec.into_iter()
                .map(|obj| {
                    obj.map(convert_yara_obj_to_module_value)
                        .unwrap_or(ModuleValue::Undefined)
                })
                .collect(),
        ),
        YrObjectValue::Dictionary(map) => ModuleValue::Dictionary(
            map.into_iter()
                .map(|(key, obj)| (key.to_vec(), convert_yara_obj_to_module_value(obj)))
                .collect(),
        ),
        YrObjectValue::Structure(vec) => ModuleValue::Object(
            vec.into_iter()
                .map(|obj| {
                    let key: &str = Box::leak(
                        String::from_utf8(obj.identifier().unwrap().to_vec())
                            .unwrap()
                            .into_boxed_str(),
                    );
                    (key, convert_yara_obj_to_module_value(obj))
                })
                .collect(),
        ),
        YrObjectValue::Function => ModuleValue::Function(Arc::new(|_, _| None)),
        YrObjectValue::Undefined => ModuleValue::Undefined,
    }
}

fn compare_module_values(
    boreal_value: &ModuleValue,
    yara_value: ModuleValue,
    path: &str,
    diffs: &mut Vec<Diff>,
) {
    match (boreal_value, yara_value) {
        (ModuleValue::Undefined, ModuleValue::Undefined) => (),
        (ModuleValue::Function(_), ModuleValue::Function(_)) => (),
        (ModuleValue::Integer(a), ModuleValue::Integer(b)) if *a == b => (),
        (ModuleValue::Float(a), ModuleValue::Float(b)) if *a == b => (),
        (ModuleValue::Bytes(a), ModuleValue::Bytes(b)) if *a == b => (),
        (ModuleValue::Object(a), ModuleValue::Object(mut b)) => {
            for (key, boreal_value) in a {
                let subpath = format!("{path}.{key}");
                match b.remove(key) {
                    Some(yara_value) => {
                        compare_module_values(boreal_value, yara_value, &subpath, diffs)
                    }
                    None => {
                        if !is_undefined(boreal_value) {
                            diffs
                                .push(Diff::new(&subpath, format!("extra value {boreal_value:?}")));
                        }
                    }
                }
            }
            for (key, yara_value) in b {
                if !is_undefined(&yara_value) {
                    diffs.push(Diff::new(
                        &format!("{path}.{key}"),
                        format!("missing value {yara_value:?}"),
                    ));
                }
            }
        }
        (ModuleValue::Array(a), ModuleValue::Array(b)) => {
            if a.len() == b.len() {
                for (i, (boreal_value, yara_value)) in a.iter().zip(b.into_iter()).enumerate() {
                    let subpath = format!("{path}[{i}]");
                    compare_module_values(boreal_value, yara_value, &subpath, diffs);
                }
            } else {
                diffs.push(Diff::new(
                    path,
                    format!("different lengths: {} != {}", a.len(), b.len()),
                ));
            }
        }
        (ModuleValue::Dictionary(a), ModuleValue::Dictionary(mut b)) => {
            for (key, boreal_value) in a {
                let subpath = format!("{}[\"{}\"]", path, std::str::from_utf8(key).unwrap());
                match b.remove(key) {
                    Some(yara_value) => {
                        compare_module_values(boreal_value, yara_value, &subpath, diffs)
                    }
                    None => {
                        if !is_undefined(boreal_value) {
                            diffs
                                .push(Diff::new(&subpath, format!("extra value {boreal_value:?}")));
                        }
                    }
                }
            }
        }
        (ModuleValue::Undefined, yara_value) => {
            if !is_undefined(&yara_value) {
                diffs.push(Diff::new(path, format!("missing value {yara_value:?}")));
            }
        }

        (a, b) => {
            diffs.push(Diff::new(path, format!("{a:?} != {b:?}")));
        }
    }
}

fn is_undefined(value: &ModuleValue) -> bool {
    match value {
        ModuleValue::Undefined => true,
        ModuleValue::Array(vec) => vec.is_empty(),
        ModuleValue::Dictionary(obj) => obj.is_empty(),
        ModuleValue::Object(obj) => {
            // An object where all values are considered undefined is allowed (same eval behavior).
            obj.values().all(is_undefined)
        }
        _ => false,
    }
}

impl Diff {
    fn new(path: &str, desc: String) -> Self {
        Self {
            path: path.to_owned(),
            desc,
        }
    }
}

struct Diff {
    path: String,
    desc: String,
}

impl std::fmt::Debug for Diff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Diff")
            .field("path", &self.path)
            .field("desc", &self.desc)
            .finish()
    }
}

pub fn join_str(a: &str, b: &str) -> Vec<u8> {
    format!("{}{}", a, b).into_bytes()
}

struct YaraBlocks<'a> {
    current: usize,
    regions: &'a [(usize, Option<&'a [u8]>)],
}

impl yara::MemoryBlockIterator for YaraBlocks<'_> {
    fn first(&mut self) -> Option<yara::MemoryBlock> {
        self.current = 0;
        self.next()
    }

    fn next(&mut self) -> Option<yara::MemoryBlock> {
        let (start, mem) = self.regions.get(self.current)?;
        self.current += 1;
        Some(yara::MemoryBlock::new(*start as u64, mem.unwrap_or(b"")))
    }
}

pub struct BinHelper {
    proc: std::process::Child,
    pub output: Vec<String>,
}

impl BinHelper {
    pub fn run(arg: &str) -> Self {
        // Path to current exe
        let path = std::env::current_exe().unwrap();
        // Path to "deps" dir
        let path = path.parent().unwrap();
        // Path to parent of deps dir, ie destination of build artifacts
        let path = path.parent().unwrap();
        // Now select the bin helper
        let path = path.join(if cfg!(windows) {
            "boreal-test-helpers.exe"
        } else {
            "boreal-test-helpers"
        });
        if !path.exists() {
            panic!(
                "File {} not found. \
                You need to compile the `boreal-test-helpers` crate to run this test",
                path.display()
            );
        }
        let mut child = std::process::Command::new(path)
            .arg(arg)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        // Accumulate read inputs until the "ready" line is found
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut lines = Vec::new();
        let mut buffer = String::new();
        loop {
            buffer.clear();
            stdout.read_line(&mut buffer).unwrap();
            if buffer.trim() == "ready" {
                break;
            }
            lines.push(buffer.trim().to_owned());
        }
        Self {
            proc: child,
            output: lines,
        }
    }

    pub fn pid(&self) -> u32 {
        self.proc.id()
    }
}

impl Drop for BinHelper {
    fn drop(&mut self) {
        drop(self.proc.kill());
        drop(self.proc.wait());
    }
}
