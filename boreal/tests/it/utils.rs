use std::path::Path;

use boreal::{
    scan_params::{EarlyScanConfiguration, ScanParamsBuilder},
    ScanResult,
};

pub struct Checker {
    scanner: boreal::Scanner,
    yara_rules: Option<yara::Rules>,
}

pub struct Compiler {
    compiler: boreal::Compiler,
    yara_compiler: Option<yara::Compiler>,
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

    pub fn new_inner(with_yara: bool) -> Self {
        let mut compiler = boreal::Compiler::new();
        compiler.add_module(super::module_tests::Tests);

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
            panic!("parsing failed: {}", err.to_short_description("mem", rules));
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
            panic!(
                "add of file {} failed: {}",
                path.display(),
                err.to_short_description("mem", &std::fs::read_to_string(path).unwrap())
            );
        }
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_file(path).unwrap());
    }

    pub fn add_file_in_namespace(&mut self, path: &Path, ns: &str) {
        if let Err(err) = self.compiler.add_rules_file_in_namespace(path, ns) {
            panic!(
                "add of file {} failed: {}",
                path.display(),
                err.to_short_description("mem", &std::fs::read_to_string(path).unwrap())
            );
        }
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_file_with_namespace(path, ns).unwrap());
    }

    pub fn check_add_rules_err(mut self, rules: &str, expected_prefix: &str) {
        let err = self.compiler.add_rules_str(rules).unwrap_err();
        let desc = err.to_short_description("mem", rules);
        assert!(
            desc.starts_with(expected_prefix),
            "error: {}\nexpected prefix: {}",
            desc,
            expected_prefix
        );

        // Check libyara also rejects it
        if let Some(compiler) = self.yara_compiler.take() {
            assert!(
                compiler.add_rules_str(rules).is_err(),
                "conformity test failed for libyara"
            );
        }
    }

    define_symbol_compiler_method!(define_symbol_int, i64);
    define_symbol_compiler_method!(define_symbol_float, f64);
    define_symbol_compiler_method!(define_symbol_str, &str);
    define_symbol_compiler_method!(define_symbol_bool, bool);

    pub fn into_checker(self) -> Checker {
        Checker {
            scanner: self.compiler.into_scanner(),
            yara_rules: self.yara_compiler.map(|v| v.compile_rules().unwrap()),
        }
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

    #[track_caller]
    pub fn check(&self, mem: &[u8], expected_res: bool) {
        self.scanner().check(mem, expected_res);
    }

    #[track_caller]
    pub fn check_count(&self, mem: &[u8], count: usize) {
        check_boreal_inner(
            &self.scanner,
            ScanParamsBuilder::default(),
            mem,
            |res, desc| {
                assert_eq!(
                    res.matched_rules.len(),
                    count,
                    "test failed for boreal {}",
                    desc
                );
            },
        );

        if let Some(rules) = &self.yara_rules {
            let len = rules.scan_mem(mem, 1).unwrap().len();
            assert_eq!(len, count, "conformity test failed for libyara");
        }
    }

    // Check matches against a list of "<namespace>:<rule_name>" strings.
    #[track_caller]
    pub fn check_rule_matches(&self, mem: &[u8], expected_matches: &[&str]) {
        let mut expected: Vec<String> = expected_matches.iter().map(|v| v.to_string()).collect();
        expected.sort_unstable();
        check_boreal_inner(
            &self.scanner,
            ScanParamsBuilder::default(),
            mem,
            |res, desc| {
                let mut res: Vec<String> = res
                    .matched_rules
                    .into_iter()
                    .map(|v| {
                        if let Some(ns) = &v.namespace {
                            format!("{}:{}", ns, v.name)
                        } else {
                            format!("default:{}", v.name)
                        }
                    })
                    .collect();
                res.sort_unstable();
                assert_eq!(res, expected, "test failed for boreal {}", desc);
            },
        );

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let mut res: Vec<String> = res
                .iter()
                .map(|v| format!("{}:{}", v.namespace, v.identifier))
                .collect();
            res.sort_unstable();
            assert_eq!(res, expected, "conformity test failed for libyara");
        }
    }

    // Check matches against a list of [("<namespace>:<rule_name>", [("var_name", [(offset, length), ...]), ...]]
    #[track_caller]
    pub fn check_full_matches(&self, mem: &[u8], mut expected: FullMatches) {
        // We need to compute the full matches for this test
        let params = ScanParamsBuilder::default().compute_full_matches(true);
        check_boreal_inner(&self.scanner, params, mem, |res, desc| {
            let res = get_boreal_full_matches(&res);
            assert_eq!(res, expected, "test failed for boreal {}", desc);
        });

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let mut res = get_yara_full_matches(&res);
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
    }

    #[track_caller]
    pub fn check_boreal(&self, mem: &[u8], expected_res: bool) {
        check_boreal_inner(
            &self.scanner,
            ScanParamsBuilder::default(),
            mem,
            |res, desc| {
                let res = !res.matched_rules.is_empty();
                assert_eq!(res, expected_res, "test failed for boreal {}", desc);
            },
        );
    }

    #[track_caller]
    pub fn check_libyara(&self, mem: &[u8], expected_res: bool) {
        if let Some(rules) = &self.yara_rules {
            let res = !rules.scan_mem(mem, 1).unwrap().is_empty();
            assert_eq!(res, expected_res, "conformity test failed for libyara");
        }
    }

    #[track_caller]
    pub fn check_str_has_match(&self, mem: &[u8], expected_match: &[u8]) {
        check_boreal_inner(
            &self.scanner,
            ScanParamsBuilder::default(),
            mem,
            |res, desc| {
                let mut found = false;
                for r in res.matched_rules {
                    for var in r.matches {
                        for mat in var.matches {
                            if mat.data == expected_match {
                                found = true;
                            }
                        }
                    }
                }
                assert!(found, "test failed for boreal {}", desc);
            },
        );

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

    pub fn scanner(&self) -> Scanner {
        Scanner {
            scanner: self.scanner.clone(),
            yara_scanner: self.yara_rules.as_ref().map(|v| v.scanner().unwrap()),
        }
    }
}

pub struct Scanner<'a> {
    scanner: boreal::Scanner,
    yara_scanner: Option<yara::Scanner<'a>>,
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

impl<'a> Scanner<'a> {
    #[track_caller]
    pub fn check(&mut self, mem: &[u8], expected_res: bool) {
        self.check_boreal(mem, expected_res);
        self.check_libyara(mem, expected_res);
    }

    #[track_caller]
    pub fn check_boreal(&self, mem: &[u8], expected_res: bool) {
        check_boreal_inner(
            &self.scanner,
            ScanParamsBuilder::default(),
            mem,
            |res, desc| {
                let res = !res.matched_rules.is_empty();
                assert_eq!(res, expected_res, "test failed for boreal {}", desc);
            },
        );
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

fn check_boreal_inner<F>(
    scanner: &boreal::Scanner,
    builder: ScanParamsBuilder,
    mem: &[u8],
    checker: F,
) where
    F: Fn(ScanResult, &str),
{
    // Test with and without the use of the VariableSet optim. This ensures that we test both
    // cases (which can both be used in prod, but depends on the auto configuration).
    {
        let mut scanner = scanner.clone();
        scanner.set_scan_params(
            builder
                .clone()
                .early_scan(EarlyScanConfiguration::Disable)
                .build(),
        );
        let res = scanner.scan_mem(mem);
        checker(res, "without variable set");
    }

    {
        let mut scanner = scanner.clone();
        scanner.set_scan_params(
            builder
                .clone()
                .early_scan(EarlyScanConfiguration::Enable)
                .build(),
        );
        let res = scanner.scan_mem(mem);
        checker(res, "with variable set");
    }
}

// Parse and compile `rule`, then for each test,
// check that when running the rule on the given byte string, the
// result is the given bool value.
#[track_caller]
pub fn check_boreal(rule: &str, mem: &[u8], expected_res: bool) {
    let checker = Checker::new_without_yara(rule);
    checker.check(mem, expected_res);
}

#[track_caller]
pub fn check(rule: &str, mem: &[u8], expected_res: bool) {
    let checker = Checker::new(rule);
    checker.check(mem, expected_res);
}

#[track_caller]
pub fn check_count(rule: &str, mem: &[u8], expected_count: usize) {
    let checker = Checker::new(rule);
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

type FullMatches<'a> = Vec<(String, Vec<(&'a str, Vec<(&'a [u8], usize, usize)>)>)>;

fn get_boreal_full_matches<'a>(res: &'a ScanResult<'a>) -> FullMatches<'a> {
    res.matched_rules
        .iter()
        .map(|v| {
            let rule_name = if let Some(ns) = &v.namespace {
                format!("{}:{}", ns, v.name)
            } else {
                format!("default:{}", v.name)
            };
            let str_matches: Vec<_> = v
                .matches
                .iter()
                .map(|str_match| {
                    (
                        str_match.name,
                        str_match
                            .matches
                            .iter()
                            .map(|m| (&*m.data, m.offset, m.data.len()))
                            .collect(),
                    )
                })
                .collect();
            (rule_name, str_matches)
        })
        .collect()
}

fn get_yara_full_matches<'a>(res: &'a [yara::Rule]) -> FullMatches<'a> {
    res.iter()
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
                            .map(|m| (&*m.data, m.offset, m.length))
                            .collect(),
                    )
                })
                .collect();
            (rule_name, str_matches)
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
        {}
        and for all of ($*) : (# >= 0) // this part is just to remove "unused strings" errors
}}"#,
        condition
    )
}
