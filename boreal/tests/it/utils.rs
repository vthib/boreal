pub struct Checker {
    scanner: boreal::Scanner,
    yara_rules: Option<yara::Rules>,
}

pub struct Compiler {
    compiler: boreal::Compiler,
    yara_compiler: Option<yara::Compiler>,
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
        Self {
            compiler,
            yara_compiler: if with_yara {
                Some(yara::Compiler::new().unwrap())
            } else {
                None
            },
        }
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
            assert!(compiler.add_rules_str(rules).is_err());
        }
    }

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
        self.check_boreal(mem, expected_res);

        if let Some(rules) = &self.yara_rules {
            let res = !rules.scan_mem(mem, 1).unwrap().is_empty();
            assert_eq!(res, expected_res, "conformity test failed for libyara");
        }
    }

    #[track_caller]
    pub fn check_count(&self, mem: &[u8], count: usize) {
        let res = self.scanner.scan_mem(mem);
        assert_eq!(res.len(), count, "test failed for boreal");

        if let Some(rules) = &self.yara_rules {
            let len = rules.scan_mem(mem, 1).unwrap().len();
            assert_eq!(len, count, "conformity test failed for libyara");
        }
    }

    // Check matches against a list of "<namespace>:<rule_name>" strings.
    #[track_caller]
    pub fn check_matches(&self, mem: &[u8], expected_matches: &[&str]) {
        let expected: Vec<String> = expected_matches.iter().map(|v| v.to_string()).collect();
        let res = self.scanner.scan_mem(mem);
        let res: Vec<String> = res
            .into_iter()
            .map(|v| {
                if let Some(ns) = &v.namespace {
                    format!("{}:{}", ns, v.name)
                } else {
                    format!("default:{}", v.name)
                }
            })
            .collect();
        assert_eq!(res, expected, "test failed for boreal");

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let res: Vec<String> = res
                .iter()
                .map(|v| format!("{}:{}", v.namespace, v.identifier))
                .collect();
            assert_eq!(res, expected, "conformity test failed for libyara");
        }
    }

    #[track_caller]
    pub fn check_boreal(&self, mem: &[u8], expected_res: bool) {
        let res = self.scanner.scan_mem(mem);
        let res = !res.is_empty();
        assert_eq!(res, expected_res, "test failed for boreal");
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
