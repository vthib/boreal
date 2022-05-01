use boreal::{Compiler, Scanner};

pub struct Checker {
    scanner: Scanner,
    yara_rules: Option<yara::Rules>,
}

impl Checker {
    pub fn new(rule: &str) -> Self {
        Self::new_inner(rule, true)
    }

    pub fn new_without_yara(rule: &str) -> Self {
        Self::new_inner(rule, false)
    }

    fn new_inner(rule: &str, with_yara: bool) -> Self {
        let mut compiler = new_compiler();
        if let Err(err) = compiler.add_rules_str(&rule) {
            panic!("parsing failed: {}", err.to_short_description("mem", rule));
        }

        let yara_rules = if with_yara {
            let compiler = yara::Compiler::new().unwrap();
            let compiler = compiler.add_rules_str(rule).unwrap();
            Some(compiler.compile_rules().unwrap())
        } else {
            None
        };

        Self {
            scanner: compiler.into_scanner(),
            yara_rules,
        }
    }

    #[track_caller]
    pub fn check(&self, mem: &[u8], expected_res: bool) {
        self.check_boreal(mem, expected_res);

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap().len() > 0;
            assert_eq!(res, expected_res, "conformity test failed for libyara");
        }
    }

    #[track_caller]
    pub fn check_boreal(&self, mem: &[u8], expected_res: bool) {
        let res = self.scanner.scan_mem(mem);
        let res = res.matching_rules.len() > 0;
        assert_eq!(res, expected_res, "test failed for boreal");
    }
}

pub fn new_compiler() -> Compiler {
    let mut compiler = Compiler::new();
    compiler.add_module(super::module_tests::Tests);
    compiler
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
pub fn check_file(rule: &str, filepath: &str, expected_res: bool) {
    use std::io::Read;

    let mut f = std::fs::File::open(filepath).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();

    check(rule, &buffer, expected_res);
}

#[track_caller]
pub fn check_err(rule: &str, expected_prefix: &str) {
    let mut compiler = new_compiler();
    let err = compiler.add_rules_str(&rule).unwrap_err();
    let desc = err.to_short_description("mem", rule);
    assert!(
        desc.starts_with(expected_prefix),
        "error: {}\nexpected prefix: {}",
        desc,
        expected_prefix
    );

    // Check libyara also rejects it
    let compiler = yara::Compiler::new().unwrap();
    assert!(compiler.add_rules_str(rule).is_err());
}
