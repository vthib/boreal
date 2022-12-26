use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use boreal::module::{Module, StaticValue, Value as ModuleValue};
use boreal::scanner::{ScanParams, ScanResult};

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
            panic!("parsing failed: {}", add_rule_error_get_desc(&err, rules));
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
                add_rule_error_get_desc(&err, ""),
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
                add_rule_error_get_desc(&err, ""),
            );
        }
        self.yara_compiler = self
            .yara_compiler
            .take()
            .map(|compiler| compiler.add_rules_file_with_namespace(path, ns).unwrap());
    }

    #[track_caller]
    pub fn check_add_rules_err(mut self, rules: &str, expected_prefix: &str) {
        let err = self.compiler.add_rules_str(rules).unwrap_err();
        let desc = add_rule_error_get_desc(&err, rules);
        assert!(
            desc.starts_with(expected_prefix),
            "error: {desc}\nexpected prefix: {expected_prefix}"
        );

        // Check libyara also rejects it
        if let Some(compiler) = self.yara_compiler.take() {
            assert!(
                compiler.add_rules_str(rules).is_err(),
                "conformity test failed for libyara"
            );
        }
    }

    pub fn check_add_rules_warnings(mut self, rules: &str, expected_warnings_prefix: &[&str]) {
        let status = self.compiler.add_rules_str(rules).unwrap();
        let warnings: Vec<_> = status
            .warnings()
            .map(|warn| add_rule_error_get_desc(warn, rules))
            .collect();
        assert_eq!(warnings.len(), expected_warnings_prefix.len());
        for (desc, expected_prefix) in warnings.iter().zip(expected_warnings_prefix.iter()) {
            assert!(
                desc.starts_with(expected_prefix),
                "warning: {desc}\nexpected prefix: {expected_prefix}"
            );
        }

        // Check libyara also rejects it
        // TODO: add a way to get the warnings in yara-rust
        // For the moment, check the rule is not rejected at least.
        if let Some(compiler) = self.yara_compiler.take() {
            if let Err(err) = compiler.add_rules_str(rules) {
                panic!("conformity test failed for libyara: {err:?}");
            }
        }
    }

    define_symbol_compiler_method!(define_symbol_int, i64);
    define_symbol_compiler_method!(define_symbol_float, f64);
    define_symbol_compiler_method!(define_symbol_str, &str);
    define_symbol_compiler_method!(define_symbol_bool, bool);

    pub fn set_params(&mut self, params: boreal::compiler::CompilerParams) {
        self.compiler.set_params(params);
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

    pub fn set_scan_params(&mut self, scan_params: ScanParams) {
        self.scanner.set_scan_params(scan_params);
    }

    #[track_caller]
    pub fn check(&self, mem: &[u8], expected_res: bool) {
        self.scanner().check(mem, expected_res);
    }

    #[track_caller]
    pub fn check_count(&self, mem: &[u8], count: usize) {
        let res = self.scanner.scan_mem(mem);
        assert_eq!(res.matched_rules.len(), count, "test failed for boreal",);

        if let Some(rules) = &self.yara_rules {
            let len = rules.scan_mem(mem, 1).unwrap().len();
            assert_eq!(len, count, "conformity test failed for libyara");
        }
    }

    // Check matches against a list of "<namespace>:<rule_name>" strings.
    #[track_caller]
    pub fn check_rule_matches(&self, mem: &[u8], expected_matches: &[&str]) -> ScanResult {
        let mut expected: Vec<String> = expected_matches.iter().map(|v| v.to_string()).collect();
        expected.sort_unstable();
        let scan_res = self.scanner.scan_mem(mem);
        let mut res: Vec<String> = scan_res
            .matched_rules
            .iter()
            .map(|v| {
                if let Some(ns) = &v.namespace {
                    format!("{}:{}", ns, v.name)
                } else {
                    format!("default:{}", v.name)
                }
            })
            .collect();
        res.sort_unstable();
        assert_eq!(res, expected, "test failed for boreal");

        if let Some(rules) = &self.yara_rules {
            let res = rules.scan_mem(mem, 1).unwrap();
            let mut res: Vec<String> = res
                .iter()
                .map(|v| format!("{}:{}", v.namespace, v.identifier))
                .collect();
            res.sort_unstable();
            assert_eq!(res, expected, "conformity test failed for libyara");
        }

        scan_res
    }

    // Check matches against a list of [("<namespace>:<rule_name>", [("var_name", [(offset, length), ...]), ...]]
    #[track_caller]
    pub fn check_full_matches(&self, mem: &[u8], mut expected: FullMatches) {
        // We need to compute the full matches for this test
        {
            let mut scanner = self.scanner.clone();
            scanner.set_scan_params(scanner.scan_params().clone().compute_full_matches(true));
            let res = scanner.scan_mem(mem);
            let res = get_boreal_full_matches(&res);
            assert_eq!(res, expected, "test failed for boreal");
        }

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
        let res = self.scanner.scan_mem(mem);
        let res = !res.matched_rules.is_empty();
        assert_eq!(res, expected_res, "test failed for boreal");
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
        let res = self.scanner.scan_mem(mem);
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
        let res = self.scanner.scan_mem(mem);
        let res = !res.matched_rules.is_empty();
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

#[track_caller]
pub fn check_warnings(rule: &str, expected_warnings: &[&str]) {
    let compiler = Compiler::new();
    compiler.check_add_rules_warnings(rule, expected_warnings);
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
                            .map(|m| (&*m.data, m.offset, m.length))
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
        {condition}
        and for all of ($*) : (# >= 0) // this part is just to remove "unused strings" errors
}}"#
    )
}

fn add_rule_error_get_desc(err: &boreal::compiler::AddRuleError, rules: &str) -> String {
    match &err.path {
        Some(path) => err.to_short_description(
            &path.file_name().unwrap().to_string_lossy(),
            &std::fs::read_to_string(path).unwrap(),
        ),
        None => err.to_short_description("mem", rules),
    }
}

/// Compare boreal & yara module values on a given file
pub fn compare_module_values_on_file<M: Module>(module: M, path: &str, ignored_diffs: &[&str]) {
    let mem = std::fs::read(path).unwrap();
    compare_module_values_on_mem(module, path, &mem, ignored_diffs);
}

/// Compare boreal & yara module values on a given bytestring
pub fn compare_module_values_on_mem<M: Module>(
    module: M,
    mem_name: &str,
    mem: &[u8],
    ignored_diffs: &[&str],
) {
    let mut compiler = boreal::Compiler::new();
    compiler
        .add_rules_str(&format!(
            "import \"{}\" rule a {{ condition: true }}",
            module.get_name()
        ))
        .unwrap();
    let scanner = compiler.into_scanner();

    let res = scanner.scan_mem(mem);
    let boreal_value = res
        .module_values
        .into_iter()
        .find_map(|(name, module_value)| {
            if name == module.get_name() {
                Some(module_value)
            } else {
                None
            }
        })
        .unwrap();

    // Enrich value using the static values, so that it can be compared with yara's
    let mut boreal_value = Arc::try_unwrap(boreal_value).unwrap();
    enrich_with_static_values(&mut boreal_value, module.get_static_values());

    let c = yara::Compiler::new().unwrap();
    let c = c
        .add_rules_str(&format!(
            "import \"{}\" rule a {{ condition: true }}",
            module.get_name()
        ))
        .unwrap();
    let rules = c.compile_rules().unwrap();

    rules
        .scan_mem_callback(mem, 0, |msg| {
            if let yara::CallbackMsg::ModuleImported(obj) = msg {
                let yara_value = convert_yara_obj_to_module_value(obj);
                let mut diffs = Vec::new();
                compare_module_values(&boreal_value, yara_value, module.get_name(), &mut diffs);

                // Remove ignored diffs from the reported ones.
                for path in ignored_diffs {
                    match diffs.iter().position(|d| &d.path == path) {
                        Some(pos) => {
                            diffs.remove(pos);
                        }
                        None => {
                            panic!(
                                "ignored diff on path {path} but there is no diff on this path",
                            );
                        }
                    }
                }

                if !diffs.is_empty() {
                    panic!(
                        "found differences for module {} on {}: {:#?}",
                        module.get_name(),
                        mem_name,
                        diffs
                    );
                }
            }
            yara::CallbackReturn::Continue
        })
        .unwrap();
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
        StaticValue::Function { fun, .. } => ModuleValue::Function(Arc::new(Box::new(fun))),
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
        YrObjectValue::Function => ModuleValue::Function(Arc::new(Box::new(|_, _| None))),
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
            // An object where all values are the undefined value is allowed (same eval behavior).
            obj.values()
                .all(|value| matches!(value, ModuleValue::Undefined))
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
