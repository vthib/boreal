use boreal::Scanner;

// Parse and compile `rule`, then for each test,
// check that when running the rule on the given byte string, the
// result is the given bool value.
#[track_caller]
pub fn check_boreal(rule: &str, mem: &[u8], expected_res: bool) {
    // Check with boreal
    let mut scanner = Scanner::new();
    if let Err(err) = scanner.add_rules_from_str(&rule) {
        panic!("parsing failed: {}", err.to_short_description("mem", rule));
    }
    let res = scanner.scan_mem(mem);
    let res = res.matching_rules.len() > 0;
    assert_eq!(res, expected_res, "test failed for boreal");
}

#[track_caller]
pub fn check(rule: &str, mem: &[u8], expected_res: bool) {
    // Check with boreal
    check_boreal(rule, mem, expected_res);

    // Check with libyara, for conformity
    let compiler = yara::Compiler::new().unwrap();
    let compiler = compiler.add_rules_str(rule).unwrap();
    let rules = compiler.compile_rules().unwrap();
    let res = rules.scan_mem(mem, 1).unwrap().len() > 0;
    assert_eq!(res, expected_res, "conformity test failed for libyara");
}

#[track_caller]
pub fn check_file(rule: &str, filepath: &str, expected_res: bool) {
    use std::io::Read;

    println!("cwd: {:?}", std::env::current_dir().unwrap());
    let mut f = std::fs::File::open(filepath).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();

    check(rule, &buffer, expected_res);
}

#[track_caller]
pub fn check_err(rule: &str, expected_prefix: &str) {
    let mut scanner = Scanner::new();
    let err = scanner.add_rules_from_str(&rule).unwrap_err();
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
