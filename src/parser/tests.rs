use nom::Finish;

#[track_caller]
pub fn parse<'a, F: 'a, O, O2>(f: F, input: &'a str, expected_rest_input: &str, expected_result: O2)
where
    F: FnOnce(&'a str) -> nom::IResult<&'a str, O>,
    O: PartialEq + std::fmt::Debug + From<O2>,
{
    let res = f(input).unwrap();
    assert_eq!(res.0, expected_rest_input);
    assert_eq!(res.1, expected_result.into());
}

#[track_caller]
pub fn parse_err<F, O>(f: F, input: &str)
where
    F: FnOnce(&str) -> nom::IResult<&str, O>,
    O: PartialEq + std::fmt::Debug,
{
    let res = f(input).finish();
    assert!(res.is_err());
}

#[track_caller]
pub fn parse_check<F, O, C>(f: F, input: &str, check: C)
where
    F: FnOnce(&str) -> nom::IResult<&str, O>,
    O: PartialEq + std::fmt::Debug,
    C: FnOnce(O),
{
    let res = f(input).finish();
    check(res.unwrap().1);
}

#[test]
fn test_parsing_global() {
    let glob_str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/parsing/**/*.yara");

    for entry in glob::glob(glob_str).expect("Failed to read glob pattern") {
        let entry = entry.unwrap();
        match super::parse_file(&entry) {
            Ok(_) => println!("OK   {:?}", &entry),
            Err(e) => println!("FAIL {:?}\n  {:?}", &entry, e),
        };
    }
}
