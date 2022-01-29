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
    let assets_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/parsing_all/");
    let glob1 =
        glob::glob(&format!("{}/**/*.yara", assets_dir)).expect("Failed to read glob pattern");
    let glob2 =
        glob::glob(&format!("{}/**/*.yar", assets_dir)).expect("Failed to read glob pattern");

    let mut nb_ok = 0;
    let mut nb_failed = 0;
    for entry in glob1.chain(glob2) {
        let entry = entry.unwrap();
        match super::parse_file(&entry) {
            Ok(_) => {
                nb_ok += 1;
                println!("OK   {:?}", &entry);
            }
            Err(e) => {
                nb_failed += 1;
                println!("FAIL {:?}\n  {:?}", &entry, e);
            }
        };
    }

    println!(
        "parsed {}/{} OK ({:.2}%)",
        nb_ok,
        (nb_ok + nb_failed),
        (f64::from(nb_ok) * 100.) / f64::from(nb_ok + nb_failed)
    );
}
