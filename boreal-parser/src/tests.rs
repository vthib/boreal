use super::types::{Input, ParseResult};
use codespan_reporting::{
    files::SimpleFile,
    term::{
        self,
        termcolor::{ColorChoice, StandardStream},
    },
};
use nom::Finish;

#[track_caller]
pub fn parse<'a, F, O, O2>(f: F, input: &'a str, expected_rest_input: &str, expected_result: O2)
where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O> + 'a,
    O: PartialEq + std::fmt::Debug + From<O2>,
{
    let input = Input::new(input);
    let res = f(input).unwrap();
    assert_eq!(res.0.cursor(), expected_rest_input);
    assert_eq!(res.1, expected_result.into());
}

#[track_caller]
pub fn parse_err<'a, F, O>(f: F, input: &'a str)
where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O>,
    O: PartialEq + std::fmt::Debug,
{
    let input = Input::new(input);
    let res = f(input).finish();
    assert!(res.is_err());
}

#[track_caller]
pub fn parse_check<'a, F, O, C>(f: F, input: &'a str, check: C)
where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O>,
    O: PartialEq + std::fmt::Debug,
    C: FnOnce(O),
{
    let input = Input::new(input);
    let res = f(input).finish();
    check(res.unwrap().1);
}

#[test]
fn test_parsing_global() {
    let assets_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/parsing/");
    let glob1 =
        glob::glob(&format!("{}/**/*.yara", assets_dir)).expect("Failed to read glob pattern");
    let glob2 =
        glob::glob(&format!("{}/**/*.yar", assets_dir)).expect("Failed to read glob pattern");

    let writer = StandardStream::stderr(ColorChoice::Always);
    let config = codespan_reporting::term::Config::default();

    let mut nb_ok = 0;
    let mut nb_failed = 0;
    for entry in glob1.chain(glob2) {
        let entry = entry.unwrap();
        let contents = std::fs::read_to_string(&entry).unwrap();
        match super::parse_str(&contents) {
            Ok(_) => {
                nb_ok += 1;
                println!("OK   {:?}", &entry);
            }
            Err(e) => {
                nb_failed += 1;
                println!("FAIL {:?}", &entry);

                let filename = entry.display().to_string();
                let files = SimpleFile::new(&filename, &contents);
                term::emit(&mut writer.lock(), &config, &files, &e.to_diagnostic()).unwrap();
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
