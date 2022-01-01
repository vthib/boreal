use nom::Finish;

#[track_caller]
pub fn parse<F, O>(f: F, input: &str, expected_rest_input: &str, expected_result: O)
where
    F: FnOnce(&str) -> nom::IResult<&str, O>,
    O: PartialEq + std::fmt::Debug,
{
    let res = f(input).unwrap();
    assert_eq!(res.0, expected_rest_input);
    assert_eq!(res.1, expected_result);
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
