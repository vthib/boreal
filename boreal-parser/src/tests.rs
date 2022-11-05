use super::types::{Input, ParseResult};
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
