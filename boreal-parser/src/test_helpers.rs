use crate::error::Error;

use crate::types::{Input, ParseResult};
use nom::Finish;

#[track_caller]
pub(crate) fn parse<'a, F, O, O2>(
    f: F,
    input: &'a str,
    expected_rest_input: &str,
    expected_result: O2,
) where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O> + 'a,
    O: PartialEq + std::fmt::Debug + From<O2>,
{
    let input = Input::new(input);
    let res = f(input).unwrap();
    assert_eq!(res.0.cursor(), expected_rest_input);
    assert_eq!(res.1, expected_result.into());
}

#[track_caller]
pub(crate) fn parse_err<'a, F, O>(f: F, input: &'a str)
where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O>,
    O: PartialEq + std::fmt::Debug,
{
    let input = Input::new(input);
    let res = f(input).finish();
    assert!(res.is_err());
}

#[track_caller]
pub(crate) fn parse_err_type<'a, F, O>(f: F, input: &'a str, err: &Error)
where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O>,
    O: PartialEq + std::fmt::Debug,
{
    let input = Input::new(input);
    let res = f(input).finish();
    assert_eq!(&res.unwrap_err(), err);
}

#[track_caller]
pub(crate) fn parse_check<'a, F, O, C>(f: F, input: &'a str, check: C)
where
    F: FnOnce(Input<'a>) -> ParseResult<'a, O>,
    O: PartialEq + std::fmt::Debug,
    C: FnOnce(O),
{
    let input = Input::new(input);
    let res = f(input).finish();
    check(res.unwrap().1);
}

// This test serves two purposes:
// - Ensure public types have expected impls: Clone, Debug, Send & Sync
// - Instrument those impls to avoid having those derive be marked as missed in coverage...
//
// Each module that exposes public types is expected to use it on those types.
pub(crate) fn test_public_type<T: Clone + std::fmt::Debug + Send + Sync>(t: T) {
    #[allow(clippy::redundant_clone)]
    let _r = t.clone();
    let _r = format!("{:?}", &t);
}
