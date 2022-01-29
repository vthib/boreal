use nom::{error::Error, IResult};

pub type Input<'a> = &'a str;
pub type ParseError<'a> = Error<Input<'a>>;
pub type ParseResult<'a, O> = IResult<Input<'a>, O, ParseError<'a>>;
