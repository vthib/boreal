use std::ops::{RangeFrom, RangeTo};

use nom::{
    error::{Error, ErrorKind, ParseError as NomParseError},
    Err, IResult, InputIter, InputLength, InputTake,
};

#[derive(Clone, Copy, Debug)]
pub struct Input<'a> {
    /// Whole input being parsed.
    ///
    /// This reference is never modified.
    input: &'a str,

    /// Cursor pointing to the string slice currently being parsed.
    ///
    /// This is a reference on the same slice as [`input`], updated
    /// as we go through the parsing.
    cursor: &'a str,

    /// Saved position before the last applied rtrim.
    cursor_before_last_rtrim: &'a str,
}

pub type ParseError<'a> = Error<Input<'a>>;
pub type ParseResult<'a, O> = IResult<Input<'a>, O, ParseError<'a>>;

impl<'a> Input<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            cursor: input,
            cursor_before_last_rtrim: input,
        }
    }

    pub fn cursor(&self) -> &'a str {
        self.cursor
    }

    pub fn advance(&mut self, count: usize) {
        if self.cursor.len() >= count {
            self.cursor = &self.cursor[count..];
        } else {
            self.cursor = &self.cursor[self.cursor.len()..];
        }
    }

    pub fn strip_prefix(&self, prefix: &str) -> Option<Self> {
        self.cursor
            .strip_prefix(prefix)
            .map(|cursor| Self { cursor, ..*self })
    }

    pub fn save_cursor_before_rtrim(&mut self) {
        self.cursor_before_last_rtrim = self.cursor;
    }
}

impl<'a> InputIter for Input<'a> {
    type Item = char;
    type Iter = std::str::CharIndices<'a>;
    type IterElem = std::str::Chars<'a>;

    fn iter_indices(&self) -> Self::Iter {
        self.cursor.iter_indices()
    }

    fn iter_elements(&self) -> Self::IterElem {
        self.cursor.iter_elements()
    }

    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.cursor.position(predicate)
    }

    fn slice_index(&self, count: usize) -> Result<usize, nom::Needed> {
        self.cursor.slice_index(count)
    }
}

impl InputTake for Input<'_> {
    fn take(&self, count: usize) -> Self {
        Self {
            cursor: self.cursor.take(count),
            ..*self
        }
    }

    fn take_split(&self, count: usize) -> (Self, Self) {
        let (prefix, suffix) = self.cursor.take_split(count);
        (
            Self {
                cursor: prefix,
                ..*self
            },
            Self {
                cursor: suffix,
                ..*self
            },
        )
    }
}

impl nom::InputTakeAtPosition for Input<'_> {
    type Item = char;

    fn split_at_position<P, E: NomParseError<Self>>(&self, predicate: P) -> IResult<Self, Self, E>
    where
        P: Fn(Self::Item) -> bool,
    {
        match self.position(predicate) {
            Some(n) => Ok(self.take_split(n)),
            None => Err(Err::Incomplete(nom::Needed::new(1))),
        }
    }

    fn split_at_position1<P, E: NomParseError<Self>>(
        &self,
        predicate: P,
        e: ErrorKind,
    ) -> IResult<Self, Self, E>
    where
        P: Fn(Self::Item) -> bool,
    {
        match self.position(predicate) {
            Some(0) => Err(Err::Error(E::from_error_kind(*self, e))),
            Some(n) => Ok(self.take_split(n)),
            None => Err(Err::Incomplete(nom::Needed::new(1))),
        }
    }

    fn split_at_position_complete<P, E: NomParseError<Self>>(
        &self,
        predicate: P,
    ) -> IResult<Self, Self, E>
    where
        P: Fn(Self::Item) -> bool,
    {
        match self.split_at_position(predicate) {
            Err(Err::Incomplete(_)) => Ok(self.take_split(self.input_len())),
            res => res,
        }
    }

    fn split_at_position1_complete<P, E: NomParseError<Self>>(
        &self,
        predicate: P,
        e: ErrorKind,
    ) -> IResult<Self, Self, E>
    where
        P: Fn(Self::Item) -> bool,
    {
        match self.position(predicate) {
            Some(0) => Err(Err::Error(E::from_error_kind(*self, e))),
            Some(n) => Ok(self.take_split(n)),
            None => {
                if self.input_len() == 0 {
                    Err(Err::Error(E::from_error_kind(*self, e)))
                } else {
                    Ok(self.take_split(self.input_len()))
                }
            }
        }
    }
}

impl<'a> nom::FindSubstring<&'a str> for Input<'_> {
    fn find_substring(&self, substr: &'a str) -> Option<usize> {
        self.cursor.find_substring(substr)
    }
}

impl<'a> nom::Compare<&'a str> for Input<'_> {
    fn compare(&self, t: &'a str) -> nom::CompareResult {
        self.cursor.compare(t)
    }

    fn compare_no_case(&self, t: &'a str) -> nom::CompareResult {
        self.cursor.compare_no_case(t)
    }
}

impl nom::Slice<RangeFrom<usize>> for Input<'_> {
    fn slice(&self, range: RangeFrom<usize>) -> Self {
        Self {
            cursor: self.cursor.slice(range),
            ..*self
        }
    }
}

impl nom::Slice<RangeTo<usize>> for Input<'_> {
    fn slice(&self, range: RangeTo<usize>) -> Self {
        Self {
            cursor: self.cursor.slice(range),
            ..*self
        }
    }
}

impl InputLength for Input<'_> {
    fn input_len(&self) -> usize {
        self.cursor.input_len()
    }
}

impl nom::Offset for Input<'_> {
    fn offset(&self, second: &Self) -> usize {
        self.cursor.offset(second.cursor())
    }
}

impl nom::ExtendInto for Input<'_> {
    type Item = char;
    type Extender = String;

    #[inline]
    fn new_builder(&self) -> String {
        String::new()
    }

    #[inline]
    fn extend_into(&self, acc: &mut String) {
        acc.push_str(self.cursor);
    }
}
