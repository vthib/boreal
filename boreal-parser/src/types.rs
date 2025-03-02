use std::ops::Range;

use super::error::Error;
use nom::{
    error::{ErrorKind, ParseError as NomParseError},
    Compare, CompareResult, Err, IResult,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Input<'a> {
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

    /// Counter on inner recursion.
    ///
    /// This is used in combinators using recursions, but only if no other recursive combinator
    /// can be present in it.
    /// For example, recursion to parse hex-strings and regexes uses this counter, but recursion
    /// to parse expressions do not (as expressions can contain regexes).
    pub inner_recursion_counter: usize,

    /// Counter on expression recursion.
    pub expr_recursion_counter: usize,
}

/// Position inside the input.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Position<'a> {
    cursor: &'a str,
}

pub(crate) type ParseResult<'a, O> = IResult<Input<'a>, O, Error>;

impl<'a> Input<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self {
            input,
            cursor: input,
            cursor_before_last_rtrim: input,
            inner_recursion_counter: 0,
            expr_recursion_counter: 0,
        }
    }

    pub(crate) fn pos(&self) -> Position<'a> {
        Position {
            cursor: self.cursor,
        }
    }

    pub(crate) fn cursor(&self) -> &'a str {
        self.cursor
    }

    pub(crate) fn advance(&mut self, count: usize) {
        if self.cursor.len() >= count {
            self.cursor = &self.cursor[count..];
        } else {
            self.cursor = &self.cursor[self.cursor.len()..];
        }
    }

    pub(crate) fn strip_prefix(&self, prefix: &str) -> Option<Self> {
        self.cursor
            .strip_prefix(prefix)
            .map(|cursor| Self { cursor, ..*self })
    }

    pub(crate) fn save_cursor_before_rtrim(&mut self) {
        self.cursor_before_last_rtrim = self.cursor;
    }

    pub(crate) fn get_position_offset(&self) -> usize {
        (self.cursor.as_ptr() as usize) - (self.input.as_ptr() as usize)
    }

    /// Generate a span from a starting position.
    ///
    /// The given input is the start of the span.
    /// The end of the span is the cursor saved before the last rtrim.
    pub(crate) fn get_span_from(&self, start: Position) -> Range<usize> {
        let input = self.input.as_ptr() as usize;

        let start = start.cursor.as_ptr() as usize - input;
        let end = self.cursor_before_last_rtrim.as_ptr() as usize - input;
        if start <= end {
            Range { start, end }
        } else {
            // Can happen when generating errors when entering a combinator, before any parsing is
            // done, which is the case for recursion checks
            Range { start, end: start }
        }
    }

    /// Generate a span from a starting position, without considering rtrims.
    ///
    /// The given input is the start of the span.
    /// The end of the span is the current position of the cursor.
    pub(crate) fn get_span_from_no_rtrim(&self, start: Position) -> Range<usize> {
        let input = self.input.as_ptr() as usize;

        Range {
            start: start.cursor.as_ptr() as usize - input,
            end: self.cursor.as_ptr() as usize - input,
        }
    }
}

impl<'a> nom::Input for Input<'a> {
    type Item = char;
    type Iter = std::str::Chars<'a>;
    type IterIndices = std::str::CharIndices<'a>;

    fn input_len(&self) -> usize {
        self.cursor.input_len()
    }

    fn take(&self, count: usize) -> Self {
        Self {
            cursor: self.cursor.take(count),
            ..*self
        }
    }

    fn take_from(&self, count: usize) -> Self {
        Self {
            cursor: self.cursor.take_from(count),
            ..*self
        }
    }

    fn take_split(&self, count: usize) -> (Self, Self) {
        let (suffix, prefix) = self.cursor.take_split(count);
        (
            Self {
                cursor: suffix,
                ..*self
            },
            Self {
                cursor: prefix,
                ..*self
            },
        )
    }

    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.cursor.position(predicate)
    }

    fn iter_elements(&self) -> Self::Iter {
        self.cursor.iter_elements()
    }

    fn iter_indices(&self) -> Self::IterIndices {
        self.cursor.iter_indices()
    }

    fn slice_index(&self, count: usize) -> Result<usize, nom::Needed> {
        self.cursor.slice_index(count)
    }

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

impl<'a> Compare<&'a str> for Input<'_> {
    fn compare(&self, t: &'a str) -> CompareResult {
        self.cursor.compare(t)
    }

    fn compare_no_case(&self, t: &'a str) -> CompareResult {
        self.cursor.compare_no_case(t)
    }
}

impl nom::Offset for Input<'_> {
    fn offset(&self, second: &Self) -> usize {
        self.cursor.offset(second.cursor())
    }
}

impl std::ops::Deref for Input<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.cursor
    }
}

#[cfg(test)]
mod tests {
    use nom::error::ErrorKind;
    use nom::{Compare, CompareResult, Input};

    use crate::error::Error;
    use crate::test_helpers::test_public_type;

    use super::Input as I;

    #[test]
    fn test_input_advance() {
        let mut input = I::new("rule a { condition: true }");

        input.advance(0);
        assert_eq!(input.cursor(), "rule a { condition: true }");
        assert_eq!(input.get_position_offset(), 0);
        input.advance(1);
        assert_eq!(input.cursor(), "ule a { condition: true }");
        assert_eq!(input.get_position_offset(), 1);
        input.advance(20);
        assert_eq!(input.cursor(), "rue }");
        assert_eq!(input.get_position_offset(), 21);
        input.advance(9);
        assert_eq!(input.cursor(), "");
        assert_eq!(input.get_position_offset(), 26);
        input.advance(9);
        assert_eq!(input.cursor(), "");
        assert_eq!(input.get_position_offset(), 26);
    }

    #[test]
    fn test_input_strip_prefix() {
        let input = I::new("rule a { condition: true }");

        let input = input.strip_prefix("rule").unwrap();
        assert_eq!(input.cursor(), " a { condition: true }");
        assert_eq!(input.get_position_offset(), 4);

        assert!(input.strip_prefix("condition").is_none());

        let input = input.strip_prefix(" a { condition: ").unwrap();
        assert_eq!(input.cursor(), "true }");
        assert_eq!(input.get_position_offset(), 20);
    }

    #[test]
    fn test_input_take_trait() {
        let mut input = I::new("rule a { condition: true }");

        let take = input.take(15);
        assert_eq!(take.cursor(), "rule a { condit");
        assert_eq!(take.get_position_offset(), 0);

        let take = input.take_from(15);
        assert_eq!(take.cursor(), "ion: true }");
        assert_eq!(take.get_position_offset(), 15);

        input.advance(7);
        let (post, pre) = input.take_split(13);
        assert_eq!(pre.cursor(), "{ condition: ");
        assert_eq!(pre.get_position_offset(), 7);
        assert_eq!(post.cursor(), "true }");
        assert_eq!(post.get_position_offset(), 20);
    }

    #[test]
    fn test_input_take_at_position_trait() {
        let mut input = I::new("rule a { condition: true }");
        input.advance(5);

        // split_at_position
        assert!(input.split_at_position::<_, Error>(|c| c == '/').is_err());

        let (post, pre) = input.split_at_position::<_, Error>(|c| c == ':').unwrap();
        assert_eq!(pre.cursor(), "a { condition");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), ": true }");
        assert_eq!(post.get_position_offset(), 18);

        let (post, pre) = input.split_at_position::<_, Error>(|c| c == 'a').unwrap();
        assert_eq!(pre.cursor(), "");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), "a { condition: true }");
        assert_eq!(post.get_position_offset(), 5);

        // split_at_position1
        assert!(input
            .split_at_position1::<_, Error>(|c| c == '/', ErrorKind::Char)
            .is_err());

        let (post, pre) = input
            .split_at_position1::<_, Error>(|c| c == ':', ErrorKind::Char)
            .unwrap();
        assert_eq!(pre.cursor(), "a { condition");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), ": true }");
        assert_eq!(post.get_position_offset(), 18);

        assert!(input
            .split_at_position1::<_, Error>(|c| c == 'a', ErrorKind::Char)
            .is_err());

        // split_at_position_complete
        let (post, pre) = input
            .split_at_position_complete::<_, Error>(|c| c == '/')
            .unwrap();
        assert_eq!(pre.cursor(), "a { condition: true }");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), "");
        assert_eq!(post.get_position_offset(), 26);

        let (post, pre) = input
            .split_at_position_complete::<_, Error>(|c| c == ':')
            .unwrap();
        assert_eq!(pre.cursor(), "a { condition");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), ": true }");
        assert_eq!(post.get_position_offset(), 18);

        let (post, pre) = input
            .split_at_position_complete::<_, Error>(|c| c == 'a')
            .unwrap();
        assert_eq!(pre.cursor(), "");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), "a { condition: true }");
        assert_eq!(post.get_position_offset(), 5);

        // split_at_position1_complete
        let (post, pre) = input
            .split_at_position1_complete::<_, Error>(|c| c == '/', ErrorKind::Char)
            .unwrap();
        assert_eq!(pre.cursor(), "a { condition: true }");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), "");
        assert_eq!(post.get_position_offset(), 26);

        let (post, pre) = input
            .split_at_position1_complete::<_, Error>(|c| c == ':', ErrorKind::Char)
            .unwrap();
        assert_eq!(pre.cursor(), "a { condition");
        assert_eq!(pre.get_position_offset(), 5);
        assert_eq!(post.cursor(), ": true }");
        assert_eq!(post.get_position_offset(), 18);

        assert!(input
            .split_at_position1_complete::<_, Error>(|c| c == 'a', ErrorKind::Char)
            .is_err());
    }

    #[test]
    fn test_input_iter() {
        let input = I::new("condition: true");
        let (post, pre) = input.take_split(7);

        assert_eq!(
            pre.iter_elements().collect::<Vec<_>>(),
            ['c', 'o', 'n', 'd', 'i', 't', 'i']
        );
        assert_eq!(
            post.iter_indices().collect::<Vec<_>>(),
            [
                (0, 'o'),
                (1, 'n'),
                (2, ':'),
                (3, ' '),
                (4, 't'),
                (5, 'r'),
                (6, 'u'),
                (7, 'e'),
            ]
        );
    }

    #[test]
    fn test_compare_trait() {
        let mut input = I::new("rule a { condition: true }");
        input.advance(9);

        assert_eq!(input.compare("true"), CompareResult::Error);
        assert_eq!(input.compare("condition"), CompareResult::Ok);
        assert_eq!(input.compare("CONDITION"), CompareResult::Error);
        assert_eq!(
            input.take(5).compare("condition"),
            CompareResult::Incomplete
        );
        assert_eq!(input.take(5).compare("CONDITION"), CompareResult::Error);

        assert_eq!(input.compare_no_case("true"), CompareResult::Error);
        assert_eq!(input.compare_no_case("condition"), CompareResult::Ok);
        assert_eq!(input.compare_no_case("CONDITION"), CompareResult::Ok);
        assert_eq!(
            input.take(5).compare_no_case("condition"),
            CompareResult::Incomplete
        );
        assert_eq!(
            input.take(5).compare_no_case("CONDITION"),
            CompareResult::Incomplete
        );
    }

    #[test]
    fn test_public_types() {
        test_public_type(I::new(r"a"));
        test_public_type(I::new(r"a").pos());
    }
}
