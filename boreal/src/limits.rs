/// Max length of the matches returned in matching rules.
///
/// See [`crate::scanner::StringMatch`].
pub const MATCH_MAX_LENGTH: usize = 512;

/// Max number of matches for a given string.
///
/// Matches that would occur after this value are not reported.
/// YARA uses `1_000_000` for this value, is there any reason to have such a huge number?
// TODO: provide a way to configure it in the API.
pub const STRING_MAX_NB_MATCHES: usize = 1_000;
