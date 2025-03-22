use std::ops::Range;

use regex_automata::Input;

use crate::regex::{regex_hir_to_string, Hir, Regex};

use super::analysis::HirAnalysis;
use super::widener::widen_hir;
use super::{MatchType, Modifiers};

#[derive(Debug)]
pub(super) struct RawMatcher {
    regex: regex_automata::meta::Regex,

    /// Regex of the non wide version of the regex.
    ///
    /// This is only set for the specific case of a regex variable, with a wide modifier, that
    /// contains word boundaries.
    /// In this case, the regex expression cannot be "widened", and this regex is used to post
    /// check matches.
    non_wide_regex: Option<Regex>,

    /// Saved expressions of the regex.
    ///
    /// Only used for serialization.
    #[cfg(feature = "serialize")]
    exprs: [Box<str>; 2],
}

#[cfg(feature = "serialize")]
impl PartialEq for RawMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.non_wide_regex == other.non_wide_regex && self.exprs == other.exprs
    }
}

impl RawMatcher {
    pub(super) fn new(
        hir: &Hir,
        analysis: &HirAnalysis,
        modifiers: Modifiers,
    ) -> Result<Self, crate::regex::Error> {
        let non_wide_regex = if analysis.has_word_boundaries && modifiers.wide {
            let expr = regex_hir_to_string(hir);
            Some(Regex::from_string(
                expr,
                modifiers.nocase,
                modifiers.dot_all,
            )?)
        } else {
            None
        };

        let builder = Regex::builder(modifiers.nocase, modifiers.dot_all);

        let (expr1, expr2) = match (modifiers.ascii, modifiers.wide) {
            (true, true) => {
                // Build a regex with 2 patterns: one for the ascii version,
                // one for the wide version.
                let expr = regex_hir_to_string(hir);
                let wide_expr = regex_hir_to_string(&widen_hir(hir));

                (expr, wide_expr)
            }
            (false, true) => {
                let wide_hir = widen_hir(hir);
                (regex_hir_to_string(&wide_hir), String::new())
            }
            _ => (regex_hir_to_string(hir), String::new()),
        };
        let regex = if expr2.is_empty() {
            builder.build(&expr1)
        } else {
            builder.build_many(&[&expr1, &expr2])
        }
        .map_err(crate::regex::Error::from)?;

        Ok(Self {
            regex,
            #[cfg(feature = "serialize")]
            exprs: [expr1.into_boxed_str(), expr2.into_boxed_str()],
            non_wide_regex,
        })
    }

    pub(super) fn find_next_match_at(
        &self,
        mem: &[u8],
        mut offset: usize,
        modifiers: Modifiers,
    ) -> Option<(Range<usize>, MatchType)> {
        loop {
            let m = self.regex.find(Input::new(mem).span(offset..mem.len()))?;
            let mat = m.range();

            let match_type = match (modifiers.ascii, modifiers.wide, m.pattern().as_u32()) {
                (false, true, _) => MatchType::WideStandard,
                // First pattern is ascii, Second one is wide
                (true, true, 0) => MatchType::Ascii,
                (true, true, _) => MatchType::WideAlternate,
                _ => MatchType::Ascii,
            };

            match self.non_wide_regex.as_ref() {
                Some(regex) => {
                    // TODO: avoid this for the raw matcher too. Use a dfa validator?
                    match apply_wide_word_boundaries(mat.clone(), mem, regex, match_type) {
                        Some(new_mat) => return Some((new_mat, match_type)),
                        None => offset = mat.start + 1,
                    }
                }
                None => return Some((mat, match_type)),
            }
        }
    }

    #[cfg(feature = "serialize")]
    pub(super) fn deserialize<R: std::io::Read>(
        modifiers: Modifiers,
        reader: &mut R,
    ) -> std::io::Result<Self> {
        wire::deserialize_raw_matcher(modifiers, reader)
    }
}

/// Check the match respects the word boundaries inside the variable.
fn apply_wide_word_boundaries(
    mut mat: Range<usize>,
    mem: &[u8],
    regex: &Regex,
    match_type: MatchType,
) -> Option<Range<usize>> {
    match match_type {
        MatchType::WideStandard | MatchType::WideAlternate => (),
        MatchType::Ascii => return Some(mat),
    }

    // Take the previous and next byte, so that word boundaries placed at the beginning or end of
    // the regex can be checked.
    // Note that we must check that the previous/next byte is "wide" as well, otherwise it is not
    // valid.
    let start = if mat.start >= 2 && mem[mat.start - 1] == b'\0' {
        mat.start - 2
    } else {
        mat.start
    };

    // Remove the wide bytes, and then use the non wide regex to check for word boundaries.
    // Since when checking word boundaries, we might match more than the initial match (because of
    // non greedy repetitions bounded by word boundaries), we need to add more data at the end.
    // How much? We cannot know, but including too much would be too much of a performance tank.
    // This is arbitrarily capped at 500 for the moment (or until the string is no longer wide)...
    let unwiden_mem = unwide(&mem[start..std::cmp::min(mem.len(), mat.end + 500)]);

    #[allow(clippy::bool_to_int_with_if)]
    let expected_start = if start < mat.start { 1 } else { 0 };
    match regex.find(&unwiden_mem) {
        Some(m) if m.start == expected_start => {
            // Modify the match end. This is needed because the application of word boundary
            // may modify the match. Since we matched on non wide mem though, double the size.
            mat.end = mat.start + 2 * (m.end - m.start);
            Some(mat)
        }
        _ => None,
    }
}

fn unwide(mem: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();

    for b in mem.chunks_exact(2) {
        if b[1] != b'\0' {
            break;
        }
        res.push(b[0]);
    }

    res
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use crate::matcher::Modifiers;
    use crate::regex::Regex;

    use super::RawMatcher;

    impl Serialize for RawMatcher {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.exprs[0].serialize(writer)?;
            self.exprs[1].serialize(writer)?;
            self.non_wide_regex
                .as_ref()
                .map(Regex::as_str)
                .serialize(writer)?;
            Ok(())
        }
    }

    pub(super) fn deserialize_raw_matcher<R: io::Read>(
        modifiers: Modifiers,
        reader: &mut R,
    ) -> io::Result<RawMatcher> {
        let expr1 = String::deserialize_reader(reader)?;
        let expr2 = String::deserialize_reader(reader)?;

        let non_wide_expr = <Option<String>>::deserialize_reader(reader)?;
        let non_wide_regex = match non_wide_expr {
            Some(expr) => Some(
                Regex::from_string(expr.clone(), modifiers.nocase, modifiers.dot_all).map_err(
                    |err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unable to compile regex with expression {expr}: {err:?}"),
                        )
                    },
                )?,
            ),
            None => None,
        };

        let builder = Regex::builder(modifiers.nocase, modifiers.dot_all);
        let res = if expr2.is_empty() {
            builder.build_many(&[&expr1])
        } else {
            builder.build_many(&[&expr1, &expr2])
        };
        let regex = res.map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unable to compile regex with expression {expr1}, {expr2}: {err:?}",),
            )
        })?;
        Ok(RawMatcher {
            regex,
            exprs: [expr1.into_boxed_str(), expr2.into_boxed_str()],
            non_wide_regex,
        })
    }

    #[cfg(test)]
    mod tests {
        use crate::matcher::analysis::analyze_hir;
        use crate::regex::Hir;
        use crate::wire::tests::test_round_trip_custom_deser;

        use super::*;

        #[test]
        fn test_wire_raw_matcher() {
            let hir = Hir::Dot;
            let analysis = analyze_hir(&hir, true);

            let modifiers = Modifiers {
                ascii: true,
                wide: true,
                ..Default::default()
            };
            test_round_trip_custom_deser(
                &RawMatcher::new(&hir, &analysis, modifiers).unwrap(),
                |reader| deserialize_raw_matcher(modifiers, reader),
                &[0],
            );
            let modifiers = Modifiers::default();
            test_round_trip_custom_deser(
                &RawMatcher::new(&hir, &analysis, modifiers).unwrap(),
                |reader| deserialize_raw_matcher(modifiers, reader),
                &[0, 7, 9],
            );

            // Test failure when compiling expressions.
            let mut reader = io::Cursor::new(b"\x01\x00\x00\x00[\x00\x00\x00\x00\x00");
            assert!(deserialize_raw_matcher(modifiers, &mut reader).is_err());

            // Test failure when compiling non wide regex.
            let mut reader =
                io::Cursor::new(b"\x01\x00\x00\x00[\x00\x00\x00\x00\x01\x01\x00\x00\x00[");
            assert!(deserialize_raw_matcher(modifiers, &mut reader).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::analysis::analyze_hir;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(
            RawMatcher::new(
                &Hir::Empty,
                &analyze_hir(&Hir::Empty, true),
                Modifiers::default(),
            )
            .unwrap(),
        );
    }
}
