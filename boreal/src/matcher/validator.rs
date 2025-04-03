use std::ops::Range;

use crate::regex::Hir;

use super::analysis::{analyze_hir, HirAnalysis};
use super::{MatchType, Matches, Modifiers};

mod dfa;
mod simple;

// Maximum length against which a regex validator of a AC literal match will be run.
//
// For example, lets say you have the `{ AA [1-] BB CC DD [1-] FF }` hex string. The
// `\xbb\xcc\xdd` literal is extracted, with:
// - the pre validator `\xaa.{1,}?\xbb\xcc\xdd$`
// - the post validator `^\xbb\xcc\xdd.{1,}?\xff`
//
// Both the pre and post validator will be run against a slice which maximum length is
// limited by the constant. Which means that `\xaa0\xbb\xcc\xdd` + ('0' * MAX+1) + '\xff'
// will not match.
const MAX_SPLIT_MATCH_LENGTH: usize = 4096;

#[derive(Debug)]
#[cfg_attr(all(test, feature = "serialize"), derive(PartialEq))]
pub(super) enum Validator {
    NonGreedy {
        forward: Option<HalfValidator>,
        reverse: Option<HalfValidator>,
    },
    Greedy {
        reverse: dfa::DfaValidator,
        full: dfa::DfaValidator,
    },
}

impl Validator {
    pub(super) fn new(
        pre: Option<&Hir>,
        post: Option<&Hir>,
        full: &Hir,
        modifiers: Modifiers,
    ) -> Result<Self, crate::regex::Error> {
        let reverse = match pre {
            Some(pre) => {
                let left_analysis = analyze_hir(pre, modifiers.dot_all);

                // XXX: If the left HIR has greedy repetitions, then the HIR cannot be split into a
                // (left, literals, right) triplet. This is because the greedy repetitions can
                // "eat" the literals, leading to incorrect matches.
                //
                // For example, a regex that looks like: `a.+foo.b` will extract the literal foo,
                // but against the string `aafoobbaafoobb`, it will match on the entire string,
                // while a (pre, post) matching would match twice.
                if left_analysis.has_greedy_repetitions {
                    let reverse = dfa::DfaValidator::new(pre, &left_analysis, modifiers, true)?;

                    let full_analysis = analyze_hir(full, modifiers.dot_all);
                    let full = dfa::DfaValidator::new(full, &full_analysis, modifiers, false)?;

                    return Ok(Self::Greedy { reverse, full });
                }

                Some(HalfValidator::new(pre, &left_analysis, modifiers, true)?)
            }
            None => None,
        };

        let forward = match post {
            Some(hir) => {
                let analysis = analyze_hir(hir, modifiers.dot_all);
                Some(HalfValidator::new(hir, &analysis, modifiers, false)?)
            }
            None => None,
        };

        Ok(Self::NonGreedy { forward, reverse })
    }

    #[cfg(feature = "serialize")]
    pub(super) fn deserialize<R: std::io::Read>(
        modifiers: Modifiers,
        reader: &mut R,
    ) -> std::io::Result<Self> {
        wire::deserialize_validator(modifiers, reader)
    }

    pub(super) fn validate_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
        match_type: MatchType,
    ) -> Matches {
        match self {
            Self::NonGreedy { forward, reverse } => {
                let end = match forward {
                    Some(validator) => {
                        let end = std::cmp::min(
                            mem.len(),
                            mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH),
                        );
                        match validator.find_anchored_fwd(mem, mat.start, end, match_type) {
                            Some(end) => end,
                            None => return Matches::None,
                        }
                    }
                    None => mat.end,
                };

                match reverse {
                    None => Matches::Single(mat.start..end),
                    Some(validator) => {
                        // The left validator can yield multiple matches.
                        // For example, `a.?bb`, with the `bb` atom, can match as many times as there are
                        // 'a' characters before the `bb` atom.
                        let mut matches = Vec::new();
                        let mut start = std::cmp::max(
                            start_position,
                            mat.end.saturating_sub(MAX_SPLIT_MATCH_LENGTH),
                        );
                        while let Some(s) =
                            validator.find_anchored_rev(mem, start, mat.end, match_type)
                        {
                            matches.push(s..end);
                            start = s + 1;
                            if start > mat.end {
                                break;
                            }
                        }
                        Matches::Multiple(matches)
                    }
                }
            }
            Self::Greedy { reverse, full } => {
                let mut matches = Vec::new();

                let mut start = std::cmp::max(
                    start_position,
                    mat.end.saturating_sub(MAX_SPLIT_MATCH_LENGTH),
                );
                let end =
                    std::cmp::min(mem.len(), mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH));

                while let Some(s) = reverse.find_anchored_rev(mem, start, mat.end, match_type) {
                    if let Some(e) = full.find_anchored_fwd(mem, s, end, match_type) {
                        matches.push(s..e);
                    }
                    start = s + 1;
                    if start > mat.end {
                        break;
                    }
                }

                Matches::Multiple(matches)
            }
        }
    }
}

impl std::fmt::Display for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonGreedy { forward, reverse } => {
                write!(f, "NonGreedy {{ ")?;
                match reverse {
                    Some(v) => write!(f, "reverse: {v}")?,
                    None => write!(f, "reverse: none")?,
                }
                write!(f, ", ")?;
                match forward {
                    Some(v) => write!(f, "forward: {v}")?,
                    None => write!(f, "forward: none")?,
                }
                write!(f, " }}")
            }
            Self::Greedy { .. } => {
                write!(f, "Greedy {{ reverse: Dfa, full: Dfa }}")
            }
        }
    }
}

#[derive(Debug)]
#[cfg_attr(all(test, feature = "serialize"), derive(PartialEq))]
pub(super) enum HalfValidator {
    // Simplified validator for very simple regex expressions.
    Simple(simple::SimpleValidator),
    // Dfa validator, handling all the complex cases
    Dfa(dfa::DfaValidator),
}

impl HalfValidator {
    fn new(
        hir: &Hir,
        analysis: &HirAnalysis,
        modifiers: Modifiers,
        reverse: bool,
    ) -> Result<Self, crate::regex::Error> {
        match simple::SimpleValidator::new(hir, analysis, modifiers, reverse) {
            Some(v) => Ok(Self::Simple(v)),
            None => Ok(Self::Dfa(dfa::DfaValidator::new(
                hir, analysis, modifiers, reverse,
            )?)),
        }
    }

    fn find_anchored_fwd(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        match_type: MatchType,
    ) -> Option<usize> {
        match self {
            Self::Simple(validator) => validator.find_anchored_fwd(haystack, start, end),
            Self::Dfa(validator) => validator.find_anchored_fwd(haystack, start, end, match_type),
        }
    }

    fn find_anchored_rev(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        match_type: MatchType,
    ) -> Option<usize> {
        match self {
            Self::Simple(validator) => validator.find_anchored_rev(haystack, start, end),
            Self::Dfa(validator) => validator.find_anchored_rev(haystack, start, end, match_type),
        }
    }
}

impl std::fmt::Display for HalfValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Simple(_) => write!(f, "Simple"),
            Self::Dfa(_) => write!(f, "Dfa"),
        }
    }
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use crate::matcher::Modifiers;

    use super::simple::SimpleValidator;
    use super::{dfa, HalfValidator, Validator};

    impl Serialize for Validator {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Validator::NonGreedy { forward, reverse } => {
                    0_u8.serialize(writer)?;
                    forward.serialize(writer)?;
                    reverse.serialize(writer)?;
                }
                Validator::Greedy { reverse, full } => {
                    1_u8.serialize(writer)?;
                    reverse.serialize(writer)?;
                    full.serialize(writer)?;
                }
            }
            Ok(())
        }
    }

    pub(super) fn deserialize_validator<R: io::Read>(
        modifiers: Modifiers,
        reader: &mut R,
    ) -> io::Result<Validator> {
        let discriminant = u8::deserialize_reader(reader)?;
        match discriminant {
            0 => {
                let forward_opt = bool::deserialize_reader(reader)?;
                let forward = if forward_opt {
                    Some(deserialize_half_validator(modifiers, false, reader)?)
                } else {
                    None
                };
                let reverse_opt = bool::deserialize_reader(reader)?;
                let reverse = if reverse_opt {
                    Some(deserialize_half_validator(modifiers, true, reader)?)
                } else {
                    None
                };
                Ok(Validator::NonGreedy { forward, reverse })
            }
            1 => {
                let reverse = dfa::DfaValidator::deserialize(modifiers, true, reader)?;
                let full = dfa::DfaValidator::deserialize(modifiers, true, reader)?;
                Ok(Validator::Greedy { reverse, full })
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid discriminant when deserializing a validator: {v}"),
            )),
        }
    }

    impl Serialize for HalfValidator {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Self::Simple(simple) => {
                    0_u8.serialize(writer)?;
                    simple.serialize(writer)?;
                }
                Self::Dfa(dfa) => {
                    1_u8.serialize(writer)?;
                    dfa.serialize(writer)?;
                }
            }
            Ok(())
        }
    }

    fn deserialize_half_validator<R: io::Read>(
        modifiers: Modifiers,
        reverse: bool,
        reader: &mut R,
    ) -> io::Result<HalfValidator> {
        let discriminant = u8::deserialize_reader(reader)?;
        match discriminant {
            0 => Ok(HalfValidator::Simple(SimpleValidator::deserialize_reader(
                reader,
            )?)),
            1 => {
                let dfa = dfa::DfaValidator::deserialize(modifiers, reverse, reader)?;
                Ok(HalfValidator::Dfa(dfa))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid discriminant when deserializing a half validator: {v}"),
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use dfa::DfaValidator;

        use crate::matcher::analysis::analyze_hir;
        use crate::regex::Hir;
        use crate::wire::tests::test_round_trip_custom_deser;

        use super::*;

        #[test]
        fn test_wire_validator() {
            let hir = Hir::Dot;
            let analysis = analyze_hir(&hir, false);
            let modifiers = Modifiers::default();

            test_round_trip_custom_deser(
                &Validator::NonGreedy {
                    forward: None,
                    reverse: Some(HalfValidator::Simple(
                        SimpleValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                    )),
                },
                |reader| deserialize_validator(modifiers, reader),
                &[0, 1, 2],
            );
            test_round_trip_custom_deser(
                &Validator::NonGreedy {
                    forward: Some(HalfValidator::Simple(
                        SimpleValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                    )),
                    reverse: None,
                },
                |reader| deserialize_validator(modifiers, reader),
                &[0],
            );
            test_round_trip_custom_deser(
                &Validator::Greedy {
                    reverse: DfaValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                    full: DfaValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                },
                |reader| deserialize_validator(modifiers, reader),
                &[0, 1, 14],
            );

            // Test failure when compiling expressions.
            let mut reader = io::Cursor::new(b"\x05");
            assert!(deserialize_validator(modifiers, &mut reader).is_err());
        }

        #[test]
        fn test_wire_half_validator() {
            let hir = Hir::Dot;
            let analysis = analyze_hir(&hir, false);
            let modifiers = Modifiers::default();

            test_round_trip_custom_deser(
                &HalfValidator::Simple(
                    SimpleValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                ),
                |reader| deserialize_half_validator(modifiers, false, reader),
                &[0, 1],
            );
            test_round_trip_custom_deser(
                &HalfValidator::Dfa(DfaValidator::new(&hir, &analysis, modifiers, false).unwrap()),
                |reader| deserialize_half_validator(modifiers, false, reader),
                &[0, 1],
            );

            // Test failure when compiling expressions.
            let mut reader = io::Cursor::new(b"\x05");
            assert!(deserialize_half_validator(modifiers, false, &mut reader).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_type_traits_non_clonable;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(
            Validator::new(None, None, &Hir::Empty, Modifiers::default()).unwrap(),
        );
        test_type_traits_non_clonable(
            HalfValidator::new(
                &Hir::Empty,
                &analyze_hir(&Hir::Empty, false),
                Modifiers::default(),
                false,
            )
            .unwrap(),
        );
    }
}
