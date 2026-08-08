use std::ops::Range;

use crate::matcher::ValidatorCaches;
use crate::regex::Hir;

use super::analysis::{HirAnalysis, analyze_hir};
use super::{MatchType, Matches, Modifiers};

pub(crate) mod dfa;
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
pub(super) struct Validator {
    forward: Option<HalfValidator>,
    reverse: Option<HalfValidator>,
    pub(super) reverse_is_greedy: bool,
}

impl Validator {
    pub(super) fn new(
        pre: Option<&Hir>,
        post: Option<&Hir>,
        modifiers: Modifiers,
    ) -> Result<Self, crate::regex::Error> {
        let forward = match post {
            Some(hir) => {
                let analysis = analyze_hir(hir, modifiers.dot_all);
                Some(HalfValidator::new(hir, &analysis, modifiers, false)?)
            }
            None => None,
        };

        match pre {
            Some(pre) => {
                let left_analysis = analyze_hir(pre, modifiers.dot_all);

                Ok(Self {
                    forward,
                    reverse: Some(HalfValidator::new(pre, &left_analysis, modifiers, true)?),
                    reverse_is_greedy: left_analysis.has_greedy_repetitions,
                })
            }
            None => Ok(Self {
                forward,
                reverse: None,
                reverse_is_greedy: false,
            }),
        }
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
        matcher_index: usize,
        caches: &mut ValidatorCaches,
    ) -> Matches {
        let end = match &self.forward {
            Some(validator) => {
                let end =
                    std::cmp::min(mem.len(), mat.start.saturating_add(MAX_SPLIT_MATCH_LENGTH));

                let res = match validator {
                    HalfValidator::Simple(validator) => {
                        validator.find_anchored_fwd(mem, mat.start, end)
                    }
                    HalfValidator::Dfa(validator) => {
                        let cache = caches.get_or_insert(matcher_index, false, validator);
                        validator.find_anchored_fwd(mem, mat.start, end, match_type, cache)
                    }
                };

                match res {
                    Some(end) => end,
                    None => return Matches::None,
                }
            }
            None => mat.end,
        };

        match &self.reverse {
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

                loop {
                    let next = match validator {
                        HalfValidator::Simple(validator) => {
                            validator.find_anchored_rev(mem, start, mat.end)
                        }
                        HalfValidator::Dfa(validator) => {
                            let cache = caches.get_or_insert(matcher_index, true, validator);
                            validator.find_anchored_rev(mem, start, mat.end, match_type, cache)
                        }
                    };

                    match next {
                        Some(s) => {
                            matches.push(s..end);
                            start = s + 1;
                            if start > mat.end {
                                break;
                            }
                        }
                        None => break,
                    }
                }

                Matches::Multiple(matches)
            }
        }
    }
}

impl std::fmt::Display for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validator {{ ")?;
        match &self.reverse {
            Some(v) => write!(f, "reverse: {v}")?,
            None => write!(f, "reverse: none")?,
        }
        if self.reverse_is_greedy {
            write!(f, " (greedy)")?;
        }
        write!(f, ", ")?;
        match &self.forward {
            Some(v) => write!(f, "forward: {v}")?,
            None => write!(f, "forward: none")?,
        }
        write!(f, " }}")
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
    use super::{HalfValidator, Validator, dfa};

    impl Serialize for Validator {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.forward.serialize(writer)?;
            self.reverse.serialize(writer)?;
            self.reverse_is_greedy.serialize(writer)?;
            Ok(())
        }
    }

    pub(super) fn deserialize_validator<R: io::Read>(
        modifiers: Modifiers,
        reader: &mut R,
    ) -> io::Result<Validator> {
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
        let reverse_is_greedy = bool::deserialize_reader(reader)?;
        Ok(Validator {
            forward,
            reverse,
            reverse_is_greedy,
        })
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
                &Validator {
                    forward: None,
                    reverse: Some(HalfValidator::Simple(
                        SimpleValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                    )),
                    reverse_is_greedy: true,
                },
                |reader| deserialize_validator(modifiers, reader),
                &[0, 1, 2],
            );
            test_round_trip_custom_deser(
                &Validator {
                    forward: Some(HalfValidator::Simple(
                        SimpleValidator::new(&hir, &analysis, modifiers, false).unwrap(),
                    )),
                    reverse: None,
                    reverse_is_greedy: false,
                },
                |reader| deserialize_validator(modifiers, reader),
                &[0],
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
        test_type_traits_non_clonable(Validator::new(None, None, Modifiers::default()).unwrap());
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
