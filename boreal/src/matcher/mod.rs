use std::{collections::HashSet, ops::Range};

use boreal_parser::rule::VariableModifiers;

use crate::regex::Hir;

mod analysis;
mod base64;
mod literals;
mod only_literals;
mod raw;
mod validator;
mod widener;

#[derive(Debug)]
#[cfg_attr(all(test, feature = "serialize"), derive(PartialEq))]
pub(crate) struct Matcher {
    /// Set of literals extracted from the variable.
    ///
    /// Will be used by the AC pass to scan for the variable.
    ///
    /// If both ascii and wide are set in the flags, it is expected that the literals are
    /// composed of:
    /// - the ascii literals first
    /// - the wide literals second
    ///
    /// This is required in order to know which kind is a literal match, as checking its value
    /// would be buggy.
    pub(crate) literals: Vec<Vec<u8>>,

    kind: MatcherKind,

    /// Modifiers related to matching.
    pub(crate) modifiers: Modifiers,
}

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub(crate) struct Modifiers {
    pub fullword: bool,
    pub wide: bool,
    pub ascii: bool,
    pub nocase: bool,
    pub dot_all: bool,
    pub xor_start: Option<u8>,
}

/// State of an aho-corasick match on a [`Matcher`] literals.
#[derive(Clone, Debug)]
pub enum AcMatchStatus {
    /// The literal yields multiple matches (can be empty).
    Multiple(Vec<Range<usize>>),

    /// The literal yields a single match (None if invalid).
    ///
    /// This is an optim to avoid allocating a Vec for the very common case of returning a
    /// single match.
    Single(Range<usize>),

    /// The literal does not give any match.
    None,
}

/// Type of a match.
#[derive(Copy, Clone, Debug)]
pub enum MatchType {
    /// The match is on ascii literals.
    Ascii,

    /// The match is on the wide literals for an wide only variable.
    WideStandard,

    /// The match is on wide versions of the literals for an ascii and wide variable.
    WideAlternate,
}

impl MatchType {
    fn is_wide(self) -> bool {
        match self {
            MatchType::Ascii => false,
            MatchType::WideStandard | MatchType::WideAlternate => true,
        }
    }
}

#[derive(Debug)]
enum Matches {
    /// The literal yields multiple matches (can be empty).
    Multiple(Vec<Range<usize>>),

    /// The literal yields a single match (None if invalid).
    ///
    /// This is an optim to avoid allocating a Vec for the very common case of returning a
    /// single match.
    Single(Range<usize>),

    /// The literal does not give any match.
    None,
}

#[derive(Debug)]
#[cfg_attr(all(test, feature = "serialize"), derive(PartialEq))]
enum MatcherKind {
    /// The literals cover entirely the variable.
    Literals,
    /// The regex can confirm matches from AC literal matches.
    Atomized { validator: validator::Validator },

    /// The regex cannot confirm matches from AC literal matches.
    Raw(raw::RawMatcher),
}

impl Matcher {
    pub fn new_regex(hir: &Hir, modifiers: Modifiers) -> Result<Matcher, crate::regex::Error> {
        let analysis = analysis::analyze_hir(hir, modifiers.dot_all);

        // Do not use an AC if anchors are present, it will be much efficient to just run
        // the regex directly.
        if analysis.has_start_or_end_line {
            let kind = MatcherKind::Raw(raw::RawMatcher::new(hir, &analysis, modifiers)?);
            return Ok(Self {
                literals: Vec::new(),
                kind,
                modifiers,
            });
        }

        if let Some(count) = analysis.nb_alt_literals {
            // The regex can be covered entirely by literals. This is optimal, so use this if possible.
            // TODO: handle more modifiers
            if count < 100 && !modifiers.nocase && !modifiers.wide {
                if let Some(literals) = only_literals::hir_to_only_literals(hir) {
                    return Ok(Self {
                        literals,
                        kind: MatcherKind::Literals,
                        modifiers,
                    });
                }
            }
        }

        let literals::LiteralsDetails {
            mut literals,
            pre_hir,
            post_hir,
        } = literals::get_literals_details(hir, modifiers.dot_all);

        // Dedup literals
        let mut new_lits = Vec::with_capacity(literals.len());
        let mut known_lits = HashSet::with_capacity(literals.len());
        for lit in literals {
            if known_lits.insert(lit.clone()) {
                new_lits.push(lit);
            }
        }
        literals = new_lits;

        apply_ascii_wide_flags_on_literals(&mut literals, modifiers);

        let kind = if literals.is_empty() {
            MatcherKind::Raw(raw::RawMatcher::new(hir, &analysis, modifiers)?)
        } else {
            MatcherKind::Atomized {
                validator: validator::Validator::new(
                    pre_hir.as_ref(),
                    post_hir.as_ref(),
                    hir,
                    modifiers,
                )?,
            }
        };

        Ok(Self {
            literals,
            kind,
            modifiers,
        })
    }

    pub fn new_bytes(value: Vec<u8>, modifiers: &VariableModifiers) -> Self {
        let mut literals = Vec::with_capacity(2);
        if modifiers.wide {
            if modifiers.ascii {
                let wide = string_to_wide(&value);
                literals.push(value);
                literals.push(wide);
            } else {
                literals.push(string_to_wide(&value));
            }
        } else {
            literals.push(value);
        }

        if let Some(xor_details) = modifiers.xor {
            // For each literal, for each byte in the xor range, build a new literal
            let xor_range = xor_details.0..=xor_details.1;
            let xor_range_len = xor_range.len(); // modifiers.xor_range.1.saturating_sub(modifiers.xor_range.0) + 1;
            let mut new_literals: Vec<Vec<u8>> = Vec::with_capacity(literals.len() * xor_range_len);

            // Ascii literals must be first, then wide literals. Since the "literals" var
            // is the ascii literals then the wide ones, the order is preserved.
            for lit in literals {
                for xor_byte in xor_range.clone() {
                    new_literals.push(lit.iter().map(|c| c ^ xor_byte).collect());
                }
            }
            return Self {
                literals: new_literals,
                kind: MatcherKind::Literals,
                modifiers: Modifiers {
                    fullword: modifiers.fullword,
                    wide: modifiers.wide,
                    ascii: modifiers.ascii,
                    nocase: modifiers.nocase,
                    dot_all: false,
                    xor_start: Some(xor_details.0),
                },
            };
        }

        if let Some(base64) = &modifiers.base64 {
            let mut old_literals = Vec::with_capacity(literals.len() * 3);
            std::mem::swap(&mut old_literals, &mut literals);

            if base64.ascii {
                for lit in &old_literals {
                    for offset in 0..=2 {
                        if let Some(lit) =
                            base64::encode_base64(lit, base64.alphabet.as_ref(), offset)
                        {
                            // Fullword is not compatible with base64 modifiers, hence ordering of
                            // literals is not required.
                            if base64.wide {
                                literals.push(string_to_wide(&lit));
                            }
                            literals.push(lit);
                        }
                    }
                }
            } else {
                for lit in &old_literals {
                    for offset in 0..=2 {
                        if let Some(lit) =
                            base64::encode_base64(lit, base64.alphabet.as_ref(), offset)
                        {
                            literals.push(string_to_wide(&lit));
                        }
                    }
                }
            }
        }

        Matcher {
            literals,
            kind: MatcherKind::Literals,
            modifiers: Modifiers {
                fullword: modifiers.fullword,
                wide: modifiers.wide,
                ascii: modifiers.ascii,
                nocase: modifiers.nocase,
                dot_all: false,
                xor_start: None,
            },
        }
    }

    /// Confirm that an AC match is a match on the given literal.
    ///
    /// This is needed because the AC might optimize literals and get false positive matches.
    /// This function is used to confirm the tentative match does match the literal with the given
    /// index.
    pub fn confirm_ac_literal(
        &self,
        mem: &[u8],
        mat: &Range<usize>,
        literal_index: usize,
    ) -> Option<MatchType> {
        let literal = &self.literals[literal_index];

        if self.modifiers.nocase {
            if !literal.eq_ignore_ascii_case(&mem[mat.start..mat.end]) {
                return None;
            }
        } else if literal != &mem[mat.start..mat.end] {
            return None;
        }

        match (self.modifiers.ascii, self.modifiers.wide) {
            (false, true) => Some(MatchType::WideStandard),
            // If the variable has both ascii and wide, then the ascii literals are in the first
            // half, and the wide ones in the second half.
            (true, true) if literal_index >= self.literals.len() / 2 => {
                Some(MatchType::WideAlternate)
            }
            _ => Some(MatchType::Ascii),
        }
    }

    pub fn get_xor_key(&self, literal_index: usize) -> u8 {
        #[allow(clippy::cast_possible_truncation)]
        match self.modifiers.xor_start {
            Some(start) => {
                if self.modifiers.wide {
                    match literal_index.checked_sub(self.literals.len() / 2) {
                        Some(index) => start + (index as u8),
                        None => start + (literal_index as u8),
                    }
                } else {
                    start + (literal_index as u8)
                }
            }
            None => 0,
        }
    }

    pub fn process_ac_match(
        &self,
        mem: &[u8],
        mat: Range<usize>,
        start_position: usize,
        match_type: MatchType,
    ) -> AcMatchStatus {
        match &self.kind {
            MatcherKind::Literals => {
                if self.validate_fullword(mem, &mat, match_type) {
                    AcMatchStatus::Single(mat)
                } else {
                    AcMatchStatus::None
                }
            }
            MatcherKind::Atomized { validator } => {
                match validator.validate_match(mem, mat, start_position, match_type) {
                    Matches::None => AcMatchStatus::None,
                    Matches::Single(m) => {
                        if self.validate_fullword(mem, &m, match_type) {
                            AcMatchStatus::Single(m)
                        } else {
                            AcMatchStatus::None
                        }
                    }
                    Matches::Multiple(ms) => AcMatchStatus::Multiple(
                        ms.into_iter()
                            .filter(|m| self.validate_fullword(mem, m, match_type))
                            .collect(),
                    ),
                }
            }
            MatcherKind::Raw(_) => {
                // A raw matcher has no literals, so this is unreachable.
                debug_assert!(false);
                AcMatchStatus::None
            }
        }
    }

    pub fn find_next_match_at(&self, mem: &[u8], mut offset: usize) -> Option<Range<usize>> {
        let MatcherKind::Raw(regex) = &self.kind else {
            // This variable should have been covered by the AC pass, so we should
            // not be able to reach this code.
            debug_assert!(false);
            return None;
        };

        while offset < mem.len() {
            let (mat, match_type) = regex.find_next_match_at(mem, offset, self.modifiers)?;

            if self.validate_fullword(mem, &mat, match_type) {
                return Some(mat);
            }

            offset = mat.start + 1;
        }
        None
    }

    pub fn to_desc(&self) -> String {
        match &self.kind {
            MatcherKind::Literals => "Literals".to_owned(),
            MatcherKind::Atomized { validator } => format!("Atomized {{ {validator} }}"),
            MatcherKind::Raw(_) => "Raw".to_owned(),
        }
    }

    fn validate_fullword(&self, mem: &[u8], mat: &Range<usize>, match_type: MatchType) -> bool {
        !self.modifiers.fullword || check_fullword(mem, mat, match_type)
    }
}

/// Check the match respects a possible fullword modifier for the variable.
fn check_fullword(mem: &[u8], mat: &Range<usize>, match_type: MatchType) -> bool {
    if match_type.is_wide() {
        if mat.start > 1
            && mem[mat.start - 1] == b'\0'
            && mem[mat.start - 2].is_ascii_alphanumeric()
        {
            return false;
        }
        if mat.end + 1 < mem.len()
            && mem[mat.end].is_ascii_alphanumeric()
            && mem[mat.end + 1] == b'\0'
        {
            return false;
        }
    } else {
        if mat.start > 0 && mem[mat.start - 1].is_ascii_alphanumeric() {
            return false;
        }
        if mat.end < mem.len() && mem[mat.end].is_ascii_alphanumeric() {
            return false;
        }
    }

    true
}

fn apply_ascii_wide_flags_on_literals(literals: &mut Vec<Vec<u8>>, modifiers: Modifiers) {
    if !modifiers.wide {
        return;
    }

    if modifiers.ascii {
        let wide_literals: Vec<_> = literals.iter().map(|v| widen_literal(v)).collect();
        literals.extend(wide_literals);
    } else {
        for lit in literals {
            *lit = widen_literal(lit);
        }
    }
}

fn widen_literal(literal: &[u8]) -> Vec<u8> {
    let mut new_lit = Vec::with_capacity(literal.len() * 2);
    for b in literal {
        new_lit.push(*b);
        new_lit.push(0);
    }
    new_lit
}

/// Convert an ascii string to a wide string
fn string_to_wide(s: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(s.len() * 2);
    for b in s {
        res.push(*b);
        res.push(b'\0');
    }
    res
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use crate::matcher::Modifiers;

    use super::raw::RawMatcher;
    use super::validator::Validator;
    use super::{Matcher, MatcherKind};

    impl Serialize for Matcher {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.literals.serialize(writer)?;
            self.modifiers.serialize(writer)?;
            self.kind.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for Matcher {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let literals = <Vec<Vec<u8>>>::deserialize_reader(reader)?;
            let modifiers = Modifiers::deserialize_reader(reader)?;
            let kind = deserialize_matcher_kind(modifiers, reader)?;
            Ok(Self {
                literals,
                kind,
                modifiers,
            })
        }
    }

    impl Serialize for MatcherKind {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            match self {
                Self::Literals => {
                    0_u8.serialize(writer)?;
                }
                Self::Atomized { validator } => {
                    1_u8.serialize(writer)?;
                    validator.serialize(writer)?;
                }
                Self::Raw(matcher) => {
                    2_u8.serialize(writer)?;
                    matcher.serialize(writer)?;
                }
            }
            Ok(())
        }
    }

    pub(super) fn deserialize_matcher_kind<R: io::Read>(
        modifiers: Modifiers,
        reader: &mut R,
    ) -> io::Result<MatcherKind> {
        let discriminant = u8::deserialize_reader(reader)?;
        match discriminant {
            0 => Ok(MatcherKind::Literals),
            1 => {
                let validator = Validator::deserialize(modifiers, reader)?;
                Ok(MatcherKind::Atomized { validator })
            }
            2 => {
                let matcher = RawMatcher::deserialize(modifiers, reader)?;
                Ok(MatcherKind::Raw(matcher))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid discriminant when deserializing a matcher kind: {v}"),
            )),
        }
    }

    impl Serialize for Modifiers {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.fullword.serialize(writer)?;
            self.wide.serialize(writer)?;
            self.ascii.serialize(writer)?;
            self.nocase.serialize(writer)?;
            self.dot_all.serialize(writer)?;
            self.xor_start.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for Modifiers {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let fullword = bool::deserialize_reader(reader)?;
            let wide = bool::deserialize_reader(reader)?;
            let ascii = bool::deserialize_reader(reader)?;
            let nocase = bool::deserialize_reader(reader)?;
            let dot_all = bool::deserialize_reader(reader)?;
            let xor_start = <Option<u8>>::deserialize_reader(reader)?;
            Ok(Self {
                fullword,
                wide,
                ascii,
                nocase,
                dot_all,
                xor_start,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::matcher::analysis::analyze_hir;
        use crate::regex::Hir;
        use crate::wire::tests::{test_round_trip, test_round_trip_custom_deser};

        use super::*;

        #[test]
        fn test_wire_matcher() {
            test_round_trip(
                &Matcher {
                    literals: vec![vec![3]],
                    modifiers: Modifiers::default(),
                    kind: MatcherKind::Literals,
                },
                &[0, 9, 15],
            );
        }

        #[test]
        fn test_wire_matcher_kind() {
            let modifiers = Modifiers::default();
            let hir = Hir::Dot;
            let analysis = analyze_hir(&hir, true);

            test_round_trip_custom_deser(
                &MatcherKind::Literals,
                |reader| deserialize_matcher_kind(modifiers, reader),
                &[0],
            );
            test_round_trip_custom_deser(
                &MatcherKind::Atomized {
                    validator: Validator::new(None, None, &hir, modifiers).unwrap(),
                },
                |reader| deserialize_matcher_kind(modifiers, reader),
                &[0, 1],
            );
            test_round_trip_custom_deser(
                &MatcherKind::Raw(RawMatcher::new(&hir, &analysis, modifiers).unwrap()),
                |reader| deserialize_matcher_kind(modifiers, reader),
                &[0, 1],
            );

            let mut reader = io::Cursor::new(b"\x05");
            assert!(deserialize_matcher_kind(modifiers, &mut reader).is_err());
        }

        #[test]
        fn test_wire_modifiers() {
            test_round_trip(
                &Modifiers {
                    fullword: false,
                    wide: true,
                    ascii: false,
                    nocase: true,
                    dot_all: false,
                    xor_start: None,
                },
                &[0, 1, 2, 3, 4, 5],
            );
            test_round_trip(
                &Modifiers {
                    fullword: true,
                    wide: false,
                    ascii: true,
                    nocase: false,
                    dot_all: true,
                    xor_start: Some(3),
                },
                &[0, 1, 2, 3, 4, 5],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(Matcher {
            literals: vec![],
            modifiers: Modifiers {
                dot_all: false,
                fullword: false,
                ascii: false,
                wide: false,
                nocase: false,
                xor_start: None,
            },
            kind: MatcherKind::Literals,
        });
        test_type_traits_non_clonable(MatcherKind::Literals);
        test_type_traits(Modifiers {
            fullword: false,
            ascii: false,
            wide: false,
            nocase: false,
            dot_all: false,
            xor_start: None,
        });
        test_type_traits(MatchType::Ascii);
        test_type_traits_non_clonable(Matches::None);
        test_type_traits(AcMatchStatus::None);
    }
}
