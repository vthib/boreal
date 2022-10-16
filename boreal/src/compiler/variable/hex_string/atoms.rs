use boreal_parser::HexToken;

use crate::compiler::variable::atom::AtomSet;

/// Extract an atom set from a hex string.
pub fn extract_atoms(hex_string: Vec<HexToken>) -> AtomSet {
    let mut atoms = HexAtoms::new();

    for token in hex_string {
        match token {
            HexToken::Byte(b) => atoms.add_byte(b),
            HexToken::Jump(_) => atoms.close(),
            // This could be handled, but it already is optimized when converting a hex string to
            // only literals. So it makes more sense to ignore it here.
            HexToken::MaskedByte(_, _) => atoms.close(),
            HexToken::Alternatives(alts) => atoms.add_alternatives(alts),
        }
    }

    atoms.finish()
}

struct HexAtoms {
    // Set of all already extracted atoms.
    atom_set: AtomSet,

    // Set of atoms currently being built.
    prefixes: Vec<Vec<u8>>,

    // Buffer of local atom being built.
    buffer: Vec<u8>,
}

impl HexAtoms {
    fn new() -> Self {
        Self {
            atom_set: AtomSet::default(),
            prefixes: Vec::new(),
            buffer: Vec::new(),
        }
    }

    fn add_byte(&mut self, b: u8) {
        self.buffer.push(b);
    }

    fn close(&mut self) {
        self.commit_buffer();
        self.atom_set
            .add_alternate(std::mem::take(&mut self.prefixes));
    }

    fn add_alternatives(&mut self, alts: Vec<Vec<HexToken>>) {
        // Don't make the combinatory grow too much
        if self
            .prefixes
            .len()
            .checked_mul(alts.len())
            .map_or(false, |v| v > 32)
        {
            self.close();
            return;
        }

        // Then, do the cross product between our prefixes literals and the alternatives
        let suffixes: Vec<Vec<u8>> = alts
            .into_iter()
            .map(extract_atoms)
            .flat_map(AtomSet::into_literals)
            .collect();
        // If of the suffix is empty, it means we did not have a single atom for its branch,
        // and we thus cannot add the alternatives.
        if suffixes.iter().any(Vec::is_empty) {
            self.close();
        }

        self.commit_buffer();
        self.cartesian_product(&suffixes);
    }

    fn finish(mut self) -> AtomSet {
        self.close();
        self.atom_set
    }

    fn cartesian_product(&mut self, suffixes: &[Vec<u8>]) {
        self.prefixes = self
            .prefixes
            .iter()
            .flat_map(|prefix| {
                suffixes.iter().map(|suffix| {
                    prefix
                        .iter()
                        .copied()
                        .chain(suffix.iter().copied())
                        .collect()
                })
            })
            .collect();
    }

    fn commit_buffer(&mut self) {
        let buffer = std::mem::take(&mut self.buffer);
        if self.prefixes.is_empty() {
            self.prefixes.push(buffer);
        } else {
            for t in &mut self.prefixes {
                t.extend(&buffer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse_hex_string;
    use super::*;

    #[test]
    fn test_extract_atoms() {
        #[track_caller]
        fn test(hex_string: &str, expected_atoms: &[&[u8]]) {
            let hex_string = parse_hex_string(hex_string);

            let atoms = extract_atoms(hex_string);
            assert_eq!(atoms.into_literals(), expected_atoms);
        }

        test("{ AB CD 01 }", &[b"\xab\xcd\x01"]);
        test("{ AB ?D 01 }", &[b"\xab"]);
        test("{ D? FE }", &[b"\xFE"]);
        test("{ ( AA | BB ) F? }", &[b"\xAA", b"\xBB"]);
        test(
            "{ AB ( 01 | 23 45) ( 67 | 89 | F0 ) CD }",
            &[
                b"\xAB\x01\x67\xCD",
                b"\xAB\x01\x89\xCD",
                b"\xAB\x01\xF0\xCD",
                b"\xAB\x23\x45\x67\xCD",
                b"\xAB\x23\x45\x89\xCD",
                b"\xAB\x23\x45\xF0\xCD",
            ],
        );

        // jump or masked bytes should invalidate alternations if one branch does not have a single
        // byte
        test(
            "{ AB ( 11 | 22 ) 33 ( ?1 | 44 ) }",
            &[b"\xAB\x11\x33", b"\xAB\x22\x33"],
        );

        // Test imbrication of alternations
        test(
            "{ ( 01 | ( 23 | FF ) ( ( 45 | 67 ) | 58 ( AA | BB | CC ) | DD ) ) }",
            &[
                b"\x01",
                b"\x23\x45",
                b"\x23\x67",
                b"\x23\x58\xAA",
                b"\x23\x58\xBB",
                b"\x23\x58\xCC",
                b"\x23\xDD",
                b"\xFF\x45",
                b"\xFF\x67",
                b"\xFF\x58\xAA",
                b"\xFF\x58\xBB",
                b"\xFF\x58\xCC",
                b"\xFF\xDD",
            ],
        );

        // Do not grow alternations too much, 32 max
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) ( 31 | 32 ) ( 41 | 42 ) ( 51 | 52 ) ( 61 | 62 ) ( 71 | 72 ) 88 }",
            &[
                b"\x11\x21\x31\x41\x51",
                b"\x11\x21\x31\x41\x52",
                b"\x11\x21\x31\x42\x51",
                b"\x11\x21\x31\x42\x52",
                b"\x11\x21\x32\x41\x51",
                b"\x11\x21\x32\x41\x52",
                b"\x11\x21\x32\x42\x51",
                b"\x11\x21\x32\x42\x52",
                b"\x11\x22\x31\x41\x51",
                b"\x11\x22\x31\x41\x52",
                b"\x11\x22\x31\x42\x51",
                b"\x11\x22\x31\x42\x52",
                b"\x11\x22\x32\x41\x51",
                b"\x11\x22\x32\x41\x52",
                b"\x11\x22\x32\x42\x51",
                b"\x11\x22\x32\x42\x52",
                b"\x12\x21\x31\x41\x51",
                b"\x12\x21\x31\x41\x52",
                b"\x12\x21\x31\x42\x51",
                b"\x12\x21\x31\x42\x52",
                b"\x12\x21\x32\x41\x51",
                b"\x12\x21\x32\x41\x52",
                b"\x12\x21\x32\x42\x51",
                b"\x12\x21\x32\x42\x52",
                b"\x12\x22\x31\x41\x51",
                b"\x12\x22\x31\x41\x52",
                b"\x12\x22\x31\x42\x51",
                b"\x12\x22\x31\x42\x52",
                b"\x12\x22\x32\x41\x51",
                b"\x12\x22\x32\x41\x52",
                b"\x12\x22\x32\x42\x51",
                b"\x12\x22\x32\x42\x52",
            ],
        );
        test(
            "{ ( 11 | 12 ) ( 21 | 22 ) 33 ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10  ) }",
            &[
                b"\x11\x21\x33",
                b"\x11\x22\x33",
                b"\x12\x21\x33",
                b"\x12\x22\x33",
            ],
        );

        // TODO: to improve, there are diminishing returns in computing the longest atoms.
        test(
            "{ 11 22 33 44 55 66 77 ( 88 | 99 | AA | BB ) }",
            &[
                b"\x11\x22\x33\x44\x55\x66\x77\x88",
                b"\x11\x22\x33\x44\x55\x66\x77\x99",
                b"\x11\x22\x33\x44\x55\x66\x77\xAA",
                b"\x11\x22\x33\x44\x55\x66\x77\xBB",
            ],
        );

        test("{ 11 ?A 22 33 [1] 44 55 66 A? 77 88 }", &[b"\x44\x55\x66"]);

        // hex strings found in some real rules
        test(
            "{ 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? 00 04 00 02 00 04 ?? ?? }",
            &[b"\x00\x01\x00\x01\x00\x02"]);

        test(
            "{ c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }",
            &[b"\x00\x00\x01\x00"],
        );
        test(
            "{ 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 }",
            &[b"\x00\x64\x65\x66\x61\x75\x6C\x74\x2E\x70\x72\x6F\x70\x65\x72\x74\x69\x65\x73"],
        );
        test(
"{ FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? \
83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }",
            &[b"\x00\x83\xC5\x04\x8B"]);
        test(
            "{ ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) \
04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) \
02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) \
( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }",
            &[
                b"\x02\xAA\x02\xC1\x0F\x85\x8b",
                b"\x02\xAA\x02\xC1\x0F\x85\x41\x8b",
                b"\x02\xAA\x02\xC1\x0F\x85\x44\x8b",
                b"\x02\xAA\x02\xC1\x0F\x85\x45\x8b",
                b"\x02\xAA\x02\xC1\x75\x8b",
                b"\x02\xAA\x02\xC1\x75\x41\x8b",
                b"\x02\xAA\x02\xC1\x75\x44\x8b",
                b"\x02\xAA\x02\xC1\x75\x45\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x0F\x85\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x0F\x85\x41\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x0F\x85\x44\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x0F\x85\x45\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x75\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x75\x41\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x75\x44\x8b",
                b"\x3C\x24\x02\xAA\x02\xC1\x75\x45\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x0F\x85\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x0F\x85\x41\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x0F\x85\x44\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x0F\x85\x45\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x75\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x75\x41\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x75\x44\x8b",
                b"\x7d\x00\x02\xAA\x02\xC1\x75\x45\x8b",
            ],
        );
    }
}
