use boreal_parser::{HexMask, HexToken};

/// Can the hex string be expressed using only literals.
pub fn can_use_only_literals(hex_string: &[HexToken]) -> bool {
    let nb_literals = match count_total_literals(hex_string) {
        Some(v) => v,
        None => return false,
    };

    nb_literals < 100
}

/// Count the total of literals that would needed to exhaustively express the hex string.
fn count_total_literals(hex_string: &[HexToken]) -> Option<usize> {
    let mut nb_lits = 1_usize;

    for token in hex_string {
        match token {
            HexToken::Byte(_) => (),
            HexToken::Jump(_) => return None,
            HexToken::MaskedByte(_, mask) => match mask {
                HexMask::Left | HexMask::Right => {
                    nb_lits = nb_lits.checked_mul(16)?;
                }
                HexMask::All => return None,
            },
            HexToken::Alternatives(alts) => {
                let mut nb_alts = 0_usize;
                for alt in alts {
                    nb_alts = nb_alts.checked_add(count_total_literals(alt)?)?;
                }
                nb_lits = nb_lits.checked_mul(nb_alts)?;
            }
        }
    }

    Some(nb_lits)
}

/// Convert a hex string into an array of literals that entirely express it.
pub fn hex_string_to_only_literals(hex_string: Vec<HexToken>) -> Vec<Vec<u8>> {
    let mut literals = HexLiterals::new();

    for token in hex_string {
        match token {
            HexToken::Byte(b) => literals.add_byte(b),
            HexToken::Jump(_) => unreachable!(),
            HexToken::MaskedByte(b, mask) => literals.add_masked_byte(b, &mask),
            HexToken::Alternatives(alts) => literals.add_alternatives(alts),
        }
    }

    literals.finish()
}

struct HexLiterals {
    // Combination of all possible literals.
    all: Vec<Vec<u8>>,
    // Buffer of a string of bytes to be added to all the literals.
    buffer: Vec<u8>,
}

impl HexLiterals {
    fn new() -> Self {
        Self {
            all: Vec::new(),
            buffer: Vec::new(),
        }
    }

    fn add_byte(&mut self, b: u8) {
        self.buffer.push(b);
    }

    fn add_alternatives(&mut self, alts: Vec<Vec<HexToken>>) {
        // First, commit the local buffer, to have a proper list of all possible literals
        self.commit_buffer();

        // Then, do the cross product between our prefixes literals and the alternatives
        let suffixes: Vec<Vec<u8>> = alts
            .into_iter()
            .flat_map(hex_string_to_only_literals)
            .collect();
        self.cartesian_product(&suffixes);
    }

    fn add_masked_byte(&mut self, b: u8, mask: &HexMask) {
        // First, commit the local buffer, to have a proper list of all possible literals
        self.commit_buffer();

        // Then, build the suffixes corresponding to the mask.
        let suffixes: Vec<Vec<u8>> = match mask {
            HexMask::Left => (0..=0xF).map(|i| vec![(i << 4) + b]).collect(),
            HexMask::Right => {
                let b = b << 4;
                (b..=(b + 0xF)).map(|i| vec![i]).collect()
            }
            HexMask::All => unreachable!(),
        };
        self.cartesian_product(&suffixes);
    }

    fn finish(mut self) -> Vec<Vec<u8>> {
        self.commit_buffer();
        self.all
    }

    fn cartesian_product(&mut self, suffixes: &[Vec<u8>]) {
        self.all = self
            .all
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
        if self.all.is_empty() {
            self.all.push(buffer);
        } else {
            for t in &mut self.all {
                t.extend(&buffer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::variable::tests::parse_hex_string;

    use super::*;

    #[test]
    fn test_hex_string_to_only_literals() {
        #[track_caller]
        fn test(hex_string: &str, expected_lits: &[&[u8]]) {
            let hex_string = parse_hex_string(hex_string);

            let count = count_total_literals(&hex_string);
            let lits = hex_string_to_only_literals(hex_string);
            assert_eq!(lits, expected_lits);
            assert_eq!(lits.len(), count.unwrap());
        }

        test("{ AB CD 01 }", &[b"\xab\xcd\x01"]);

        // Test masks
        test(
            "{ AB ?D 01 }",
            &[
                b"\xab\x0d\x01",
                b"\xab\x1d\x01",
                b"\xab\x2d\x01",
                b"\xab\x3d\x01",
                b"\xab\x4d\x01",
                b"\xab\x5d\x01",
                b"\xab\x6d\x01",
                b"\xab\x7d\x01",
                b"\xab\x8d\x01",
                b"\xab\x9d\x01",
                b"\xab\xAd\x01",
                b"\xab\xBd\x01",
                b"\xab\xCd\x01",
                b"\xab\xDd\x01",
                b"\xab\xEd\x01",
                b"\xab\xFd\x01",
            ],
        );
        test(
            "{ D? FE }",
            &[
                b"\xD0\xFE",
                b"\xD1\xFE",
                b"\xD2\xFE",
                b"\xD3\xFE",
                b"\xD4\xFE",
                b"\xD5\xFE",
                b"\xD6\xFE",
                b"\xD7\xFE",
                b"\xD8\xFE",
                b"\xD9\xFE",
                b"\xDA\xFE",
                b"\xDB\xFE",
                b"\xDC\xFE",
                b"\xDD\xFE",
                b"\xDE\xFE",
                b"\xDF\xFE",
            ],
        );

        // Test alternation
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

        // Test masks + alternation
        test(
            "{ ( AA | BB ) F? }",
            &[
                b"\xAA\xF0",
                b"\xAA\xF1",
                b"\xAA\xF2",
                b"\xAA\xF3",
                b"\xAA\xF4",
                b"\xAA\xF5",
                b"\xAA\xF6",
                b"\xAA\xF7",
                b"\xAA\xF8",
                b"\xAA\xF9",
                b"\xAA\xFA",
                b"\xAA\xFB",
                b"\xAA\xFC",
                b"\xAA\xFD",
                b"\xAA\xFE",
                b"\xAA\xFF",
                b"\xBB\xF0",
                b"\xBB\xF1",
                b"\xBB\xF2",
                b"\xBB\xF3",
                b"\xBB\xF4",
                b"\xBB\xF5",
                b"\xBB\xF6",
                b"\xBB\xF7",
                b"\xBB\xF8",
                b"\xBB\xF9",
                b"\xBB\xFA",
                b"\xBB\xFB",
                b"\xBB\xFC",
                b"\xBB\xFD",
                b"\xBB\xFE",
                b"\xBB\xFF",
            ],
        );
    }
}
