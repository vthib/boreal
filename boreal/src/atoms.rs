//! Utilities related to the extraction of atoms.
//!
//! An atom is a byte string that is contained in a rule's variable, with additional
//! constraints:
//!
//! - If an atom is found, then the variable may be present.
//! - If no atoms are found, then the variable cannot be found.
//!
//! That is, for any possible match of a variable, an atom in the set of the variable must be
//! contained in the match.
//!
//! Atoms are selected by computing a rank for each atom: the higher the rank, the preferred the
//! atom. This rank is related to how rare the atom should be found during scanning, and thus
//! the rate of false positive matches.

/// Maximum size of an atom extracted from a literal and used in the AC scan.
pub const ATOM_SIZE: usize = 4;

/// An atom extracted from literals.
///
/// This is equivalent to a `Vec<u8>` with max length `ATOM_SIZE`, but without
/// any allocation.
#[derive(Copy, Clone, Hash, PartialEq, Eq, Debug)]
pub struct Atom {
    data: [u8; ATOM_SIZE],
    len: u8,
}

impl Atom {
    pub fn make_ascii_lowercase(&mut self) {
        for byte in self.as_mut() {
            byte.make_ascii_lowercase();
        }
    }

    pub fn len(self) -> usize {
        usize::from(self.len)
    }
}

impl AsRef<[u8]> for Atom {
    fn as_ref(&self) -> &[u8] {
        &self.data[..(self.len as usize)]
    }
}

impl AsMut<[u8]> for Atom {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..(self.len as usize)]
    }
}

/// Pick a shorter atom from a literal.
///
/// This returns a tuple of:
/// - the extracted atom.
/// - the starting offset of the atom in the literal.
pub fn pick_atom_in_literal(lit: &[u8]) -> (Atom, usize) {
    atoms_from_literal(lit)
        .max_by_key(|(atom, _)| atom_rank(*atom))
        .unwrap_or_else(|| {
            (
                Atom {
                    data: Default::default(),
                    len: 0,
                },
                0,
            )
        })
}

struct AtomsIterator<'a> {
    lit: &'a [u8],
    index: usize,
    done: bool,
}

impl Iterator for AtomsIterator<'_> {
    type Item = (Atom, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.index == 0 && self.lit.len() <= ATOM_SIZE {
            let mut atom = Atom {
                data: Default::default(),
                #[allow(clippy::cast_possible_truncation, reason = "checked above")]
                len: self.lit.len() as u8,
            };
            atom.data[..self.lit.len()].copy_from_slice(self.lit);
            self.done = true;
            return Some((atom, 0));
        }

        let index = self.index;
        let lit = &self.lit[index..];
        if lit.len() < ATOM_SIZE {
            self.done = true;
            return None;
        }

        let atom = Atom {
            data: [lit[0], lit[1], lit[2], lit[3]],
            len: 4,
        };
        self.index += 1;
        Some((atom, index))
    }
}

fn atoms_from_literal(lit: &[u8]) -> AtomsIterator<'_> {
    AtomsIterator {
        lit,
        index: 0,
        done: false,
    }
}

pub fn atom_quality_from_literal(lit: &[u8]) -> u32 {
    atoms_from_literal(lit)
        .map(|(atom, _)| atom_rank(atom))
        .max()
        .unwrap_or(0)
}

/// Compute the rank of an atom.
///
/// The higher the value, the best quality (i.e., the less false positives).
pub fn atom_rank(atom: Atom) -> u32 {
    // This algorithm is straight copied from libyara.
    // TODO: Probably want to revisit this.
    let mut quality = 0_u32;
    let mut bitmask = [false; 256];
    let mut nb_uniq = 0;

    for b in atom.as_ref() {
        quality += byte_rank(*b);

        if !bitmask[*b as usize] {
            bitmask[*b as usize] = true;
            nb_uniq += 1;
        }
    }

    // If all the bytes in the atom are equal and very common, let's penalize
    // it heavily.
    if nb_uniq == 1 && (bitmask[0] || bitmask[0x20] || bitmask[0xCC] || bitmask[0xFF]) {
        quality -= 10 * u32::from(atom.len);
    }
    // In general atoms with more unique bytes have a better quality, so let's
    // boost the quality in the amount of unique bytes.
    else {
        quality += 2 * nb_uniq;
    }

    quality
}

pub fn byte_rank(b: u8) -> u32 {
    match b {
        0x00 | 0xCC | 0xFF => 10,
        v if v.is_ascii_lowercase() => 18,
        _ => 20,
    }
}
