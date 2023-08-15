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
const ATOM_SIZE: usize = 4;

/// Pick a shorter atom from a literal.
///
/// This returns a tuple of:
/// - the offset to add to the start of the literal, in order to get the start of the atom.
/// - the offset to substract from the end of the literal, in order to get the end of the atom.
pub fn pick_atom_in_literal(lit: &[u8]) -> (usize, usize) {
    if lit.len() <= ATOM_SIZE {
        return (0, 0);
    }

    lit.windows(ATOM_SIZE)
        .enumerate()
        .max_by_key(|(_, s)| atom_rank(s))
        .map_or((0, 0), |(i, _)| (i, lit.len() - i - ATOM_SIZE))
}

/// Compute the rank of a set of atoms.
///
/// The higher the value, the best quality (i.e., the less false positives).
pub fn atoms_rank(literals: &[Vec<u8>]) -> u32 {
    // Get the min rank. This is probably the best solution, it isn't clear if a better one
    // is easy to find.
    literals
        .iter()
        .map(|lit| {
            if lit.len() > 4 {
                lit.windows(ATOM_SIZE).map(atom_rank).max().unwrap()
            } else {
                atom_rank(lit)
            }
        })
        .min()
        .unwrap_or(0)
}

/// Compute the rank of an atom.
///
/// The higher the value, the best quality (i.e., the less false positives).
fn atom_rank(atom: &[u8]) -> u32 {
    // This algorithm is straight copied from libyara.
    // TODO: Probably want to revisit this.
    let mut quality = 0_u32;
    let mut bitmask = [false; 256];
    let mut nb_uniq = 0;

    for b in atom {
        quality += byte_rank(*b);

        if !bitmask[*b as usize] {
            bitmask[*b as usize] = true;
            nb_uniq += 1;
        }
    }

    // If all the bytes in the atom are equal and very common, let's penalize
    // it heavily.
    if nb_uniq == 1 && (bitmask[0] || bitmask[0x20] || bitmask[0xCC] || bitmask[0xFF]) {
        quality -= 10 * u32::try_from(atom.len()).unwrap_or(30);
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
        0x00 | 0x20 | 0xCC | 0xFF => 12,
        v if v.is_ascii_lowercase() => 18,
        _ => 20,
    }
}
