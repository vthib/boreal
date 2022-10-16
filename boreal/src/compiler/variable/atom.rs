//! Atom extraction and computation from variable expressions.
//!
//! An atom is a byte string that is contained in the original variable, which additional
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

/// Set of atoms that allows quickly searching for the eventual presence of a variable.
#[derive(Debug, Default)]
pub struct AtomSet {
    atoms: Vec<Atom>,
    rank: u32,
}

impl AtomSet {
    pub fn add_alternate(&mut self, atoms: Vec<Atom>) {
        // this.atoms is one possible set, and the provided atoms are another one.
        // Keep the one with the best rank.
        if self.is_empty() {
            self.atoms = atoms;
            self.rank = atoms_rank(&self.atoms);
        } else {
            let new_rank = atoms_rank(&atoms);
            if new_rank > self.rank {
                self.atoms = atoms;
                self.rank = new_rank;
            }
        }
    }

    pub fn into_literals(self) -> Vec<Vec<u8>> {
        self.atoms
    }

    pub fn get_literals(&self) -> &[Atom] {
        &self.atoms
    }

    fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }
}

type Atom = Vec<u8>;

/// Retrieve the rank of a set of atoms;
fn atoms_rank(atoms: &[Atom]) -> u32 {
    // Get the min rank. This is probably the best solution, it isn't clear if a better one
    // is easy to find.
    atoms.iter().map(atom_rank).min().unwrap_or(0)
}

/// Retrieve the rank of an atom.
fn atom_rank(atom: &Atom) -> u32 {
    // FIXME: we just use the length of the atom for the moment, this is obviously very bad,
    // eg "00 +" can be as long as we want, but is always a bad choice.
    u32::try_from(atom.len()).unwrap_or(u32::MAX)
}
