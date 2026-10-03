use std::collections::HashMap;

use super::AtomMatch;
use crate::atoms::Atom;
use crate::scanner::ScanError;

#[derive(Debug)]
pub struct HashScanner {
    width1: Width1Scanner,
    width2: FixedWidthScanner,
    width3: FixedWidthScanner,
    width4: FixedWidthScanner,

    // List of patterns that match on every byte
    empty_patterns: Vec<u32>,
}

impl HashScanner {
    pub fn new(atoms: &[Atom]) -> Self {
        let mut atoms1 = Vec::new();
        let mut atoms2 = Vec::new();
        let mut atoms3 = Vec::new();
        let mut atoms4 = Vec::new();
        let mut empty_patterns = Vec::new();

        for (index, atom) in atoms.iter().enumerate() {
            let index = u32::try_from(index).unwrap();

            match atom.as_ref() {
                [] => empty_patterns.push(index),
                [a] => {
                    atoms1.push((index, *a));
                }
                [a, b] => {
                    let atom_u32 = u32::from_le_bytes([*a, *b, 0, 0]);
                    atoms2.push((index, atom_u32));
                }
                [a, b, c] => {
                    let atom_u32 = u32::from_le_bytes([*a, *b, *c, 0]);
                    atoms3.push((index, atom_u32));
                }
                [a, b, c, d] => {
                    let atom_u32 = u32::from_le_bytes([*a, *b, *c, *d]);
                    atoms4.push((index, atom_u32));
                }
                _ => unreachable!(),
            }
        }

        Self {
            width1: Width1Scanner::new(&atoms1),
            width2: FixedWidthScanner::new(&atoms2, 0xFF_FF),
            width3: FixedWidthScanner::new(&atoms3, 0xFF_FF_FF),
            width4: FixedWidthScanner::new(&atoms4, 0xFF_FF_FF_FF),
            empty_patterns,
        }
    }

    pub fn scan<F>(&self, mem: &[u8], mut on_match: F) -> Result<(), ScanError>
    where
        F: FnMut(AtomMatch) -> Result<(), ScanError>,
    {
        for (index, slice) in mem.windows(4).enumerate() {
            let atom = u32::from_le_bytes(slice.try_into().unwrap());
            self.width1.probe(atom, index, 1, &mut on_match)?;
            self.width2.probe(atom, index, 2, &mut on_match)?;
            self.width3.probe(atom, index, 3, &mut on_match)?;
            self.width4.probe(atom, index, 4, &mut on_match)?;
        }

        let len = mem.len();
        if len >= 3 {
            let atom = u32::from_le_bytes([mem[len - 3], mem[len - 2], mem[len - 1], 0]);
            self.width1.probe(atom, len - 3, 1, &mut on_match)?;
            self.width2.probe(atom, len - 3, 2, &mut on_match)?;
            self.width3.probe(atom, len - 3, 3, &mut on_match)?;
        }
        if len >= 2 {
            let atom = u32::from_le_bytes([mem[len - 2], mem[len - 1], 0, 0]);
            self.width1.probe(atom, len - 2, 1, &mut on_match)?;
            self.width2.probe(atom, len - 2, 2, &mut on_match)?;
        }
        if len >= 1 {
            let atom = u32::from_le_bytes([mem[len - 1], 0, 0, 0]);
            self.width1.probe(atom, len - 1, 1, &mut on_match)?;
        }

        if !self.empty_patterns.is_empty() {
            for i in 0..mem.len() {
                for pattern in &self.empty_patterns {
                    on_match(AtomMatch {
                        pattern: *pattern,
                        start: i,
                        end: i,
                    })?;
                }
            }
        }

        Ok(())
    }
}

/// Scanner for atoms of a given width
#[derive(Debug)]
struct FixedWidthScanner {
    // Mask to apply to get the given width
    atom_mask: u32,

    // Map from key to pattern indices
    map: HashMap<u32, Vec<u32>>,
}

impl FixedWidthScanner {
    fn new(atoms: &[(u32, u32)], atom_mask: u32) -> Self {
        let mut map: HashMap<u32, Vec<u32>> = HashMap::new();

        for (pattern_index, atom) in atoms {
            map.entry(*atom & atom_mask)
                .or_default()
                .push(*pattern_index);
        }

        Self { atom_mask, map }
    }

    fn probe<F>(
        &self,
        atom: u32,
        start: usize,
        width: usize,
        on_match: &mut F,
    ) -> Result<(), ScanError>
    where
        F: FnMut(AtomMatch) -> Result<(), ScanError>,
    {
        let key = atom & self.atom_mask;

        if let Some(patterns) = self.map.get(&key) {
            for pattern in patterns {
                on_match(AtomMatch {
                    pattern: *pattern,
                    start,
                    end: start + width,
                })?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Width1Scanner {
    present: [bool; 256],
    map: [Vec<u32>; 256],
}

impl Width1Scanner {
    fn new(atoms: &[(u32, u8)]) -> Self {
        let mut map = [const { Vec::new() }; 256];
        let mut present = [false; 256];

        for (pattern_index, atom) in atoms {
            let key = usize::from(*atom);

            present[key] = true;
            map[key].push(*pattern_index);
        }

        Self { present, map }
    }

    fn probe<F>(
        &self,
        atom: u32,
        start: usize,
        width: usize,
        on_match: &mut F,
    ) -> Result<(), ScanError>
    where
        F: FnMut(AtomMatch) -> Result<(), ScanError>,
    {
        let key = (atom & 0xFF) as usize;

        if !self.present[key] {
            return Ok(());
        }

        for pattern in &self.map[key] {
            on_match(AtomMatch {
                pattern: *pattern,
                start,
                end: start + width,
            })?;
        }

        Ok(())
    }
}
