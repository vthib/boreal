use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::hash::{BuildHasherDefault, Hasher};

use super::AtomMatch;
use crate::atoms::Atom;
use crate::scanner::ScanError;

#[derive(Debug)]
pub struct HashScanner {
    width1: Width1Scanner,
    width2: FixedWidthScanner,
    width3: FixedWidthScanner,
    width4: FixedWidthScanner,

    // 64k array indicating for a u16 value, which widths
    // contains atoms that has this u16 value as LSB.
    //
    // This gives a very cheap way to skip some width scanner
    // on non matching u32 values.
    widths_per_hw: Box<[u8; 65536]>,

    // List of patterns that match on every byte
    empty_patterns: Vec<u32>,
}

impl HashScanner {
    pub fn new(atoms: &[Atom]) -> Self {
        let mut widths_per_hw: Box<[u8; 65536]> = vec![0_u8; 65536]
            .into_boxed_slice()
            .try_into()
            // Safety: the size matches, this cannot fail
            .unwrap();
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
                    widths_per_hw[(atom_u32 & 0xFF_FF) as usize] |= 0b001;
                    atoms2.push((index, atom_u32));
                }
                [a, b, c] => {
                    let atom_u32 = u32::from_le_bytes([*a, *b, *c, 0]);
                    widths_per_hw[(atom_u32 & 0xFF_FF) as usize] |= 0b010;
                    atoms3.push((index, atom_u32));
                }
                [a, b, c, d] => {
                    let atom_u32 = u32::from_le_bytes([*a, *b, *c, *d]);
                    widths_per_hw[(atom_u32 & 0xFF_FF) as usize] |= 0b100;
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
            widths_per_hw,
            empty_patterns,
        }
    }

    pub fn scan<F>(&self, mem: &[u8], mut on_match: F) -> Result<(), ScanError>
    where
        F: FnMut(AtomMatch) -> Result<(), ScanError>,
    {
        let block_end = mem.len().saturating_sub(3);

        // The scan idea is pretty simple, and can be thought of this way:
        //
        // ```
        // for index in 0..mem.len() {
        //     let atom = u32::from(mem[index..(index+4)]);
        //     find_width1_atoms(atom & 0xFF);
        //     find_width2_atoms(atom & 0xFF_FF);
        //     find_width3_atoms(atom & 0xFF_FF_FF);
        //     find_width4_atoms(atom);
        // }
        // ```
        //
        // This is however reworked to make this iteration as fast as possible
        // by splitting into two passes. The first pass builds a u64 value where
        // every bit indicating if there are atoms that are prefixed by the u16
        // value at the given index. The second pass iterates on this u64 value
        // to probe for atoms.

        // Iterate in steps of 64 bytes
        let mut index = 0;
        while index < block_end {
            let n = (block_end - index).min(64);
            let block = &mem[index..=index + n];

            // First pass: compute a u64 value where a bit is set to 1 if the
            // u16 prefix at this given offset is the prefix of existing atoms.
            //
            // This is branch free and computed from values (hopefully) kept
            // in cache.
            let mut candidates = 0u64;
            for i in 0..n {
                // Is there atoms of width 1 that starts with the given prefix.
                let has_width_1 = u64::from(self.width1.present[block[i] as usize]);

                // Is there atoms of other widths that starts with the given prefix.
                let prefix = u16::from_le_bytes([block[i], block[i + 1]]);
                let has_longer_widths = u64::from(self.widths_per_hw[prefix as usize] != 0);

                // Store 1 if there are atoms with this prefix.
                candidates |= (has_width_1 | has_longer_widths) << i;
            }

            // Second pass: for every set bit, probe the different tables.
            while candidates != 0 {
                let pos = index + candidates.trailing_zeros() as usize;
                // Unset the trailing "1" bit.
                candidates &= candidates - 1;

                let atom = u32::from_le_bytes([mem[pos], mem[pos + 1], mem[pos + 2], mem[pos + 3]]);

                self.width1.probe(atom, pos, 1, &mut on_match)?;

                let widths = self.widths_per_hw[(atom & 0xFF_FF) as usize];
                if widths & 0b001 != 0 {
                    self.width2.probe(atom, pos, 2, &mut on_match)?;
                }
                if widths & 0b010 != 0 {
                    self.width3.probe(atom, pos, 3, &mut on_match)?;
                }
                if widths & 0b100 != 0 {
                    self.width4.probe(atom, pos, 4, &mut on_match)?;
                }
            }

            index += n;
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
    filter: BloomFilter,

    // Mask to apply to get the given width
    atom_mask: u32,

    // Map from key to pattern indices
    map: FastMap<Pattern>,

    patterns: Box<[PatternNode]>,
}

impl FixedWidthScanner {
    fn new(atoms: &[(u32, u32)], atom_mask: u32) -> Self {
        let mut filter = BloomFilter::new(atoms.len());
        let mut map = new_fast_map(atoms.len());
        let mut patterns = PatternsBuilder::default();

        for (pattern_index, atom) in atoms {
            let key = *atom & atom_mask;
            filter.set(key);
            match map.entry(key) {
                Entry::Vacant(v) => {
                    let _r = v.insert(Pattern::new_inline(*pattern_index));
                }
                Entry::Occupied(mut o) => {
                    let existing_pattern = *o.get();

                    let previous_index = if existing_pattern.is_inline() {
                        patterns.add(PatternNode::END, existing_pattern.get())
                    } else {
                        existing_pattern.get()
                    };
                    let i = patterns.add(previous_index, *pattern_index);
                    *o.get_mut() = Pattern::new(i);
                }
            }
        }

        Self {
            filter,
            atom_mask,
            map,
            patterns: patterns.finish(),
        }
    }

    // Inline this to avoid a function call on the fast pass
    #[inline(always)]
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

        if !self.filter.contains(key) {
            return Ok(());
        }

        // Keep this out of the inlined function: this is
        // the slow path.
        self.probe_map(key, start, width, on_match)
    }

    fn probe_map<F>(
        &self,
        key: u32,
        start: usize,
        width: usize,
        on_match: &mut F,
    ) -> Result<(), ScanError>
    where
        F: FnMut(AtomMatch) -> Result<(), ScanError>,
    {
        if let Some(p) = self.map.get(&key).copied() {
            if p.is_inline() {
                on_match(AtomMatch {
                    pattern: p.get(),
                    start,
                    end: start + width,
                })?;
                return Ok(());
            }

            let mut pi = p.get();
            while pi != PatternNode::END {
                let PatternNode { pattern, next } = self.patterns[pi as usize];

                on_match(AtomMatch {
                    pattern,
                    start,
                    end: start + width,
                })?;

                pi = next;
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

    #[inline(always)]
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

        self.probe_map(key, start, width, on_match)
    }

    fn probe_map<F>(
        &self,
        key: usize,
        start: usize,
        width: usize,
        on_match: &mut F,
    ) -> Result<(), ScanError>
    where
        F: FnMut(AtomMatch) -> Result<(), ScanError>,
    {
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

#[derive(Debug)]
struct BloomFilter {
    bitmap: Box<[u64]>,
    log2_size: u32,
}

impl BloomFilter {
    fn new(size: usize) -> Self {
        let log2_size = size
            .saturating_mul(128)
            // round up to ensure the trailing bits are addressable
            .next_power_of_two()
            // log2
            .trailing_zeros()
            // never below 65536 bits (8 KB), and never above 2^24 bits (2 MB)
            .clamp(16, 24);

        let nb_bits = 1 << (log2_size as usize);

        Self {
            bitmap: vec![0u64; nb_bits / 64].into_boxed_slice(),
            log2_size,
        }
    }

    fn set(&mut self, key: u32) {
        let (bucket, mask) = self.address(key);
        self.bitmap[bucket] |= mask;
    }

    fn contains(&self, key: u32) -> bool {
        let (bucket, mask) = self.address(key);
        (self.bitmap[bucket] & mask) != 0
    }

    fn address(&self, key: u32) -> (usize, u64) {
        // Keep the log2_size MSB bits from the hash
        let h = hash(key) >> (32 - self.log2_size);
        ((h / 64) as usize, 1 << (h % 64))
    }
}

#[inline(always)]
fn hash(key: u32) -> u32 {
    key.wrapping_mul(0x9E37_79B1)
}

#[derive(Copy, Clone, Debug)]
struct Pattern(u32);

impl Pattern {
    const INLINE_BIT: u32 = 1 << 31;

    fn new_inline(pattern: u32) -> Self {
        assert_eq!(pattern & Self::INLINE_BIT, 0);
        Self(pattern | Self::INLINE_BIT)
    }

    fn new(pattern: u32) -> Self {
        assert_eq!(pattern & Self::INLINE_BIT, 0);
        Self(pattern)
    }

    fn is_inline(self) -> bool {
        self.0 & (1 << 31) != 0
    }

    fn get(self) -> u32 {
        if self.is_inline() {
            self.0 & !Self::INLINE_BIT
        } else {
            self.0
        }
    }
}

#[derive(Default)]
struct PatternsBuilder {
    data: Vec<PatternNode>,
}

#[derive(Copy, Clone, Debug)]
struct PatternNode {
    pattern: u32,
    next: u32,
}

impl PatternNode {
    const END: u32 = u32::MAX;
}

impl PatternsBuilder {
    fn add(&mut self, next: u32, pattern: u32) -> u32 {
        self.data.push(PatternNode { pattern, next });
        #[allow(clippy::cast_possible_truncation)]
        let res = (self.data.len() - 1) as u32;
        res
    }

    fn finish(self) -> Box<[PatternNode]> {
        self.data.into_boxed_slice()
    }
}

type FastMap<V> = HashMap<u32, V, BuildHasherDefault<FastHasher>>;

fn new_fast_map<V>(capacity: usize) -> FastMap<V> {
    FastMap::with_capacity_and_hasher(capacity, BuildHasherDefault::default())
}

/// Hashes an atom key with a single golden ratio multiply.
///
/// The default hasher is `SipHash`, which is chosen to resist collisions forged through a
/// public API. This is useless here and we need to make this hash as fast as possible.
#[derive(Default)]
struct FastHasher(u64);

impl Hasher for FastHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _bytes: &[u8]) {
        // This hasher is only used with u32 keys, so only write_u32 is used.
        unreachable!();
    }

    fn write_u32(&mut self, v: u32) {
        self.0 = u64::from(v).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}
