use std::ops::BitOrAssign;

#[derive(Debug, Clone, Copy, Default)]
/// A bitmap with 256 bits
pub struct Bitmap {
    low: u128,
    high: u128,
}

impl Bitmap {
    const HALF: u8 = 128;

    pub fn new() -> Self {
        Self::default()
    }

    fn mask(bit: u8) -> u128 {
        1u128 << (bit & 127)
    }

    fn get_half(&self, bit: u8) -> u128 {
        if bit < Self::HALF {
            self.low
        } else {
            self.high
        }
    }

    fn get_half_mut(&mut self, bit: u8) -> &mut u128 {
        if bit < Self::HALF {
            &mut self.low
        } else {
            &mut self.high
        }
    }

    #[must_use]
    #[inline(always)]
    pub fn get(&self, bit: u8) -> bool {
        let mask = Self::mask(bit);
        let half = self.get_half(bit);
        half & mask != 0
    }

    #[inline(always)]
    pub fn set(&mut self, bit: u8) {
        let mask = Self::mask(bit);
        let half = self.get_half_mut(bit);
        *half |= mask;
    }

    #[inline(always)]
    pub fn invert(&mut self) {
        self.low = !self.low;
        self.high = !self.high;
    }

    #[inline(always)]
    pub fn count_ones(&self) -> usize {
        (self.low.count_ones() + self.high.count_ones()) as usize
    }

    pub fn iter(&self) -> Iter {
        Iter(*self)
    }
}

/// implement `|=`
impl BitOrAssign for Bitmap {
    fn bitor_assign(&mut self, rhs: Self) {
        self.low |= rhs.low;
        self.high |= rhs.high;
    }
}

pub struct Iter(Bitmap);

impl Iterator for Iter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let (v, offset) = if self.0.low != 0 {
            (&mut self.0.low, 0)
        } else if self.0.high != 0 {
            (&mut self.0.high, 128)
        } else {
            return None;
        };

        // Safety: this value is contained in [0; 127] so it always fits in a u8.
        let t: u8 = v.trailing_zeros().try_into().unwrap();
        *v &= !(1 << t);
        Some(offset + t)
    }
}

#[cfg(test)]
mod test {
    use super::Bitmap;

    #[test]

    fn test_bitmap() {
        let mut bitmap = Bitmap::new();

        let indexes = vec![0, 10, 17, 120, 127, 128, 129, 200, 255];
        for i in &indexes {
            bitmap.set(*i);
            assert!(bitmap.get(*i));
        }

        for i in 0..=255 {
            assert_eq!(bitmap.get(i), indexes.contains(&i));
        }
        assert_eq!(bitmap.count_ones(), indexes.len());

        let value = bitmap.iter().collect::<Vec<_>>();
        assert_eq!(value, indexes);

        bitmap.invert();
        for i in 0..=255 {
            assert_eq!(bitmap.get(i), !indexes.contains(&i));
        }
    }

    #[test]
    fn test_bitmap_all() {
        let mut bitmap = Bitmap::new();
        assert_eq!(bitmap.iter().count(), 0);
        bitmap.invert();
        assert_eq!(bitmap.iter().count(), 256);
    }

    #[test]
    fn test_bitmap_or_assign() {
        let mut bitmap = Bitmap::new();
        bitmap.set(10);
        bitmap.set(30);

        let mut bitmap2 = Bitmap::new();
        bitmap2.set(20);
        bitmap2 |= bitmap;

        assert_eq!(vec![10, 20, 30], bitmap2.iter().collect::<Vec<_>>());
    }
}
