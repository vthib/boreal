/// Bytes intern pool.
#[derive(Default, Debug)]
pub(crate) struct BytesPool {
    buffer: Vec<u8>,
}

/// Symbol for a bytes string stored in a bytes intern pool.
#[derive(Copy, Clone, Debug)]
pub struct BytesSymbol {
    from: usize,
    to: usize,
}

/// Symbol for a string stored in a bytes intern pool.
#[derive(Copy, Clone, Debug)]
pub struct StringSymbol {
    from: usize,
    to: usize,
}

impl BytesPool {
    /// Insert bytes into the bytes pool.
    ///
    /// The returned symbol can then be used to retrieve those bytes from the pool.
    pub(crate) fn insert(&mut self, v: &[u8]) -> BytesSymbol {
        let from = self.buffer.len();
        self.buffer.extend(v);

        BytesSymbol {
            from,
            to: self.buffer.len(),
        }
    }

    /// Insert a string into the bytes pool.
    ///
    /// The returned symbol can then be used to retrieve the string from the pool.
    pub(crate) fn insert_str(&mut self, v: &str) -> StringSymbol {
        let from = self.buffer.len();
        self.buffer.extend(v.as_bytes());

        StringSymbol {
            from,
            to: self.buffer.len(),
        }
    }

    /// Get a byte string from the pool
    pub(crate) fn get(&self, symbol: BytesSymbol) -> &[u8] {
        &self.buffer[symbol.from..symbol.to]
    }

    /// Get a string from the pool
    pub(crate) fn get_str(&self, symbol: StringSymbol) -> &str {
        // Safety:
        // - A StringSymbol can only be constructed from `insert_str`
        // - Once a symbol is created, it is guaranteed that the indexes in the symbol
        //   will always refer to the same bytes (the buffer can only grow).
        // It is thus safe to rebuild the string from the stored bytes.
        unsafe { std::str::from_utf8_unchecked(&self.buffer[symbol.from..symbol.to]) }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(BytesPool::default());
        test_type_traits(BytesSymbol { from: 0, to: 0 });
        test_type_traits(StringSymbol { from: 0, to: 0 });
    }
}
