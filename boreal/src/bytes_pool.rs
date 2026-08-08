/// Bytes intern pool
///
/// This module defines the [`BytesPool`] and its builder type [`BytesPoolBuilder`].
///
/// This object is used to reduce the memory consumption of compiled rules, by
/// storing all bytes & strings literals used in rules (excluding those from variables,
/// or "strings" in YARA terms, but that is just confusing). This is mainly used
/// for metadata keys and values, but also for literals used in conditions.
///
/// Memory consumption is reduced thanks to two simple points.
///
/// - A single allocation is used, reduce memory fragmentation and allocation overheads.
/// - Added bytes are deduplicated. This is especially useful for metadata key names for
///   example, which tends to always be the same ones in a set of rules.
use std::collections::HashMap;

/// Bytes intern pool.
///
/// This object is used to store bytes in a single place to reduce memory consumption.
///
/// The implementation is extremely naive:
///
/// - A single Vec is used to stored the bytes, every added bytes are appended to the vec.
/// - Handles (or symbols as named here) are simply the offsets into the vec.
///
/// Some other implementations could be attempted to improve memory consumption further.
/// For example, by adding a second vec to map an index to the (from, to) pair, so that the
/// symbol can be a single usize.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BytesPool {
    pool: Box<[u8]>,
}

/// Symbol for a bytes string stored in a bytes intern pool.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BytesSymbol {
    from: u32,
    to: u32,
}

/// Symbol for a string stored in a bytes intern pool.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StringSymbol {
    from: u32,
    to: u32,
}

impl BytesPool {
    /// Get a byte string from the pool
    pub(crate) fn get(&self, symbol: BytesSymbol) -> &[u8] {
        let (from, to) = (symbol.from as usize, symbol.to as usize);

        &self.pool[from..to]
    }

    /// Get a string from the pool
    pub(crate) fn get_str(&self, symbol: StringSymbol) -> &str {
        let (from, to) = (symbol.from as usize, symbol.to as usize);

        // Safety:
        // - A StringSymbol can only be constructed from `insert_str`
        // - Once a symbol is created, it is guaranteed that the indexes in the symbol
        //   will always refer to the same bytes (the pool can only grow).
        // It is thus safe to rebuild the string from the stored bytes.
        unsafe { std::str::from_utf8_unchecked(&self.pool[from..to]) }
    }
}

#[inline(always)]
fn convert_to_u32(v: usize) -> u32 {
    // Convert by saturating to u32::MAX.
    //
    // This makes the symbol unusable, but the fact the pool
    // is full will be detected afterwards to make the compilation fail.
    // This keeps the code simple rather than forcing every caller of
    // this function to handle the error case.
    v.try_into().ok().unwrap_or(u32::MAX)
}

/// A builder for the [`BytesPool`] object.
///
/// This builder will deduplicate bytes added in the pool to reduce
/// the memory usage of the final pool.
#[derive(Default, Debug)]
pub(crate) struct BytesPoolBuilder {
    /// The pool being constructed.
    buffer: Vec<u8>,
    /// Map of bytes symbols already added in the pool.
    bytes_map: HashMap<Vec<u8>, BytesSymbol>,
    /// Map of string symbols already added in the pool.
    str_map: HashMap<String, StringSymbol>,

    /// Size limit for the pool.
    ///
    /// Only used in testing
    pub(crate) limit: Option<usize>,
}

impl BytesPoolBuilder {
    /// Insert bytes into the bytes pool.
    ///
    /// The returned symbol can then be used to retrieve those bytes from the pool.
    /// If the byte string was already added, the existing symbol will be returned.
    pub(crate) fn insert(&mut self, v: &[u8]) -> BytesSymbol {
        match self.bytes_map.get(v) {
            Some(v) => *v,
            None => {
                let from = self.buffer.len();
                self.buffer.extend(v);
                let symbol = BytesSymbol {
                    from: convert_to_u32(from),
                    to: convert_to_u32(self.buffer.len()),
                };

                let _r = self.bytes_map.insert(v.to_vec(), symbol);

                symbol
            }
        }
    }

    /// Insert a string into the bytes pool.
    ///
    /// The returned symbol can then be used to retrieve the string from the pool.
    /// If the string was already added, the existing symbol will be returned.
    pub(crate) fn insert_str(&mut self, v: &str) -> StringSymbol {
        match self.str_map.get(v) {
            Some(v) => *v,
            None => {
                let from = self.buffer.len();
                self.buffer.extend(v.as_bytes());

                let symbol = StringSymbol {
                    from: convert_to_u32(from),
                    to: convert_to_u32(self.buffer.len()),
                };

                let _r = self.str_map.insert(v.to_owned(), symbol);

                symbol
            }
        }
    }

    /// Build the final bytes pool object.
    pub(crate) fn into_pool(self) -> BytesPool {
        BytesPool {
            pool: self.buffer.into_boxed_slice(),
        }
    }

    /// Is the pool full.
    pub(crate) fn is_full(&self) -> bool {
        let limit = self.limit.unwrap_or(u32::MAX as usize);

        self.buffer.len() >= limit
    }
}

#[cfg(feature = "serialize")]
mod wire {
    use std::io;

    use crate::wire::{Deserialize, Serialize};

    use super::{BytesPool, BytesSymbol, StringSymbol};

    impl Serialize for BytesPool {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.pool.serialize(writer)
        }
    }

    impl Deserialize for BytesPool {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let pool = <Vec<u8>>::deserialize_reader(reader)?;

            Ok(Self {
                pool: pool.into_boxed_slice(),
            })
        }
    }

    impl Serialize for StringSymbol {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.from.serialize(writer)?;
            self.to.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for StringSymbol {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let from = u32::deserialize_reader(reader)?;
            let to = u32::deserialize_reader(reader)?;
            Ok(Self { from, to })
        }
    }

    impl Serialize for BytesSymbol {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            self.from.serialize(writer)?;
            self.to.serialize(writer)?;
            Ok(())
        }
    }

    impl Deserialize for BytesSymbol {
        fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
            let from = u32::deserialize_reader(reader)?;
            let to = u32::deserialize_reader(reader)?;
            Ok(Self { from, to })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::wire::tests::test_round_trip;

        #[test]
        fn test_wire_bytes_pool() {
            test_round_trip(
                &BytesPool {
                    pool: b"abcedf".to_vec().into_boxed_slice(),
                },
                &[2, 6],
            );
            test_round_trip(&BytesPool { pool: Box::new([]) }, &[2]);

            test_round_trip(&StringSymbol { from: 23, to: 2 }, &[0, 4]);
            test_round_trip(&BytesSymbol { from: 3, to: 8 }, &[0, 4]);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{test_type_traits, test_type_traits_non_clonable};

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(BytesPoolBuilder::default());
        test_type_traits_non_clonable(BytesPoolBuilder::default().into_pool());
        test_type_traits(BytesSymbol { from: 0, to: 0 });
        test_type_traits(StringSymbol { from: 0, to: 0 });
    }
}
