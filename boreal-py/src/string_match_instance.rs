use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::Ordering;

use pyo3::prelude::*;

use ::boreal::scanner;

use crate::YARA_PYTHON_COMPATIBILITY;

/// Details about a single match instance of a string.
#[pyclass(frozen, module = "boreal")]
#[derive(Clone, Hash)]
pub struct StringMatchInstance {
    /// Offset of the match.
    #[pyo3(get)]
    offset: usize,

    matched_data: Box<[u8]>,

    /// Length of the entire match before truncation.
    ///
    /// This is the actual length of the matched data, which can be different
    /// from the length of the `matched_data` field, since this field can
    /// be truncated.
    #[pyo3(get)]
    matched_length: usize,

    /// Xor key used in the match.
    #[pyo3(get)]
    xor_key: u8,
}

impl StringMatchInstance {
    pub fn new(s: scanner::StringMatch) -> Self {
        Self {
            offset: s.offset,
            matched_data: s.data,
            matched_length: s.length,
            xor_key: s.xor_key,
        }
    }
}

#[pymethods]
impl StringMatchInstance {
    /// The matched data.
    ///
    /// If the match exceeded the `max_matched_data` limit specified in the
    /// `set_config` function, the data is truncated.
    #[getter]
    fn matched_data(&self) -> &[u8] {
        &self.matched_data
    }

    /// The matched data after application of the xor operation.
    ///
    /// If the string had a xor modifier, this method can be used to
    /// get the matched data after application of the xor key.
    fn plaintext(&self) -> Vec<u8> {
        self.matched_data.iter().map(|b| b ^ self.xor_key).collect()
    }

    fn __repr__(&self) -> String {
        String::from_utf8_lossy(&self.matched_data).to_string()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        // XXX: the yara impl is to hash on the data only, which isn't very good to uniquely
        // identify a match. Instead, hash on the whole object.
        if YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst) {
            self.matched_data.hash(&mut hasher);
        } else {
            self.hash(&mut hasher);
        }
        hasher.finish()
    }
}
