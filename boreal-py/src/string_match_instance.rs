use std::hash::{DefaultHasher, Hash, Hasher};

use pyo3::prelude::*;

use ::boreal::scanner;

/// Match instance of a YARA string
#[pyclass(frozen, module = "boreal")]
#[derive(Clone)]
pub struct StringMatchInstance {
    /// Offset of the match.
    #[pyo3(get)]
    offset: usize,

    /// Matched data, might have been truncated if too long.
    matched_data: Box<[u8]>,

    /// Length of the entire match.
    #[pyo3(get)]
    matched_length: usize,
    // TODO: missing xor_key
}

impl StringMatchInstance {
    pub fn new(s: scanner::StringMatch) -> Self {
        Self {
            offset: s.offset,
            matched_data: s.data,
            matched_length: s.length,
        }
    }
}

#[pymethods]
impl StringMatchInstance {
    #[getter]
    fn matched_data(&self) -> &[u8] {
        &self.matched_data
    }

    fn __repr__(&self) -> String {
        String::from_utf8_lossy(&self.matched_data).to_string()
    }

    // XXX: the yara impl is to hash on the data only.
    // TODO: when not in yara compat mode, we should probably avoid this...
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.matched_data.hash(&mut hasher);
        hasher.finish()
    }
}
