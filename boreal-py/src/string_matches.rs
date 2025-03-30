use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::Ordering;

use pyo3::prelude::*;

use ::boreal::scanner;

use crate::{string_match_instance::StringMatchInstance, YARA_PYTHON_COMPATIBILITY};

/// Details about the matches of a string.
#[pyclass(frozen, module = "boreal")]
#[derive(Clone, Hash)]
pub struct StringMatches {
    /// Name of the string.
    #[pyo3(get)]
    identifier: String,

    /// List of matches for the string.
    #[pyo3(get)]
    instances: Vec<StringMatchInstance>,

    has_xor_modifier: bool,
}

impl StringMatches {
    pub fn new(s: scanner::StringMatches) -> Self {
        Self {
            identifier: if YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst) {
                format!("${}", &s.name)
            } else {
                s.name.to_string()
            },
            instances: s
                .matches
                .into_iter()
                .map(StringMatchInstance::new)
                .collect(),
            has_xor_modifier: s.has_xor_modifier,
        }
    }
}

#[pymethods]
impl StringMatches {
    /// Does the string have the xor modifier.
    fn is_xor(&self) -> bool {
        self.has_xor_modifier
    }

    fn __repr__(&self) -> &str {
        &self.identifier
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        // XXX: the yara impl is to hash the string name only, which isn't very good to
        // uniquely identify matches. Instead, hash on the whole object.
        if YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst) {
            self.identifier.hash(&mut hasher);
        } else {
            self.hash(&mut hasher);
        }
        hasher.finish()
    }
}
