use std::hash::{DefaultHasher, Hash, Hasher};

use pyo3::prelude::*;

use ::boreal::scanner;

use crate::string_match_instance::StringMatchInstance;

/// List of match instances of a YARA string
#[pyclass(frozen, module = "boreal")]
#[derive(Clone)]
pub struct StringMatches {
    /// Name of the matching string.
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
            // FIXME
            identifier: format!("${}", &s.name),
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

    // TODO: missing is_xor

    fn __repr__(&self) -> &str {
        &self.identifier
    }

    // XXX: the yara impl is to hash on the identifier only.
    // TODO: when not in yara compat mode, we should probably avoid this...
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.identifier.hash(&mut hasher);
        hasher.finish()
    }
}
