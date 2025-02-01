use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use pyo3::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::PyList;

use ::boreal::scanner;

use crate::rule::convert_metadata;
use crate::string_matches::StringMatches;

/// A matching rule
#[pyclass(frozen)]
pub struct Match {
    /// Name of the matching rule
    #[pyo3(get)]
    rule: String,

    /// Namespace of the matching rule
    #[pyo3(get)]
    namespace: String,

    /// List of tags associated to the rule
    #[pyo3(get)]
    tags: Py<PyList>,

    /// Dictionary with metadata associated to the rule
    #[pyo3(get)]
    meta: HashMap<String, Py<PyAny>>,

    /// Tuple with offsets and strings that matched the file
    #[pyo3(get)]
    strings: Vec<StringMatches>,
}

#[pymethods]
impl Match {
    fn __repr__(&self) -> &str {
        &self.rule
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> bool {
        let a = (&self.rule, &self.namespace);
        let b = (&other.rule, &other.namespace);
        match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            CompareOp::Le => a <= b,
            CompareOp::Lt => a < b,
            CompareOp::Gt => a > b,
            CompareOp::Ge => a >= b,
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.rule.hash(&mut hasher);
        self.namespace.hash(&mut hasher);
        hasher.finish()
    }
}

impl Match {
    pub fn new(
        py: Python,
        scanner: &scanner::Scanner,
        rule: scanner::MatchedRule,
    ) -> Result<Self, PyErr> {
        Ok(Self {
            rule: rule.name.to_string(),
            namespace: rule.namespace.unwrap_or_default().to_string(),
            meta: rule
                .metadatas
                .iter()
                .map(|m| convert_metadata(py, scanner, m))
                .collect::<Result<_, _>>()?,
            tags: PyList::new(py, rule.tags)?.unbind(),
            strings: rule.matches.into_iter().map(StringMatches::new).collect(),
        })
    }
}
