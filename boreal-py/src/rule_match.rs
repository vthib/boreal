use std::hash::{DefaultHasher, Hash, Hasher};

use pyo3::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use ::boreal::scanner;

use crate::rule::convert_metadatas;
use crate::string_matches::StringMatches;

/// Details about a matching rule.
#[pyclass(frozen, module = "boreal")]
pub struct Match {
    /// Name of the matching rule
    #[pyo3(get)]
    pub(crate) rule: String,

    /// Namespace of the matching rule
    #[pyo3(get)]
    pub(crate) namespace: String,

    /// List of tags associated to the rule
    #[pyo3(get)]
    pub(crate) tags: Py<PyList>,

    /// Dictionary with metadata associated to the rule
    #[pyo3(get)]
    pub(crate) meta: Py<PyDict>,

    /// Details about the string matches of the rule.
    #[pyo3(get)]
    pub(crate) strings: Py<PyList>,
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
        rule: scanner::EvaluatedRule,
        allow_duplicate_metadata: bool,
    ) -> Result<Self, PyErr> {
        Ok(Self {
            rule: rule.name.to_string(),
            namespace: rule.namespace.to_string(),
            meta: convert_metadatas(py, scanner, rule.metadatas, allow_duplicate_metadata)?
                .unbind(),
            tags: PyList::new(py, rule.tags)?.unbind(),
            strings: PyList::new(py, rule.matches.into_iter().map(StringMatches::new))?.unbind(),
        })
    }
}
