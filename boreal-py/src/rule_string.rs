use pyo3::{prelude::*, types::PyString};

use ::boreal::scanner::StringIdentifier;

/// Details about a string.
// FIXME: this is a namedtuple in yara
#[pyclass(frozen, module = "boreal")]
pub struct RuleString {
    /// Namespace of the rule containing the string.
    #[pyo3(get)]
    namespace: Py<PyString>,

    /// Name of the rule containing the string.
    #[pyo3(get)]
    rule: Py<PyString>,

    /// Name of the string.
    #[pyo3(get)]
    string: Py<PyString>,
}

impl RuleString {
    pub fn new(py: Python, id: &StringIdentifier) -> Self {
        Self {
            namespace: PyString::new(py, id.rule_namespace).unbind(),
            rule: PyString::new(py, id.rule_name).unbind(),
            string: PyString::new(py, &format!("${}", id.string_name)).unbind(),
        }
    }
}
