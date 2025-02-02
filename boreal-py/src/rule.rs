use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBool, PyDict, PyList, PyString};

use ::boreal::scanner;
use ::boreal::{Metadata, MetadataValue};

/// A matching rule
#[pyclass(frozen, module = "boreal")]
pub struct Rule {
    /// Name of the rule
    #[pyo3(get)]
    identifier: Py<PyString>,

    /// Namespace of the rule
    #[pyo3(get)]
    namespace: Py<PyString>,

    /// List of tags associated with the rule
    #[pyo3(get)]
    tags: Py<PyList>,

    /// Dictionary with metadata associated with the rule
    #[pyo3(get)]
    meta: Py<PyDict>,

    /// Is the rule global
    #[pyo3(get)]
    is_global: bool,

    /// Is the rule private
    #[pyo3(get)]
    is_private: bool,
}

impl Rule {
    pub fn new(
        py: Python,
        scanner: &scanner::Scanner,
        rule: &scanner::RuleDetails,
    ) -> PyResult<Self> {
        Ok(Self {
            identifier: PyString::new(py, rule.name).unbind(),
            namespace: PyString::new(py, rule.namespace.unwrap_or_default()).unbind(),
            meta: rule
                .metadatas
                .iter()
                .map(|m| convert_metadata(py, scanner, m))
                .collect::<Result<Vec<_>, _>>()?
                .into_py_dict(py)?
                .unbind(),
            tags: PyList::new(py, rule.tags)?.unbind(),
            is_global: rule.is_global,
            is_private: rule.is_private,
        })
    }
}

pub fn convert_metadata(
    py: Python,
    scanner: &scanner::Scanner,
    metadata: &Metadata,
) -> Result<(Py<PyString>, Py<PyAny>), PyErr> {
    let name = PyString::new(py, scanner.get_string_symbol(metadata.name));
    let value = match metadata.value {
        // XXX: Yara forces a string conversion here, losing data in the
        // process. Prefer using the right type here.
        // TODO: add a yara compat mode?
        MetadataValue::Bytes(v) => scanner.get_bytes_symbol(v).to_vec().into_pyobject(py)?,
        MetadataValue::Integer(v) => v.into_pyobject(py)?.into_any(),
        MetadataValue::Boolean(v) => PyBool::new(py, v).to_owned().into_any(),
    };
    Ok((name.unbind(), value.unbind()))
}
