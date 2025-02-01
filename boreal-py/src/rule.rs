use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyList};

use ::boreal::scanner;
use ::boreal::{Metadata, MetadataValue};

/// A matching rule
#[pyclass(frozen)]
pub struct Rule {
    /// Name of the rule
    #[pyo3(get)]
    identifier: String,

    /// Namespace of the rule
    #[pyo3(get)]
    namespace: String,

    /// List of tags associated with the rule
    #[pyo3(get)]
    tags: Py<PyList>,

    /// Dictionary with metadata associated with the rule
    #[pyo3(get)]
    meta: HashMap<String, Py<PyAny>>,

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
            identifier: rule.name.to_owned(),
            namespace: rule.namespace.unwrap_or_default().to_string(),
            meta: rule
                .metadatas
                .iter()
                .map(|m| convert_metadata(py, scanner, m))
                .collect::<Result<_, _>>()?,
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
) -> Result<(String, Py<PyAny>), PyErr> {
    let name = scanner.get_string_symbol(metadata.name).to_string();
    let value = match metadata.value {
        // XXX: Yara forces a string conversion here, losing data in the
        // process. Prefer using the right type here.
        // TODO: add a yara compat mode?
        MetadataValue::Bytes(v) => scanner.get_bytes_symbol(v).to_vec().into_pyobject(py)?,
        MetadataValue::Integer(v) => v.into_pyobject(py)?.into_any(),
        MetadataValue::Boolean(v) => PyBool::new(py, v).to_owned().into_any(),
    };
    Ok((name, value.unbind()))
}
