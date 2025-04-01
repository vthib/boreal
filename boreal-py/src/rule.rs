use std::collections::HashMap;
use std::sync::atomic::Ordering;

use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBool, PyDict, PyList, PyString};

use ::boreal::scanner;
use ::boreal::{Metadata, MetadataValue};

use crate::YARA_PYTHON_COMPATIBILITY;

/// Details about a rule contained in the `Scanner` object.
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
            namespace: PyString::new(py, rule.namespace).unbind(),
            meta: convert_metadatas(py, scanner, rule.metadatas, false)?.unbind(),
            tags: PyList::new(py, rule.tags)?.unbind(),
            is_global: rule.is_global,
            is_private: rule.is_private,
        })
    }
}

pub fn convert_metadatas<'py>(
    py: Python<'py>,
    scanner: &scanner::Scanner,
    metadatas: &[Metadata],
    allow_duplicate_metadata: bool,
) -> PyResult<Bound<'py, PyDict>> {
    if allow_duplicate_metadata {
        let mut res: HashMap<&str, Bound<'_, PyList>> = HashMap::new();

        for m in metadatas {
            let name = scanner.get_string_symbol(m.name);
            let value = convert_metadata_value(py, scanner, m.value)?;
            res.entry(name)
                .or_insert_with(|| PyList::empty(py))
                .append(value)?;
        }
        res.into_py_dict(py)
    } else {
        let mut res: HashMap<&str, Bound<'_, PyAny>> = HashMap::new();

        for m in metadatas {
            let name = scanner.get_string_symbol(m.name);
            let value = convert_metadata_value(py, scanner, m.value)?;
            let _r = res.insert(name, value);
        }

        res.into_py_dict(py)
    }
}

fn convert_metadata_value<'py>(
    py: Python<'py>,
    scanner: &scanner::Scanner,
    value: MetadataValue,
) -> Result<Bound<'py, PyAny>, PyErr> {
    Ok(match value {
        MetadataValue::Bytes(v) => {
            let bytes = scanner.get_bytes_symbol(v).to_vec().into_pyobject(py)?;
            // XXX: Yara forces a string conversion here, losing data in the
            // process. Prefer using the right type here.
            if YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst) {
                PyString::from_object(&bytes, "utf-8", "ignore")?.into_any()
            } else {
                bytes
            }
        }
        MetadataValue::Integer(v) => v.into_pyobject(py)?.into_any(),
        MetadataValue::Boolean(v) => PyBool::new(py, v).to_owned().into_any(),
    })
}
