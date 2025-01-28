//! Python bindings for the boreal library.
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyList, PyString};

use ::boreal::scanner::{StringMatch, StringMatches};
use ::boreal::{scanner::MatchedRule, Compiler, Scanner};
use ::boreal::{Metadata, MetadataValue};

#[pymodule]
fn boreal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compile, m)?)
}

#[pyfunction]
#[pyo3(signature = (filepath=None, source=None))]
fn compile(filepath: Option<&str>, source: Option<&str>) -> PyResult<PyScanner> {
    let mut compiler = Compiler::new();
    match (filepath, source) {
        (Some(v), None) => compiler.add_rules_file(v),
        (None, Some(v)) => compiler.add_rules_str(v),
        _ => todo!(),
    }
    .unwrap();

    Ok(PyScanner {
        scanner: compiler.into_scanner(),
    })
}

#[pyclass]
struct PyScanner {
    scanner: Scanner,
}

#[pymethods]
impl PyScanner {
    #[pyo3(signature = (filepath=None, data=None))]
    fn r#match(
        &self,
        filepath: Option<&str>,
        data: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<PyMatch>> {
        let res = match (filepath, data) {
            (Some(filepath), None) => self.scanner.scan_file(filepath),
            (None, Some(data)) => {
                if let Ok(s) = data.downcast::<PyString>() {
                    self.scanner.scan_mem(s.to_str()?.as_bytes())
                } else if let Ok(s) = data.downcast::<PyBytes>() {
                    self.scanner.scan_mem(s.as_bytes())
                } else {
                    todo!()
                }
            }
            _ => todo!(),
        };

        match res {
            Ok(v) => Python::with_gil(|py| {
                v.matched_rules
                    .into_iter()
                    .map(|v| PyMatch::new(py, &self.scanner, v))
                    .collect::<Result<_, _>>()
            }),
            // TODO: fix difference
            Err((err, _)) => Err(PyValueError::new_err(format!("{err}"))),
        }
    }
}

#[pyclass]
struct PyMatch {
    /// Name of the matching rule
    #[pyo3(get)]
    rule: Py<PyString>,

    /// Namespace of the matching rule
    #[pyo3(get)]
    namespace: Py<PyString>,

    /// List of tags associated to the rule
    #[pyo3(get)]
    tags: Py<PyList>,

    /// Dictionary with metadata associated to the rule
    #[pyo3(get)]
    meta: HashMap<String, Py<PyAny>>,

    /// Tuple with offsets and strings that matched the file
    #[pyo3(get)]
    strings: Vec<PyStringMatches>,
}

impl PyMatch {
    fn new(py: Python, scanner: &Scanner, rule: MatchedRule) -> Result<Self, PyErr> {
        Ok(Self {
            rule: rule.name.into_pyobject(py)?.unbind(),
            namespace: rule
                .namespace
                .unwrap_or_default()
                .into_pyobject(py)?
                .unbind(),
            meta: rule
                .metadatas
                .iter()
                .map(|m| convert_metadata(py, scanner, m))
                .collect::<Result<_, _>>()?,
            tags: PyList::new(py, rule.tags)?.unbind(),
            strings: rule.matches.into_iter().map(PyStringMatches::new).collect(),
        })
    }
}

fn convert_metadata(
    py: Python,
    scanner: &Scanner,
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

#[pyclass]
#[derive(Clone)]
struct PyStringMatches {
    /// Name of the matching string.
    #[pyo3(get)]
    identifier: String,

    /// List of matches for the string.
    #[pyo3(get)]
    instances: Vec<StringMatchInstance>,
    // TODO: missing flags
}

impl PyStringMatches {
    fn new(s: StringMatches) -> Self {
        Self {
            identifier: format!("${}", &s.name),
            instances: s
                .matches
                .into_iter()
                .map(StringMatchInstance::new)
                .collect(),
        }
    }
}

/// Match instance of a YARA string
#[pyclass(frozen)]
#[derive(Clone)]
struct StringMatchInstance {
    /// Offset of the match.
    #[pyo3(get)]
    offset: usize,

    /// Matched data, might have been truncated if too long.
    matched_data: Vec<u8>,

    /// Length of the entire match.
    #[pyo3(get)]
    matched_length: usize,
    // TODO: missing xor_key
}

impl StringMatchInstance {
    fn new(s: StringMatch) -> Self {
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
    fn matched_data(self_: PyRef<'_, Self>) -> PyResult<Bound<'_, PyBytes>> {
        Ok(PyBytes::new(self_.py(), &self_.matched_data))
    }

    fn __repr__(&self) -> String {
        String::from_utf8_lossy(&self.matched_data).to_string()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.matched_data.hash(&mut hasher);
        hasher.finish()
    }
}
