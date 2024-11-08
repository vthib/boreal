use ::boreal::MetadataValue;
use ::boreal::{scanner::MatchedRule, Compiler, Scanner};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyString};
use std::collections::HashMap;

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
        _ => panic!("bad"),
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
    #[pyo3(signature = (filepath=None))]
    fn r#match(&self, filepath: Option<&str>) -> PyResult<Vec<PyMatch>> {
        match self.scanner.scan_file(filepath.unwrap()) {
            Ok(v) => {
                let res = Python::with_gil(|py| {
                    v.matched_rules
                        .iter()
                        .map(|v| PyMatch::new(py, &self.scanner, v))
                        .collect()
                });
                Ok(res)
            }
            Err((err, _)) => Err(PyValueError::new_err(format!("{}", err))),
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
    strings: Vec<String>,
}

impl PyMatch {
    fn new(py: Python, scanner: &Scanner, rule: &MatchedRule) -> Self {
        Self {
            rule: PyString::new_bound(py, rule.name).unbind(),
            namespace: PyString::new_bound(py, rule.namespace.unwrap_or_default()).unbind(),
            meta: rule
                .metadatas
                .iter()
                .map(|m| {
                    let v = match m.value {
                        MetadataValue::Bytes(v) => scanner.get_bytes_symbol(v).to_object(py),
                        MetadataValue::Integer(v) => v.to_object(py),
                        MetadataValue::Boolean(v) => v.to_object(py),
                    };
                    (scanner.get_string_symbol(m.name).to_string(), v)
                })
                .collect(),
            tags: PyList::new_bound(py, rule.tags.iter().map(|v| PyString::new_bound(py, v)))
                .unbind(),
            strings: todo!(),
        }
    }
}
