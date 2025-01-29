//! Python bindings for the boreal library.
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use pyo3::basic::CompareOp;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyList, PyString};

use ::boreal::scanner;
use ::boreal::{Compiler, Scanner};
use ::boreal::{Metadata, MetadataValue};

// TODO: all clone impls should be efficient...
// TODO: should all pyclasses have names and be exposed in the module?

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
    ) -> PyResult<Vec<Match>> {
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
                    .map(|v| Match::new(py, &self.scanner, v))
                    .collect::<Result<_, _>>()
            }),
            // TODO: fix difference
            Err((err, _)) => Err(PyValueError::new_err(format!("{err}"))),
        }
    }
}

/// A matching rule
#[pyclass(frozen)]
struct Match {
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
    fn new(py: Python, scanner: &Scanner, rule: scanner::MatchedRule) -> Result<Self, PyErr> {
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

/// List of match instances of a YARA string
#[pyclass(frozen)]
#[derive(Clone)]
struct StringMatches {
    /// Name of the matching string.
    #[pyo3(get)]
    identifier: String,

    /// List of matches for the string.
    #[pyo3(get)]
    instances: Vec<StringMatchInstance>,
}

impl StringMatches {
    fn new(s: scanner::StringMatches) -> Self {
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

#[pymethods]
impl StringMatches {
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
    fn new(s: scanner::StringMatch) -> Self {
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
    fn matched_data(&self) -> &[u8] {
        &self.matched_data
    }

    fn __repr__(&self) -> String {
        String::from_utf8_lossy(&self.matched_data).to_string()
    }

    // XXX: the yara impl is to hash on the data only.
    // TODO: when not in yara compat mode, we should probably avoid this...
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.matched_data.hash(&mut hasher);
        hasher.finish()
    }
}
