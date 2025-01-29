use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use ::boreal::Scanner;

use crate::rule_match::Match;

#[pyclass]
pub struct PyScanner {
    pub scanner: Scanner,
    #[pyo3(get)]
    pub warnings: Vec<String>,
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
