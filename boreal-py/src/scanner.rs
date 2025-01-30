use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use ::boreal::scanner;

use crate::rule_match::Match;

create_exception!(boreal, ScanError, PyException, "error when scanning");
create_exception!(boreal, TimeoutError, PyException, "scan timed out");

#[pyclass]
pub struct Scanner {
    pub scanner: scanner::Scanner,
    #[pyo3(get)]
    pub warnings: Vec<String>,
}

#[pymethods]
impl Scanner {
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        filepath=None,
        data=None,
        pid=None,
        externals=None,
        callback=None,
        fast=false,
        timeout=None,
        modules_data=None,
        modules_callback=None,
        warnings_callback=None,
        which_callbacks=None,
        console_callback=None,
    ))]
    fn r#match(
        &self,
        filepath: Option<&str>,
        data: Option<&Bound<'_, PyAny>>,
        pid: Option<u32>,
        externals: Option<&Bound<'_, PyDict>>,
        callback: Option<&Bound<'_, PyAny>>,
        fast: bool,
        timeout: Option<u64>,
        modules_data: Option<&Bound<'_, PyDict>>,
        modules_callback: Option<&Bound<'_, PyAny>>,
        warnings_callback: Option<&Bound<'_, PyAny>>,
        which_callbacks: Option<&Bound<'_, PyAny>>,
        console_callback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<Match>> {
        let mut scanner = self.scanner.clone();

        if let Some(externals) = externals {
            set_externals(&mut scanner, externals)?;
        }

        if let Some(timeout) = timeout {
            scanner.set_scan_params(
                scanner::ScanParams::default().timeout_duration(Some(Duration::from_secs(timeout))),
            );
        }

        // TODO
        {
            let _ = callback;
            let _ = fast;
            let _ = modules_data;
            let _ = modules_callback;
            let _ = warnings_callback;
            let _ = which_callbacks;
            let _ = console_callback;
        }

        let res = match (filepath, data, pid) {
            (Some(filepath), None, None) => scanner.scan_file(filepath),
            (None, Some(data), None) => {
                if let Ok(s) = data.extract::<&[u8]>() {
                    scanner.scan_mem(s)
                } else if let Ok(s) = data.extract::<&str>() {
                    scanner.scan_mem(s.as_bytes())
                } else {
                    return Err(PyTypeError::new_err(
                        "data must be a string or a bytestring",
                    ));
                }
            }
            (None, None, Some(pid)) => scanner.scan_process(pid),
            _ => {
                return Err(PyTypeError::new_err(
                    "one of filepath, data or pid must be passed",
                ))
            }
        };

        match res {
            Ok(v) => Python::with_gil(|py| {
                v.matched_rules
                    .into_iter()
                    .map(|v| Match::new(py, &scanner, v))
                    .collect::<Result<_, _>>()
            }),
            Err((err, _)) => match err {
                scanner::ScanError::Timeout => Err(TimeoutError::new_err("")),
                _ => Err(ScanError::new_err(format!("{err}"))),
            },
        }
    }
}

fn set_externals(scanner: &mut scanner::Scanner, externals: &Bound<'_, PyDict>) -> PyResult<()> {
    for (key, value) in externals {
        let name: &str = key.extract()?;

        let res = if let Ok(v) = value.extract::<bool>() {
            scanner.define_symbol(name, v)
        } else if let Ok(v) = value.extract::<i64>() {
            scanner.define_symbol(name, v)
        } else if let Ok(v) = value.extract::<f64>() {
            scanner.define_symbol(name, v)
        } else if let Ok(v) = value.extract::<&str>() {
            scanner.define_symbol(name, v)
        } else if let Ok(v) = value.extract::<&[u8]>() {
            scanner.define_symbol(name, v)
        } else {
            return Err(PyTypeError::new_err(
                "invalid type for the external value, must be a boolean, integer, float or string",
            ));
        };

        // the error is ignored as is done in YARA: this avoids aborting the scan for an
        // overfit dictionary.
        drop(res);
    }
    Ok(())
}
