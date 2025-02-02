use std::panic::AssertUnwindSafe;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use ::boreal::module::{Console, ConsoleData};
use ::boreal::scanner;

use crate::rule_match::Match;

create_exception!(boreal, ScanError, PyException, "error when scanning");
create_exception!(boreal, TimeoutError, PyException, "scan timed out");

#[pyclass(frozen)]
pub struct Scanner {
    scanner: scanner::Scanner,

    /// List of warnings generated when compiling rules.
    #[pyo3(get)]
    warnings: Vec<String>,
}

impl Scanner {
    pub fn new(scanner: scanner::Scanner, warnings: Vec<String>) -> Self {
        Self { scanner, warnings }
    }
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
        if let Some(modules_data) = modules_data {
            set_modules_data(&mut scanner, modules_data)?;
        }

        if let Some(timeout) = timeout {
            scanner.set_scan_params(
                scanner::ScanParams::default().timeout_duration(Some(Duration::from_secs(timeout))),
            );
        }

        if let Some(cb) = console_callback {
            if !cb.is_callable() {
                return Err(PyTypeError::new_err("console_callback is not callable"));
            }

            // Not sure how to avoid the AssertUnwindSafe
            let cb = AssertUnwindSafe(cb.clone().unbind());
            scanner.set_module_data::<Console>(ConsoleData::new(move |log| {
                Python::with_gil(|py| {
                    let pylog = PyString::new(py, &log);
                    // Ignore result
                    let _r = cb.call1(py, (pylog,));
                });
            }));
        }

        // TODO
        {
            let _ = callback;
            let _ = fast;
            let _ = modules_callback;
            let _ = warnings_callback;
            let _ = which_callbacks;
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

    fn __iter__(&self, py: Python<'_>) -> PyResult<RulesIter> {
        // Unfortunately, we cannot return an object with a lifetime, so
        // we need to collect all rules into a vec of owned elements before
        // generating an iterator...
        Ok(RulesIter {
            rules_iter: self
                .scanner
                .rules()
                .map(|rule| crate::rule::Rule::new(py, &self.scanner, &rule))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter(),
        })
    }
}

#[pyclass]
pub struct RulesIter {
    rules_iter: std::vec::IntoIter<crate::rule::Rule>,
}

#[pymethods]
impl RulesIter {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<Self>) -> Option<crate::rule::Rule> {
        slf.rules_iter.next()
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

fn set_modules_data(
    scanner: &mut scanner::Scanner,
    modules_data: &Bound<'_, PyDict>,
) -> PyResult<()> {
    #[allow(clippy::never_loop)]
    for (key, value) in modules_data {
        let name: &str = key.extract()?;

        #[cfg(feature = "cuckoo")]
        {
            use ::boreal::module::{Cuckoo, CuckooData};

            if name == "cuckoo" {
                match value.extract::<&str>() {
                    Ok(value) => match CuckooData::from_json_report(value) {
                        Some(data) => scanner.set_module_data::<Cuckoo>(data),
                        None => {
                            return Err(PyTypeError::new_err(
                                "the data for the cuckoo module is invalid",
                            ))
                        }
                    },

                    Err(_) => {
                        return Err(PyTypeError::new_err(
                            "the data for the cuckoo module must be a string",
                        ))
                    }
                }
                continue;
            }
        }
        #[cfg(not(feature = "cuckoo"))]
        // Suppress unused var warnings
        {
            let _ = scanner;
            let _v = value;
        }

        return Err(PyTypeError::new_err(format!(
            "cannot set data for unknown module `{name}`",
        )));
    }

    Ok(())
}
