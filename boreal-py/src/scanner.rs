use std::panic::AssertUnwindSafe;
use std::time::Duration;

use boreal::scanner::{ScanCallbackResult, ScanEvent};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use ::boreal::module::{Console, ConsoleData};
use ::boreal::scanner;

use crate::rule_match::Match;
use crate::{CALLBACK_ALL, CALLBACK_NON_MATCHES};

create_exception!(boreal, ScanError, PyException, "error when scanning");
create_exception!(boreal, TimeoutError, PyException, "scan timed out");

#[pyclass(frozen, module = "boreal")]
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
                    // FIXME: Ignore result
                    let _r = cb.call1(py, (pylog,));
                });
            }));
        }

        let callback = match callback {
            Some(cb) => {
                if !cb.is_callable() {
                    return Err(PyTypeError::new_err("callback is not callable"));
                }
                Some(cb.clone().unbind())
            }
            None => None,
        };

        let which = match which_callbacks {
            Some(v) => v
                .extract::<u32>()
                .map_err(|_| PyTypeError::new_err("invalid `which_callbacks` parameter: {:?}"))?,
            None => CALLBACK_ALL,
        };
        if callback.is_some() && (which & CALLBACK_NON_MATCHES) != 0 {
            return Err(PyValueError::new_err(
                "only CALLBACK_MATCHES is supported for the `which_callbacks` parameter",
            ));
        }

        // TODO
        {
            let _ = fast;
            let _ = modules_callback;
            let _ = warnings_callback;
        }

        let mut cb_handler = CallbackHandler::new(&scanner, callback);
        let res = match (filepath, data, pid) {
            (Some(filepath), None, None) => {
                scanner.scan_file_with_callback(filepath, |event| cb_handler.handle_event(event))
            }
            (None, Some(data), None) => {
                if let Ok(s) = data.extract::<&[u8]>() {
                    scanner.scan_mem_with_callback(s, |event| cb_handler.handle_event(event))
                } else if let Ok(s) = data.extract::<&str>() {
                    scanner.scan_mem_with_callback(s.as_bytes(), |event| {
                        cb_handler.handle_event(event)
                    })
                } else {
                    return Err(PyTypeError::new_err(
                        "data must be a string or a bytestring",
                    ));
                }
            }
            (None, None, Some(pid)) => {
                scanner.scan_process_with_callback(pid, |event| cb_handler.handle_event(event))
            }
            _ => {
                return Err(PyTypeError::new_err(
                    "one of filepath, data or pid must be passed",
                ))
            }
        };

        // If an error was generated inside the callback, rethrow it
        if let Some(err) = cb_handler.error {
            return Err(err);
        }

        match res {
            Ok(()) => Ok(cb_handler.matches),
            Err(err) => match err {
                // To be iso with yara, an explicit abort by a callback does not return
                // any error.
                scanner::ScanError::CallbackAbort => Ok(cb_handler.matches),
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

struct CallbackHandler<'s> {
    scanner: &'s scanner::Scanner,
    matches: Vec<Match>,
    callback: Option<Py<PyAny>>,
    error: Option<PyErr>,
}

impl<'s> CallbackHandler<'s> {
    fn new(scanner: &'s scanner::Scanner, callback: Option<Py<PyAny>>) -> Self {
        Self {
            scanner,
            matches: Vec::new(),
            callback,
            error: None,
        }
    }

    fn handle_event(&mut self, event: ScanEvent<'s, '_>) -> ScanCallbackResult {
        match self.handle_event_inner(event) {
            Ok(res) => res,
            Err(err) => {
                self.error = Some(err);
                ScanCallbackResult::Abort
            }
        }
    }

    fn handle_event_inner(&mut self, event: ScanEvent<'s, '_>) -> PyResult<ScanCallbackResult> {
        match event {
            ScanEvent::RuleMatch(rule_match) => Python::with_gil(|py| {
                let m = Match::new(py, self.scanner, rule_match)?;

                let mut ret = ScanCallbackResult::Continue;
                if let Some(cb) = &self.callback {
                    let rule = match_to_callback_dict(py, &m)?;
                    let result = cb.call1(py, (rule,))?;

                    match result.extract::<u32>(py) {
                        Ok(v) if v == super::CALLBACK_CONTINUE => {
                            ret = ScanCallbackResult::Continue;
                        }
                        Ok(v) if v == super::CALLBACK_ABORT => ret = ScanCallbackResult::Abort,
                        _ => (),
                    }
                }

                // Always save the match: even if a callback is used, the matches
                // are returned from the match function call.
                self.matches.push(m);
                Ok(ret)
            }),
            _ => Ok(ScanCallbackResult::Continue),
        }
    }
}

fn match_to_callback_dict<'py>(py: Python<'py>, m: &Match) -> Result<Bound<'py, PyDict>, PyErr> {
    let d = PyDict::new(py);

    d.set_item("rule", &m.rule)?;
    d.set_item("namespace", &m.namespace)?;
    d.set_item("meta", m.meta.clone_ref(py))?;
    d.set_item("tags", m.tags.clone_ref(py))?;
    d.set_item("strings", m.strings.clone_ref(py))?;
    d.set_item("matches", true)?;

    Ok(d)
}

#[pyclass(module = "boreal")]
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
