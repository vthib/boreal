use std::panic::AssertUnwindSafe;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use ::boreal::module::{Console, ConsoleData, Value};
use ::boreal::scanner::{self, CallbackEvents, ScanCallbackResult, ScanEvent};

use crate::rule_match::Match;
use crate::rule_string::RuleString;
use crate::{
    CALLBACK_ALL, CALLBACK_MATCHES, CALLBACK_NON_MATCHES, CALLBACK_TOO_MANY_MATCHES,
    MATCH_MAX_LENGTH,
};

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
        let modules_callback = match modules_callback {
            Some(cb) => {
                if !cb.is_callable() {
                    return Err(PyTypeError::new_err("modules_callback is not callable"));
                }
                Some(cb.clone().unbind())
            }
            None => None,
        };
        let warnings_callback = match warnings_callback {
            Some(cb) => {
                if !cb.is_callable() {
                    return Err(PyTypeError::new_err("warnings_callback is not callable"));
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

        let mut params = scanner.scan_params().clone();
        if let Some(timeout) = timeout {
            params = params.timeout_duration(Some(Duration::from_secs(timeout)));
        }
        let mut events = CallbackEvents::RULE_MATCH;
        if callback.is_some() && (which & CALLBACK_NON_MATCHES) != 0 {
            params = params.include_not_matched_rules(true);
            events |= CallbackEvents::RULE_NO_MATCH;
        }
        if modules_callback.is_some() {
            events |= CallbackEvents::MODULE_IMPORT;
        }
        if warnings_callback.is_some() {
            events |= CallbackEvents::STRING_REACHED_MATCH_LIMIT;
        }
        params = params.callback_events(events);
        if let Ok(lock) = MATCH_MAX_LENGTH.lock() {
            if let Some(value) = *lock {
                params = params.match_max_length(value);
            }
        }
        // TODO: only do this in libyara compat mode.
        // Default value in libyara
        params = params.string_max_nb_matches(1_000_000);
        scanner.set_scan_params(params);

        // TODO
        {
            let _ = fast;
        }

        let mut cb_handler = CallbackHandler::new(
            &scanner,
            callback,
            modules_callback,
            warnings_callback,
            which,
        );
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
    modules_callback: Option<Py<PyAny>>,
    warnings_callback: Option<Py<PyAny>>,
    which: u32,
    error: Option<PyErr>,
}

impl<'s> CallbackHandler<'s> {
    fn new(
        scanner: &'s scanner::Scanner,
        callback: Option<Py<PyAny>>,
        modules_callback: Option<Py<PyAny>>,
        warnings_callback: Option<Py<PyAny>>,
        which: u32,
    ) -> Self {
        Self {
            scanner,
            matches: Vec::new(),
            callback,
            modules_callback,
            warnings_callback,
            which,
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
            ScanEvent::RuleMatch(rule_match) => self.handle_rule_event(rule_match, true),
            ScanEvent::RuleNoMatch(rule_match) => self.handle_rule_event(rule_match, false),
            ScanEvent::ModuleImport {
                module_name,
                dynamic_values,
            } => match &self.modules_callback {
                Some(cb) => Python::with_gil(|py| {
                    // A module value must be an object. If empty,  means the module has not
                    // generated any values.
                    let dict = match dynamic_values {
                        Value::Object(map) => crate::module::convert_object(py, map)?,
                        _ => PyDict::new(py),
                    };
                    // TODO: add yara compat mode to avoid overwriting the value if not in
                    // compat mode.
                    dict.set_item("module", module_name)?;

                    let result = cb.call1(py, (dict,))?;
                    Ok(convert_callback_return_value(py, &result))
                }),
                None => Ok(ScanCallbackResult::Continue),
            },
            ScanEvent::StringReachedMatchLimit(string_identifier) => {
                match &self.warnings_callback {
                    Some(cb) => Python::with_gil(|py| {
                        let rule_string = RuleString::new(py, &string_identifier);
                        let msg_id = CALLBACK_TOO_MANY_MATCHES;
                        let result = cb.call1(py, (msg_id, rule_string))?;
                        Ok(convert_callback_return_value(py, &result))
                    }),
                    None => Ok(ScanCallbackResult::Continue),
                }
            }
            _ => Ok(ScanCallbackResult::Continue),
        }
    }

    fn handle_rule_event(
        &mut self,
        rule: scanner::EvaluatedRule,
        matched: bool,
    ) -> PyResult<ScanCallbackResult> {
        Python::with_gil(|py| {
            let m = Match::new(py, self.scanner, rule)?;

            let ret = match &self.callback {
                Some(cb) => {
                    if (matched && (self.which & CALLBACK_MATCHES) != 0)
                        || (!matched && (self.which & CALLBACK_NON_MATCHES) != 0)
                    {
                        let rule = match_to_callback_dict(py, &m, matched)?;
                        convert_callback_return_value(py, &cb.call1(py, (rule,))?)
                    } else {
                        ScanCallbackResult::Continue
                    }
                }
                None => ScanCallbackResult::Continue,
            };

            // Always save the match: even if a callback is used, the matches
            // are returned from the match function call.
            // But, only the real matches are saved, not the "non match"...
            if matched {
                self.matches.push(m);
            }
            Ok(ret)
        })
    }
}

fn match_to_callback_dict<'py>(
    py: Python<'py>,
    m: &Match,
    matched: bool,
) -> Result<Bound<'py, PyDict>, PyErr> {
    let d = PyDict::new(py);

    d.set_item("rule", &m.rule)?;
    d.set_item("namespace", &m.namespace)?;
    d.set_item("meta", m.meta.clone_ref(py))?;
    d.set_item("tags", m.tags.clone_ref(py))?;
    d.set_item("strings", m.strings.clone_ref(py))?;
    d.set_item("matches", matched)?;

    Ok(d)
}

fn convert_callback_return_value(py: Python, value: &PyObject) -> ScanCallbackResult {
    match value.extract::<u32>(py) {
        Ok(v) if v == super::CALLBACK_CONTINUE => ScanCallbackResult::Continue,
        Ok(v) if v == super::CALLBACK_ABORT => ScanCallbackResult::Abort,
        _ => ScanCallbackResult::Continue,
    }
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
