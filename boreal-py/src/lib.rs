//! Python bindings for the boreal library.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::sync::Mutex;

use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use pyo3::{create_exception, ffi, intern};

use ::boreal::compiler;

// TODO: all clone impls should be efficient...
// TODO: check GIL handling in all functions (especially match)

mod module;
mod rule;
mod rule_match;
mod scanner;
mod string_match_instance;
mod string_matches;

create_exception!(boreal, AddRuleError, PyException, "error when adding rules");

static MAX_STRINGS_PER_RULE: Mutex<Option<usize>> = Mutex::new(None);
static MATCH_MAX_LENGTH: Mutex<Option<usize>> = Mutex::new(None);

const CALLBACK_CONTINUE: u32 = 0;
const CALLBACK_ABORT: u32 = 1;

const CALLBACK_MATCHES: u32 = 0x01;
const CALLBACK_NON_MATCHES: u32 = 0x02;
const CALLBACK_ALL: u32 = CALLBACK_MATCHES | CALLBACK_NON_MATCHES;

#[pymodule]
fn boreal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_function(wrap_pyfunction!(set_config, m)?)?;

    m.add("modules", get_available_modules(py))?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("CALLBACK_CONTINUE", CALLBACK_CONTINUE)?;
    m.add("CALLBACK_ABORT", CALLBACK_ABORT)?;
    m.add("CALLBACK_MATCHES", CALLBACK_MATCHES)?;
    m.add("CALLBACK_NON_MATCHES", CALLBACK_NON_MATCHES)?;
    m.add("CALLBACK_ALL", CALLBACK_ALL)?;

    m.add("AddRuleError", py.get_type::<AddRuleError>())?;
    m.add("ScanError", py.get_type::<scanner::ScanError>())?;
    m.add("TimeoutError", py.get_type::<scanner::TimeoutError>())?;

    m.add("Rule", py.get_type::<rule::Rule>())?;
    m.add("Match", py.get_type::<rule_match::Match>())?;
    m.add("Scanner", py.get_type::<scanner::Scanner>())?;
    m.add("RulesIter", py.get_type::<scanner::RulesIter>())?;
    m.add(
        "StringMatchInstance",
        py.get_type::<string_match_instance::StringMatchInstance>(),
    )?;
    m.add(
        "StringMatches",
        py.get_type::<string_matches::StringMatches>(),
    )?;

    Ok(())
}

// TODO: add strict_escape?
#[pyfunction]
#[pyo3(signature = (
    filepath=None,
    source=None,
    file=None,
    filepaths=None,
    sources=None,
    externals=None,
    includes=true,
    error_on_warning=false
))]
#[allow(clippy::too_many_arguments)]
fn compile(
    filepath: Option<&str>,
    source: Option<&str>,
    file: Option<&Bound<'_, PyAny>>,
    filepaths: Option<&Bound<'_, PyDict>>,
    sources: Option<&Bound<'_, PyDict>>,
    externals: Option<&Bound<'_, PyDict>>,
    includes: bool,
    error_on_warning: bool,
) -> PyResult<scanner::Scanner> {
    let mut compiler = build_compiler();

    let mut params = compiler::CompilerParams::default()
        .disable_includes(!includes)
        .fail_on_warnings(error_on_warning);
    if let Ok(lock) = MAX_STRINGS_PER_RULE.lock() {
        if let Some(value) = *lock {
            params = params.max_strings_per_rule(value);
        }
    }
    compiler.set_params(params);

    if let Some(externals) = externals {
        add_externals(&mut compiler, externals)?;
    }

    let mut warnings = Vec::new();

    match (filepath, source, file, filepaths, sources) {
        (Some(filepath), None, None, None, None) => {
            let res = compiler
                .add_rules_file(filepath)
                // TODO: contents
                .map_err(|err| convert_compiler_error(&err, filepath, ""))
                .map_err(AddRuleError::new_err)?;
            warnings = res
                .warnings()
                .map(|err| convert_compiler_error(err, filepath, ""))
                .collect();
        }
        (None, Some(source), None, None, None) => {
            let res = compiler
                .add_rules_str(source)
                .map_err(|err| convert_compiler_error(&err, "source", source))
                .map_err(AddRuleError::new_err)?;
            warnings = res
                .warnings()
                .map(|err| convert_compiler_error(err, "source", source))
                .collect();
        }
        (None, None, Some(file), None, None) => {
            // Read the file into a string
            let res = file.call_method0(intern!(file.py(), "read"))?;
            let contents: &str = res.extract()?;

            let res = compiler
                .add_rules_str(contents)
                .map_err(|err| convert_compiler_error(&err, "file", contents))
                .map_err(AddRuleError::new_err)?;
            warnings = res
                .warnings()
                .map(|err| convert_compiler_error(err, "file", contents))
                .collect();
        }
        (None, None, None, Some(filepaths), None) => {
            for (key, value) in filepaths {
                let namespace: &str = key.extract().map_err(|_| {
                    PyTypeError::new_err("keys of the `filepaths` argument must be strings")
                })?;
                let filepath: &str = value.extract().map_err(|_| {
                    PyTypeError::new_err("values of the `filepaths` argument must be strings")
                })?;
                let res = compiler
                    .add_rules_file_in_namespace(filepath, namespace)
                    // TODO: contents
                    .map_err(|err| convert_compiler_error(&err, filepath, ""))
                    .map_err(AddRuleError::new_err)?;
                warnings.extend(
                    res.warnings()
                        .map(|err| convert_compiler_error(err, filepath, "")),
                );
            }
        }
        (None, None, None, None, Some(sources)) => {
            for (key, value) in sources {
                let namespace: &str = key.extract().map_err(|_| {
                    PyTypeError::new_err("keys of the `sources` argument must be strings")
                })?;
                let source: &str = value.extract().map_err(|_| {
                    PyTypeError::new_err("values of the `sources` argument must be strings")
                })?;
                let res = compiler
                    .add_rules_str_in_namespace(source, namespace)
                    .map_err(|err| convert_compiler_error(&err, namespace, source))
                    .map_err(AddRuleError::new_err)?;
                warnings.extend(
                    res.warnings()
                        .map(|err| convert_compiler_error(err, namespace, source)),
                );
            }
        }
        _ => return Err(PyTypeError::new_err("invalid arguments passed")),
    }

    Ok(scanner::Scanner::new(compiler.into_scanner(), warnings))
}

#[pyfunction]
#[pyo3(signature = (max_strings_per_rule=None, max_match_data=None))]
#[allow(clippy::too_many_arguments)]
fn set_config(
    // TODO: what to do for stack_size
    max_strings_per_rule: Option<usize>,
    max_match_data: Option<usize>,
) {
    if let Some(value) = max_strings_per_rule {
        if let Ok(mut lock) = MAX_STRINGS_PER_RULE.lock() {
            *lock = Some(value);
        }
    }
    if let Some(value) = max_match_data {
        if let Ok(mut lock) = MATCH_MAX_LENGTH.lock() {
            *lock = Some(value);
        }
    }
}

fn get_available_modules(py: Python<'_>) -> Vec<Bound<'_, PyString>> {
    build_compiler()
        .available_modules()
        .map(|s| PyString::new(py, s))
        .collect()
}

fn build_compiler() -> compiler::Compiler {
    compiler::CompilerBuilder::new()
        .add_module(::boreal::module::Console::with_callback(|log| {
            // XXX: when targetting python 3.12 or above, this could be simplified
            // by using the "%.*s" format, avoiding the CString conversion.
            if let Ok(cstr) = CString::new(log) {
                // Safety: see <https://docs.python.org/3/c-api/unicode.html#c.PyUnicode_FromFormat>
                // for the format. A '%s" expects a c-string pointer, which has just been built.
                unsafe { ffi::PySys_FormatStdout(c"%s\n".as_ptr(), cstr.as_ptr()) }
            }
        }))
        .build()
}

fn convert_compiler_error(err: &compiler::AddRuleError, input_name: &str, input: &str) -> String {
    err.to_short_description(input_name, input)
}

fn add_externals(compiler: &mut compiler::Compiler, externals: &Bound<'_, PyDict>) -> PyResult<()> {
    for (key, value) in externals {
        let name: &str = key.extract()?;

        if let Ok(v) = value.extract::<bool>() {
            let _r = compiler.define_symbol(name, v);
        } else if let Ok(v) = value.extract::<i64>() {
            let _r = compiler.define_symbol(name, v);
        } else if let Ok(v) = value.extract::<f64>() {
            let _r = compiler.define_symbol(name, v);
        } else if let Ok(v) = value.extract::<&str>() {
            let _r = compiler.define_symbol(name, v);
        } else if let Ok(v) = value.extract::<&[u8]>() {
            let _r = compiler.define_symbol(name, v);
        } else {
            return Err(PyTypeError::new_err(
                "invalid type for the external value, must be a boolean, integer, float or string",
            ));
        }
    }
    Ok(())
}
