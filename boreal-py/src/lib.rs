//! Python bindings for the boreal library.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use pyo3::{create_exception, ffi, intern};

use ::boreal::compiler;

mod module;
mod rule;
mod rule_match;
mod rule_string;
mod scanner;
mod string_match_instance;
mod string_matches;

create_exception!(boreal, Error, PyException, "Generic boreal error");
create_exception!(
    boreal,
    AddRuleError,
    Error,
    "Raised when failing to compile a rule"
);

static MAX_STRINGS_PER_RULE: Mutex<Option<usize>> = Mutex::new(None);
static MATCH_MAX_LENGTH: Mutex<Option<usize>> = Mutex::new(None);
static YARA_PYTHON_COMPATIBILITY: AtomicBool = AtomicBool::new(false);

const CALLBACK_CONTINUE: u32 = 0;
const CALLBACK_ABORT: u32 = 1;

const CALLBACK_MATCHES: u32 = 0x01;
const CALLBACK_NON_MATCHES: u32 = 0x02;
const CALLBACK_ALL: u32 = CALLBACK_MATCHES | CALLBACK_NON_MATCHES;

// Same value as declared in yara, for compatibility.
const CALLBACK_TOO_MANY_MATCHES: u32 = 6;

/// Python bindings for the YARA scanner boreal.
#[pymodule]
fn boreal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_function(wrap_pyfunction!(set_config, m)?)?;
    #[cfg(feature = "serialize")]
    m.add_function(wrap_pyfunction!(load, m)?)?;

    m.add("modules", get_available_modules(py))?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("CALLBACK_CONTINUE", CALLBACK_CONTINUE)?;
    m.add("CALLBACK_ABORT", CALLBACK_ABORT)?;
    m.add("CALLBACK_MATCHES", CALLBACK_MATCHES)?;
    m.add("CALLBACK_NON_MATCHES", CALLBACK_NON_MATCHES)?;
    m.add("CALLBACK_ALL", CALLBACK_ALL)?;
    m.add("CALLBACK_TOO_MANY_MATCHES", CALLBACK_TOO_MANY_MATCHES)?;

    m.add("Error", py.get_type::<Error>())?;
    m.add("AddRuleError", py.get_type::<AddRuleError>())?;
    // Add an alias for SyntaxError: this provides compatibility
    // with code using yara.
    m.add("SyntaxError", py.get_type::<AddRuleError>())?;

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
    m.add("RuleString", py.get_type::<rule_string::RuleString>())?;
    m.add("CompilerProfile", py.get_type::<CompilerProfile>())?;

    Ok(())
}

/// Compile YARA rules and generate a Scanner object.
///
/// One of `filepath`, `filepaths`, `source`, `sources`
/// or `file` must be passed.
///
/// Args:
///     filepath: Path to a file containing the rules to compile.
///     filepaths: Dictionary where the value is a path to a file, containing
///         rules to compile, and the key is the name of the namespace that
///         will contain those rules.
///     source: String containing the rules to compile.
///     sources: Dictionary where the value is a string containing the rules
///         to compile, and the key is the name of the namespace that will
///         contain those rules.
///     file: An opened file containing the rules to compile. This can be any
///         object that exposes a `read` method.
///     externals: Dictionary of externals symbols to make available during
///         compilation. The key is the name of the external symbol, and the
///         value is the original value to assign to this symbol. This original
///         value can be replaced during scanning by specifying an `externals`
///         dictionary, see the `Scanner::match` method.
///     includes: Allow rules to use the `include` directive. If set to False,
///         any use of the `include` directive will result in a compilation
///         error.
///     error_on_warning: If true, make the compilation fail when a warning
///         is emitted. If false, warnings can be found in the resulting
///         `Scanner` object, see `Scanner::warnings`.
///     include_callback: If specified, this callback is used to resolve
///         callbacks. The callback will receive three arguments:
///           - The path being included.
///           - The path of the current document. Can be None if the current
///             document was specified as a string, such as when using the
///             `source` or `sources` parameter.
///           - The current namespace.
///         The callback must return a string which is the included document.
///     strict_escape: If true, invalid escape sequences in regexes will
///         generate warnings. The default value depends on the yara
///         compatibility mode: it is False if in compat mode, or True
///         otherwise.
///     profile: Profile to use when compiling the rules. If not specified,
///         `CompilerProfile::Speed` is used.
///
/// Returns:
///   a `Scanner` object that holds the compiled rules.
///
/// Raises:
///  TypeError: A provided argument has the wrong type, or none
///      of the input arguments were provided.
///  boreal.AddRuleError: A rule failed to compile.
#[pyfunction]
#[pyo3(signature = (
    filepath=None,
    filepaths=None,
    source=None,
    sources=None,
    file=None,
    externals=None,
    includes=true,
    error_on_warning=false,
    include_callback=None,
    strict_escape=None,
    profile=None,
))]
#[allow(clippy::too_many_arguments)]
fn compile(
    filepath: Option<&str>,
    filepaths: Option<&Bound<'_, PyDict>>,
    source: Option<&str>,
    sources: Option<&Bound<'_, PyDict>>,
    file: Option<&Bound<'_, PyAny>>,
    externals: Option<&Bound<'_, PyDict>>,
    includes: bool,
    error_on_warning: bool,
    include_callback: Option<&Bound<'_, PyAny>>,
    strict_escape: Option<bool>,
    profile: Option<&CompilerProfile>,
) -> PyResult<scanner::Scanner> {
    let mut compiler = build_compiler(profile);

    // By default, enable strict escape, this is the default behavior in boreal.
    // If in yara compat mode, use the yara default behavior and disable it.
    let disable_unknown_escape_warning = match strict_escape {
        Some(v) => !v,
        None => YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst),
    };

    let mut params = compiler::CompilerParams::default()
        .disable_includes(!includes)
        .fail_on_warnings(error_on_warning)
        .disable_unknown_escape_warning(disable_unknown_escape_warning);
    if let Ok(lock) = MAX_STRINGS_PER_RULE.lock() {
        if let Some(value) = *lock {
            params = params.max_strings_per_rule(value);
        }
    }

    compiler.set_params(params);

    if let Some(externals) = externals {
        add_externals(&mut compiler, externals)?;
    }

    if let Some(cb) = include_callback {
        if !cb.is_callable() {
            return Err(PyTypeError::new_err("include_callback is not callable"));
        }

        let include_callback = cb.clone().unbind();
        compiler.set_include_callback(move |include_name, current_path, ns| {
            call_py_include_callback(&include_callback, include_name, current_path, ns)
                .map_err(|desc| std::io::Error::new(std::io::ErrorKind::Other, desc))
        });
    }

    let mut warnings = Vec::new();

    match (filepath, source, file, filepaths, sources) {
        (Some(filepath), None, None, None, None) => {
            let res = compiler
                .add_rules_file(filepath)
                .map_err(|err| AddRuleError::new_err(format!("{err}")))?;
            warnings = res.warnings().map(|err| format!("{err}")).collect();
        }
        (None, Some(source), None, None, None) => {
            let res = compiler
                .add_rules_str(source)
                .map_err(|err| AddRuleError::new_err(format!("{err}")))?;
            warnings = res.warnings().map(|err| format!("{err}")).collect();
        }
        (None, None, Some(file), None, None) => {
            // Read the file into a string
            let res = file.call_method0(intern!(file.py(), "read"))?;
            let contents: &str = res.extract()?;

            let res = compiler
                .add_rules_str(contents)
                .map_err(|err| AddRuleError::new_err(format!("{err}")))?;
            warnings = res.warnings().map(|err| format!("{err}")).collect();
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
                    .map_err(|err| AddRuleError::new_err(format!("{err}")))?;
                warnings.extend(res.warnings().map(|err| format!("{err}")));
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
                    .map_err(|err| AddRuleError::new_err(format!("{err}")))?;
                warnings.extend(res.warnings().map(|err| format!("{err}")));
            }
        }
        _ => return Err(PyTypeError::new_err("invalid arguments passed")),
    }

    Ok(scanner::Scanner::new(compiler.finalize(), warnings))
}

/// Profile to use when compiling rules.
#[pyclass(eq, eq_int, module = "boreal")]
#[derive(Debug, PartialEq)]
enum CompilerProfile {
    /// Prioritize scan speed.
    ///
    /// This profile will strive to get the best possible scan speed by using more memory
    /// when possible.
    Speed = 0,
    /// Prioritize memory usage
    ///
    /// This profile will strive to reduce memory usage as much as possible, even if it means
    /// a slower scan speed overall.
    Memory = 1,
}

/// Modify some global parameters
///
/// Args:
///   max_strings_per_rule: Maximum number of strings allowed in a single rule.
///       If a rule has more strings than this limit, its compilation will fail.
///   max_match_data: Maximum length for the match data returned in match
///       results. The match details returned in results will be truncated if
///       they exceed this limit. Default value is 512
///   stack_size: Unused, this is accepted purely for compatibility with yara.
///   yara_compatibility: Enable or disable full YARA compatibility. See the
///       global documentation of this library for more details.
///
/// Raises:
///  TypeError: A provided argument has the wrong type
#[pyfunction]
#[pyo3(signature = (
    max_strings_per_rule=None,
    max_match_data=None,
    stack_size=None,
    yara_compatibility=None,
))]
#[allow(clippy::too_many_arguments)]
fn set_config(
    max_strings_per_rule: Option<usize>,
    max_match_data: Option<usize>,
    stack_size: Option<u64>,
    yara_compatibility: Option<bool>,
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
    if let Some(value) = yara_compatibility {
        YARA_PYTHON_COMPATIBILITY.store(value, Ordering::SeqCst);
    }
    // Ignore stack size, this isn't used in boreal.
    let _ = stack_size;
}

/// Load rules from a serialized scanner object.
///
/// A scanner can be serialized into a bytestring and reloaded using
/// this function.
///
/// See [the boreal documentation](https://docs.rs/boreal/latest/boreal/scanner/struct.Scanner.html#method.to_bytes)
/// for more details about this feature and its limitations.
///
/// One of `filepath`, `file` or `data` must be provided.
///
/// Args:
///   filepath: The path to the file containing the serialized files.
///   file: An opened file containing the serialized files. This can be any
///       object that exposes a `read` method, as long as this read method
///       returns bytes.
///   data: The serialized bytes.
///
/// Returns:
///   a `Scanner` object.
///
/// Raises:
///  TypeError: A provided argument has the wrong type, or none
///      of the input arguments were provided.
///  boreal.Error: The deserialization failed.
#[cfg(feature = "serialize")]
#[pyfunction]
#[pyo3(signature = (
    filepath=None,
    file=None,
    data=None,
))]
fn load(
    filepath: Option<&str>,
    file: Option<&Bound<'_, PyAny>>,
    data: Option<&[u8]>,
) -> PyResult<scanner::Scanner> {
    let res = match (filepath, file, data) {
        (Some(filepath), None, None) => {
            let contents = std::fs::read(filepath)?;
            scanner::Scanner::load(&contents)
        }
        (None, Some(file), None) => {
            let Ok(res) = file.call_method0(intern!(file.py(), "read")) else {
                return Err(PyTypeError::new_err(
                    "the file parameter must implement the read method",
                ));
            };
            let contents: &[u8] = res.extract()?;
            scanner::Scanner::load(contents)
        }
        (None, None, Some(data)) => scanner::Scanner::load(data),
        _ => {
            return Err(PyTypeError::new_err(
                "one of filepath or file must be passed",
            ))
        }
    };

    res.map_err(|err| Error::new_err(format!("Unable to create a Scanner from bytes: {err:?}")))
}

fn call_py_include_callback(
    include_callback: &Py<PyAny>,
    include_name: &str,
    current_path: Option<&Path>,
    ns: &str,
) -> Result<String, String> {
    let current_path = current_path.map(|v| v.display().to_string());

    Python::with_gil(|py| {
        let res = include_callback
            .call1(py, (include_name, current_path, ns))
            .map_err(|err| format!("error when calling include callback: {err:?}"))?;
        res.extract(py)
            .map_err(|err| format!("include callback did not return a string: {err:?}"))
    })
}

fn get_available_modules(py: Python<'_>) -> Vec<Bound<'_, PyString>> {
    build_compiler(None)
        .available_modules()
        .map(|s| PyString::new(py, s))
        .collect()
}

fn build_compiler(profile: Option<&CompilerProfile>) -> compiler::Compiler {
    compiler::CompilerBuilder::new()
        .profile(match profile {
            Some(CompilerProfile::Speed) | None => ::boreal::compiler::CompilerProfile::Speed,
            Some(CompilerProfile::Memory) => ::boreal::compiler::CompilerProfile::Memory,
        })
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
