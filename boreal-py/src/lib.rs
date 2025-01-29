//! Python bindings for the boreal library.
use pyo3::prelude::*;

use ::boreal::Compiler;

// TODO: all clone impls should be efficient...
// TODO: should all pyclasses have names and be exposed in the module?

mod rule_match;
mod scanner;
mod string_match_instance;
mod string_matches;

#[pymodule]
fn boreal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compile, m)?)
}

#[pyfunction]
#[pyo3(signature = (filepath=None, source=None))]
fn compile(filepath: Option<&str>, source: Option<&str>) -> PyResult<scanner::PyScanner> {
    let mut compiler = Compiler::new();
    match (filepath, source) {
        (Some(v), None) => compiler.add_rules_file(v),
        (None, Some(v)) => compiler.add_rules_str(v),
        _ => todo!(),
    }
    .unwrap();

    Ok(scanner::PyScanner {
        scanner: compiler.into_scanner(),
    })
}
