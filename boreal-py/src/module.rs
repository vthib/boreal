use std::collections::HashMap;
use std::sync::atomic::Ordering;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use ::boreal::module::Value;

use crate::YARA_PYTHON_COMPATIBILITY;

pub fn convert_object<'py>(
    py: Python<'py>,
    obj: &HashMap<&str, Value>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (k, v) in obj {
        let k = k.into_pyobject(py)?;
        if let Some(v) = convert_value(py, v)? {
            dict.set_item(k, v)?;
        }
    }
    Ok(dict)
}

fn convert_value<'py>(py: Python<'py>, value: &Value) -> PyResult<Option<Bound<'py, PyAny>>> {
    let result = match value {
        Value::Integer(i) => i.into_pyobject(py)?.into_any(),
        Value::Float(f) => f.into_pyobject(py)?.into_any(),
        Value::Bytes(bytes) => bytes.into_pyobject(py)?.into_any(),
        Value::Boolean(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::Object(obj) => convert_object(py, obj)?.into_any(),
        Value::Array(vec) => {
            let list = PyList::empty(py);
            for item in vec {
                if let Some(v) = convert_value(py, item)? {
                    list.append(v)?;
                }
            }
            list.into_any()
        }
        Value::Dictionary(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                let key = if YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst) {
                    // FIXME: YARA pretends the key is utf-8, which is not guaranteed. This makes
                    // the whole match call fail if it is not the case. Would be nice to fix on
                    // YARA side, but in the meantime, we reproduce the same logic, except we
                    // do not abort the scan.
                    let Ok(s) = std::str::from_utf8(k) else {
                        continue;
                    };
                    s.into_pyobject(py)?.into_any()
                } else {
                    PyBytes::new(py, k).into_any()
                };

                if let Some(v) = convert_value(py, v)? {
                    dict.set_item(key, v)?;
                }
            }
            dict.into_any()
        }
        // Hard to convert so just ignore those values.
        Value::Regex(_) | Value::Function(_) | Value::Undefined => return Ok(None),
    };
    Ok(Some(result))
}
