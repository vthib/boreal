use std::collections::HashMap;
use std::sync::atomic::Ordering;

use boreal::module::StaticValue;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use ::boreal::module::Value;

use crate::YARA_PYTHON_COMPATIBILITY;

pub fn add_dynamic_values_to_dict<'py>(
    py: Python<'py>,
    dict: &Bound<'py, PyDict>,
    obj: &HashMap<&str, Value>,
) -> PyResult<()> {
    for (k, v) in obj {
        let k = k.into_pyobject(py)?;
        if let Some(v) = convert_dynamic_value(py, v)? {
            dict.set_item(k, v)?;
        }
    }
    Ok(())
}

pub fn add_static_values_to_dict<'py>(
    py: Python<'py>,
    dict: &Bound<'py, PyDict>,
    obj: HashMap<&str, StaticValue>,
) -> PyResult<()> {
    for (k, v) in obj {
        let k = k.into_pyobject(py)?;
        if let Some(v) = convert_static_value(py, v)? {
            dict.set_item(k, v)?;
        }
    }
    Ok(())
}

fn convert_dynamic_value<'py>(
    py: Python<'py>,
    value: &Value,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    let result = match value {
        Value::Integer(i) => i.into_pyobject(py)?.into_any(),
        Value::Float(f) => f.into_pyobject(py)?.into_any(),
        Value::Bytes(bytes) => bytes.into_pyobject(py)?.into_any(),
        Value::Boolean(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::Object(obj) => {
            let dict = PyDict::new(py);
            add_dynamic_values_to_dict(py, &dict, obj)?;
            dict.into_any()
        }
        Value::Array(vec) => {
            let list = PyList::empty(py);
            for item in vec {
                if let Some(v) = convert_dynamic_value(py, item)? {
                    list.append(v)?;
                }
            }
            list.into_any()
        }
        Value::Dictionary(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                // XXX: YARA pretends the key is utf-8, which is not guaranteed. This makes
                // the whole match call fail if it is not the case.
                // See <https://github.com/VirusTotal/yara-python/issues/273>.
                // The ideal behavior is to use a byte string as the key, which we do by default.
                // But this is not compatible with yara, so in compat mode, we use a string as
                // well, except we skip the key if invalid instead of breaking the whole scan.
                let key = if YARA_PYTHON_COMPATIBILITY.load(Ordering::SeqCst) {
                    let Ok(s) = std::str::from_utf8(k) else {
                        continue;
                    };
                    s.into_pyobject(py)?.into_any()
                } else {
                    PyBytes::new(py, k).into_any()
                };

                if let Some(v) = convert_dynamic_value(py, v)? {
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

fn convert_static_value(py: Python, value: StaticValue) -> PyResult<Option<Bound<'_, PyAny>>> {
    let result = match value {
        StaticValue::Integer(i) => i.into_pyobject(py)?.into_any(),
        StaticValue::Float(f) => f.into_pyobject(py)?.into_any(),
        StaticValue::Bytes(bytes) => bytes.into_pyobject(py)?.into_any(),
        StaticValue::Boolean(b) => b.into_pyobject(py)?.to_owned().into_any(),
        StaticValue::Object(obj) => {
            let dict = PyDict::new(py);
            add_static_values_to_dict(py, &dict, obj)?;
            dict.into_any()
        }
        StaticValue::Function { .. } => return Ok(None),
    };

    Ok(Some(result))
}
