use std::collections::HashMap;

use super::{Module, ScanContext, StaticValue, Type, Value};

/// `math` module. Exposes math functions and helpers.
#[derive(Debug)]
pub struct Math;

impl Module for Math {
    fn get_name(&self) -> &'static str {
        "math"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            ("MEAN_BYTES", StaticValue::Float(127.5)),
            (
                "in_range",
                StaticValue::function(
                    Self::in_range,
                    vec![vec![Type::Float, Type::Float, Type::Float]],
                    Type::Integer,
                ),
            ),
            (
                "deviation",
                StaticValue::function(
                    Self::deviation,
                    vec![
                        vec![Type::Integer, Type::Integer, Type::Float],
                        vec![Type::Bytes, Type::Float],
                    ],
                    Type::Float,
                ),
            ),
            (
                "mean",
                StaticValue::function(
                    Self::mean,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Float,
                ),
            ),
            (
                "serial_correlation",
                StaticValue::function(
                    Self::serial_correlation,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Float,
                ),
            ),
            (
                "monte_carlo_pi",
                StaticValue::function(
                    Self::monte_carlo_pi,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Float,
                ),
            ),
            (
                "entropy",
                StaticValue::function(
                    Self::entropy,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Float,
                ),
            ),
            (
                "min",
                StaticValue::function(
                    Self::min,
                    vec![vec![Type::Integer, Type::Integer]],
                    Type::Integer,
                ),
            ),
            (
                "max",
                StaticValue::function(
                    Self::max,
                    vec![vec![Type::Integer, Type::Integer]],
                    Type::Integer,
                ),
            ),
            (
                "to_number",
                StaticValue::function(Self::to_number, vec![vec![Type::Boolean]], Type::Integer),
            ),
            (
                "abs",
                StaticValue::function(Self::abs, vec![vec![Type::Integer]], Type::Integer),
            ),
            (
                "count",
                StaticValue::function(
                    Self::count,
                    vec![
                        vec![Type::Integer, Type::Integer, Type::Integer],
                        vec![Type::Integer],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "percentage",
                StaticValue::function(
                    Self::percentage,
                    vec![
                        vec![Type::Integer, Type::Integer, Type::Integer],
                        vec![Type::Integer],
                    ],
                    Type::Float,
                ),
            ),
            (
                "mode",
                StaticValue::function(
                    Self::mode,
                    vec![vec![Type::Integer, Type::Integer], vec![]],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }
}

fn get_mem_slice<'a>(ctx: &ScanContext<'a>, offset: i64, length: i64) -> Option<&'a [u8]> {
    let start: usize = offset.try_into().ok()?;
    let end = start.checked_add(length.try_into().ok()?)?;
    let end = std::cmp::min(end, ctx.mem.len());

    ctx.mem.get(start..end)
}

impl Math {
    fn in_range(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let test: f64 = args.next()?.try_into().ok()?;
        let lower: f64 = args.next()?.try_into().ok()?;
        let upper: f64 = args.next()?.try_into().ok()?;

        Some(Value::Integer(i64::from(test >= lower && test <= upper)))
    }

    fn deviation(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let deviation = match args.next()? {
            Value::Bytes(bytes) => {
                let mean: f64 = args.next()?.try_into().ok()?;
                compute_deviation(&bytes, mean)
            }
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;
                let mean: f64 = args.next()?.try_into().ok()?;

                compute_deviation(get_mem_slice(ctx, offset, length)?, mean)
            }
            _ => return None,
        };

        Some(Value::Float(deviation))
    }

    fn mean(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let mean = match args.next()? {
            Value::Bytes(bytes) => compute_mean(&bytes),
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                compute_mean(get_mem_slice(ctx, offset, length)?)
            }
            _ => return None,
        };

        Some(Value::Float(mean))
    }

    fn serial_correlation(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let scc = match args.next()? {
            Value::Bytes(bytes) => compute_serial_correlation(&bytes),
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                compute_serial_correlation(get_mem_slice(ctx, offset, length)?)
            }
            _ => return None,
        };

        Some(Value::Float(scc))
    }

    fn monte_carlo_pi(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let mc = match args.next()? {
            Value::Bytes(bytes) => compute_monte_carlo_pi(&bytes),
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                compute_monte_carlo_pi(get_mem_slice(ctx, offset, length)?)
            }
            _ => return None,
        };

        mc.map(Value::Float)
    }

    fn entropy(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let entropy = match args.next()? {
            Value::Bytes(bytes) => compute_entropy(&bytes),
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;
                compute_entropy(get_mem_slice(ctx, offset, length)?)
            }
            _ => return None,
        };

        Some(Value::Float(entropy))
    }

    fn min(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let a: i64 = args.next()?.try_into().ok()?;
        let b: i64 = args.next()?.try_into().ok()?;

        // libyara cast those as u64, which can lead to very confusing behavior on negative
        // numbers...
        #[allow(clippy::cast_sign_loss)]
        {
            let a = a as u64;
            let b = b as u64;

            #[allow(clippy::cast_possible_wrap)]
            Some(if a < b {
                (a as i64).into()
            } else {
                (b as i64).into()
            })
        }
    }

    fn max(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let a: i64 = args.next()?.try_into().ok()?;
        let b: i64 = args.next()?.try_into().ok()?;

        // libyara cast those as u64, which can lead to very confusing behavior on negative
        // numbers...
        #[allow(clippy::cast_sign_loss)]
        {
            let a = a as u64;
            let b = b as u64;

            #[allow(clippy::cast_possible_wrap)]
            Some(if a > b {
                (a as i64).into()
            } else {
                (b as i64).into()
            })
        }
    }

    fn to_number(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v: bool = args.next()?.try_into().ok()?;

        Some(Value::Integer(v.into()))
    }

    fn abs(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v: i64 = args.next()?.try_into().ok()?;

        v.checked_abs().map(Value::Integer)
    }

    fn count(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let byte: i64 = args.next()?.try_into().ok()?;
        // libyara type cast this to a byte directly.
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        let byte: u8 = byte as u8;

        let dist = match (args.next(), args.next()) {
            (Some(Value::Integer(offset)), Some(Value::Integer(length))) => {
                distribution(get_mem_slice(ctx, offset, length)?)
            }
            (None, None) => distribution(ctx.mem),
            _ => return None,
        };

        dist.get(byte as usize)
            .and_then(|v| i64::try_from(*v).ok())
            .map(Value::Integer)
    }

    fn percentage(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let byte: i64 = args.next()?.try_into().ok()?;
        let byte: usize = byte.try_into().ok()?;

        let dist = match (args.next(), args.next()) {
            (Some(Value::Integer(offset)), Some(Value::Integer(length))) => {
                distribution(get_mem_slice(ctx, offset, length)?)
            }
            (None, None) => distribution(ctx.mem),
            _ => return None,
        };

        let count = dist.get(byte)?;
        let sum: u64 = dist.iter().sum();

        Some(Value::Float((*count as f64) / (sum as f64)))
    }

    fn mode(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();

        let dist = match (args.next(), args.next()) {
            (Some(Value::Integer(offset)), Some(Value::Integer(length))) => {
                distribution(get_mem_slice(ctx, offset, length)?)
            }
            (None, None) => distribution(ctx.mem),
            _ => return None,
        };

        // Find the index of the most common byte
        // Reverse to return the first index of the maximum value and not the last one.
        let most_common = dist.iter().enumerate().rev().max_by_key(|(_, n)| *n)?.0;
        most_common.try_into().ok().map(Value::Integer)
    }
}

fn compute_mean(bytes: &[u8]) -> f64 {
    let sum: u64 = bytes.iter().map(|v| u64::from(*v)).sum();

    (sum as f64) / (bytes.len() as f64)
}

fn compute_deviation(bytes: &[u8], mean: f64) -> f64 {
    let dist = distribution(bytes);
    let sum: f64 = dist
        .into_iter()
        .enumerate()
        .filter(|(_, n)| *n != 0)
        .map(|(c, n)| ((c as f64) - mean).abs() * (n as f64))
        .sum();

    sum / (bytes.len() as f64)
}

fn compute_entropy(bytes: &[u8]) -> f64 {
    let dist = distribution(bytes);

    let len = bytes.len() as f64;
    dist.into_iter()
        .filter(|n| *n != 0)
        .map(|n| {
            let x = (n as f64) / len;
            -(x * x.log2())
        })
        .sum()
}

fn compute_serial_correlation(bytes: &[u8]) -> f64 {
    // Algorithm can also be found here:
    // https://github.com/Fourmilab/ent_random_sequence_tester/blob/master/src/randtest.c
    //
    // Basically, for a sequence of bytes [a0, a1, ..., aN]:
    //
    // scct1 = sum(a0 * a1 + a1 * a2 + ... + a(N-1) * aN + aN * a0)
    // scct2 = sum(ax) ** 2
    // scct3 = sum(ax * ax)
    //
    // scc = (N*scct1 - scct2) / (N*scct3 - scct2)
    let mut scct1 = 0.0_f64;
    let mut scct2 = 0.0_f64;
    let mut scct3 = 0.0_f64;
    let mut prev = 0.0_f64;

    for c in bytes {
        let c = f64::from(*c);
        scct1 += prev * c;
        scct2 += c;
        scct3 += c * c;
        prev = c;
    }

    // Yes, this breaks the formula for len <= 2. But its how those implementations basically
    // handle this...
    if !bytes.is_empty() {
        scct1 += f64::from(u32::from(bytes[0]) * u32::from(bytes[bytes.len() - 1]));
    }
    scct2 *= scct2;

    let n = bytes.len() as f64;
    let scc = n * scct3 - scct2;
    if scc == 0.0 {
        -100_000.0
    } else {
        (n * scct1 - scct2) / scc
    }
}

fn compute_monte_carlo_pi(bytes: &[u8]) -> Option<f64> {
    // Algorithm can also be found here:
    // https://github.com/Fourmilab/ent_random_sequence_tester/blob/master/src/randtest.c
    //
    // As described here: <https://www.fourmilab.ch/random/>
    //
    // > Each successive sequence of six bytes is used as 24 bit X and Y co-ordinates within a
    // > square. If the distance of the randomly-generated point is less than the radius of a
    // > circle inscribed within the square, the six-byte sequence is considered a “hit”. The
    // > percentage of hits can be used to calculate the value of Pi. For very large streams
    // > (this approximation converges very slowly), the value will approach the correct value of
    // > Pi if the sequence is close to random.
    use std::f64::consts::PI;

    const MONTEN: usize = 6;
    const MONTEN_HALF: i32 = 3;

    let incirc: f64 = (256.0_f64.powi(MONTEN_HALF) - 1.0).powi(2);

    let mut inmount = 0_u32;
    let mut mcount = 0_u32;

    for w in bytes.chunks_exact(MONTEN) {
        let mut mx = 0.0_f64;
        let mut my = 0.0_f64;

        for j in 0..(MONTEN / 2) {
            mx = (mx * 256.0) + f64::from(w[j]);
            my = (my * 256.0) + f64::from(w[j + MONTEN / 2]);
        }

        mcount += 1;
        if (mx * mx + my * my) <= incirc {
            inmount += 1;
        }
    }

    if mcount == 0 {
        None
    } else {
        let mpi = 4.0 * f64::from(inmount) / f64::from(mcount);
        Some(((mpi - PI) / PI).abs())
    }
}

#[inline]
fn distribution(bytes: &[u8]) -> [u64; 256] {
    let mut counters = [0u64; 256];

    for b in bytes {
        counters[*b as usize] += 1;
    }

    counters
}

#[cfg(test)]
mod tests {
    use crate::module::ModuleDataMap;

    use super::*;

    fn build_ctx() -> ScanContext<'static> {
        ScanContext {
            mem: b"",
            module_data: ModuleDataMap::default(),
        }
    }

    #[test]
    fn test_in_range_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::in_range(&ctx, vec![]).is_none());
        assert!(Math::in_range(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::in_range(&ctx, vec![0.5.into(), 0.5.into()]).is_none());
        assert!(Math::in_range(&ctx, vec![0.into()]).is_none());
        assert!(Math::in_range(&ctx, vec![0.5.into(), 0.into()]).is_none());
        assert!(Math::in_range(&ctx, vec![0.5.into(), 0.5.into(), 0.into()]).is_none());
    }

    #[test]
    fn test_deviation_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::deviation(&ctx, vec![]).is_none());
        assert!(Math::deviation(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::deviation(&ctx, vec![b"".to_vec().into()]).is_none());
        assert!(Math::deviation(&ctx, vec![b"".to_vec().into(), 0.into()]).is_none());
        assert!(Math::deviation(&ctx, vec![0.into()]).is_none());
        assert!(Math::deviation(&ctx, vec![0.into(), 0.into()]).is_none());
        assert!(Math::deviation(&ctx, vec![0.into(), 0.5.into()]).is_none());
        assert!(Math::deviation(&ctx, vec![0.into(), 0.into(), 0.into()]).is_none());
    }

    #[test]
    fn test_mean_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::mean(&ctx, vec![]).is_none());
        assert!(Math::mean(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::mean(&ctx, vec![0.into()]).is_none());
        assert!(Math::mean(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_serial_correlation_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::serial_correlation(&ctx, vec![]).is_none());
        assert!(Math::serial_correlation(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::serial_correlation(&ctx, vec![0.into()]).is_none());
        assert!(Math::serial_correlation(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_monte_carlo_pi_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::monte_carlo_pi(&ctx, vec![]).is_none());
        assert!(Math::monte_carlo_pi(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::monte_carlo_pi(&ctx, vec![0.into()]).is_none());
        assert!(Math::monte_carlo_pi(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_entropy_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::entropy(&ctx, vec![]).is_none());
        assert!(Math::entropy(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::entropy(&ctx, vec![0.into()]).is_none());
        assert!(Math::entropy(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_min_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::min(&ctx, vec![]).is_none());
        assert!(Math::min(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::min(&ctx, vec![0.into()]).is_none());
        assert!(Math::min(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_max_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::max(&ctx, vec![]).is_none());
        assert!(Math::max(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::max(&ctx, vec![0.into()]).is_none());
        assert!(Math::max(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_to_number_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::to_number(&ctx, vec![]).is_none());
        assert!(Math::to_number(&ctx, vec![0.into()]).is_none());
    }

    #[test]
    fn test_abs_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::abs(&ctx, vec![]).is_none());
        assert!(Math::abs(&ctx, vec![0.5.into()]).is_none());
    }

    #[test]
    fn test_count_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::count(&ctx, vec![]).is_none());
        assert!(Math::count(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::count(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_percentage_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::percentage(&ctx, vec![]).is_none());
        assert!(Math::percentage(&ctx, vec![0.5.into()]).is_none());
        assert!(Math::percentage(&ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_mode_invalid_args() {
        let ctx = build_ctx();

        assert!(Math::mode(&ctx, vec![0.5.into()]).is_none());
    }
}
