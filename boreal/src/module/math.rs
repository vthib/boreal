use std::collections::HashMap;

use super::{EvalContext, Module, StaticValue, Type, Value};

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
            (
                "to_string",
                StaticValue::function(
                    Self::to_string,
                    vec![vec![Type::Integer], vec![Type::Integer, Type::Integer]],
                    Type::Bytes,
                ),
            ),
        ]
        .into()
    }
}

impl Math {
    fn in_range(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let test: f64 = args.next()?.try_into().ok()?;
        let lower: f64 = args.next()?.try_into().ok()?;
        let upper: f64 = args.next()?.try_into().ok()?;

        Some(Value::Integer(i64::from(test >= lower && test <= upper)))
    }

    fn deviation(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let deviation = match args.next()? {
            Value::Bytes(bytes) => {
                let mean: f64 = args.next()?.try_into().ok()?;
                compute_deviation(distribution_from_bytes(&bytes), mean)
            }
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;
                let mean: f64 = args.next()?.try_into().ok()?;

                let start: usize = offset.try_into().ok()?;
                let length: usize = length.try_into().ok()?;
                compute_deviation(distribution(ctx, start, length)?, mean)
            }
            _ => return None,
        };

        Some(Value::Float(deviation))
    }

    fn mean(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let mean = match args.next()? {
            Value::Bytes(bytes) => compute_from_bytes(&bytes, Mean::new())?,
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                compute_from_mem(ctx, offset, length, Mean::new())?
            }
            _ => return None,
        };

        Some(Value::Float(mean))
    }

    fn serial_correlation(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let scc = match args.next()? {
            Value::Bytes(bytes) => compute_from_bytes(&bytes, SerialCorrelation::new())?,
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                compute_from_mem(ctx, offset, length, SerialCorrelation::new())?
            }
            _ => return None,
        };

        Some(Value::Float(scc))
    }

    fn monte_carlo_pi(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let mc = match args.next()? {
            Value::Bytes(bytes) => compute_from_bytes(&bytes, MonteCarloPi::new())?,
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                compute_from_mem(ctx, offset, length, MonteCarloPi::new())?
            }
            _ => return None,
        };

        Some(Value::Float(mc))
    }

    fn entropy(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let distribution = match args.next()? {
            Value::Bytes(bytes) => distribution_from_bytes(&bytes),
            Value::Integer(offset) => {
                let length: i64 = args.next()?.try_into().ok()?;

                let start: usize = offset.try_into().ok()?;
                let length: usize = length.try_into().ok()?;
                distribution(ctx, start, length)?
            }
            _ => return None,
        };

        Some(Value::Float(compute_entropy(distribution)))
    }

    fn min(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
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

    fn max(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
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

    fn to_number(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v: bool = args.next()?.try_into().ok()?;

        Some(Value::Integer(v.into()))
    }

    fn abs(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v: i64 = args.next()?.try_into().ok()?;

        v.checked_abs().map(Value::Integer)
    }

    fn count(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let byte: i64 = args.next()?.try_into().ok()?;
        let byte: usize = byte.try_into().ok()?;

        let dist = match (args.next(), args.next()) {
            (Some(Value::Integer(offset)), Some(Value::Integer(length))) => {
                let start: usize = offset.try_into().ok()?;
                let length: usize = length.try_into().ok()?;
                distribution(ctx, start, length)?
            }
            (None, None) => distribution_from_bytes(ctx.mem.get_direct()?),
            _ => return None,
        };

        dist.counters
            .get(byte)
            .and_then(|v| i64::try_from(*v).ok())
            .map(Value::Integer)
    }

    fn percentage(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let byte: i64 = args.next()?.try_into().ok()?;
        let byte: usize = byte.try_into().ok()?;

        let dist = match (args.next(), args.next()) {
            (Some(Value::Integer(offset)), Some(Value::Integer(length))) => {
                let start: usize = offset.try_into().ok()?;
                let length: usize = length.try_into().ok()?;
                distribution(ctx, start, length)?
            }
            (None, None) => distribution_from_bytes(ctx.mem.get_direct()?),
            _ => return None,
        };

        let count = dist.counters.get(byte)?;

        Some(Value::Float((*count as f64) / (dist.nb_values as f64)))
    }

    fn mode(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();

        let dist = match (args.next(), args.next()) {
            (Some(Value::Integer(offset)), Some(Value::Integer(length))) => {
                let start: usize = offset.try_into().ok()?;
                let length: usize = length.try_into().ok()?;
                distribution(ctx, start, length)?
            }
            (None, None) => distribution_from_bytes(ctx.mem.get_direct()?),
            _ => return None,
        };

        // Find the index of the most common byte
        // Reverse to return the first index of the maximum value and not the last one.
        let most_common = dist
            .counters
            .iter()
            .enumerate()
            .rev()
            .max_by_key(|(_, n)| *n)?
            .0;
        most_common.try_into().ok().map(Value::Integer)
    }

    fn to_string(_ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let value: i64 = args.next()?.try_into().ok()?;
        let base: Option<i64> = match args.next() {
            Some(v) => Some(v.try_into().ok()?),
            None => None,
        };

        let s = match base {
            Some(10) | None => format!("{value}"),
            Some(16) => format!("{value:x}"),
            Some(8) => format!("{value:o}"),
            _ => return None,
        };

        Some(Value::Bytes(s.into_bytes()))
    }
}

trait MathDigest {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Option<f64>;
}

struct Mean {
    sum: u64,
    nb: usize,
}

impl Mean {
    fn new() -> Self {
        Self { sum: 0, nb: 0 }
    }
}

impl MathDigest for Mean {
    fn update(&mut self, data: &[u8]) {
        for b in data {
            self.sum = self.sum.saturating_add(u64::from(*b));
        }
        self.nb = self.nb.saturating_add(data.len());
    }

    fn finalize(self) -> Option<f64> {
        Some((self.sum as f64) / (self.nb as f64))
    }
}

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
struct SerialCorrelation {
    scct1: f64,
    scct2: f64,
    scct3: f64,
    prev: f64,
    first: u8,
    first_range: bool,
    last: u8,
    nb_values: usize,
}

impl SerialCorrelation {
    fn new() -> Self {
        Self {
            scct1: 0.0,
            scct2: 0.0,
            scct3: 0.0,
            prev: 0.0,
            first: 0,
            first_range: true,
            last: 0,
            nb_values: 0,
        }
    }
}

impl MathDigest for SerialCorrelation {
    fn update(&mut self, data: &[u8]) {
        if !data.is_empty() {
            if self.first_range {
                self.first_range = false;
                self.first = data[0];
            }
            self.last = data[data.len() - 1];
        }
        for c in data {
            let c = f64::from(*c);
            self.scct1 += self.prev * c;
            self.scct2 += c;
            self.scct3 += c * c;
            self.prev = c;
        }
        self.nb_values += data.len();
    }

    fn finalize(mut self) -> Option<f64> {
        // Yes, this breaks the formula for len <= 2. But its how those implementations basically
        // handle this...
        if self.nb_values > 0 {
            self.scct1 += f64::from(u32::from(self.first) * u32::from(self.last));
        }
        self.scct2 *= self.scct2;

        let n = self.nb_values as f64;
        let scc = n * self.scct3 - self.scct2;
        Some(if scc == 0.0 {
            -100_000.0
        } else {
            (n * self.scct1 - self.scct2) / scc
        })
    }
}

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
struct MonteCarloPi {
    inmount: u32,
    mcount: u32,
    incirc: f64,
}

const MONTEN: usize = 6;
const MONTEN_HALF: i32 = 3;

impl MonteCarloPi {
    fn new() -> Self {
        Self {
            inmount: 0,
            mcount: 0,
            incirc: (256.0_f64.powi(MONTEN_HALF) - 1.0).powi(2),
        }
    }
}

impl MathDigest for MonteCarloPi {
    fn update(&mut self, data: &[u8]) {
        for w in data.chunks_exact(MONTEN) {
            let mut mx = 0.0_f64;
            let mut my = 0.0_f64;

            for j in 0..(MONTEN / 2) {
                mx = (mx * 256.0) + f64::from(w[j]);
                my = (my * 256.0) + f64::from(w[j + MONTEN / 2]);
            }

            self.mcount += 1;
            if (mx * mx + my * my) <= self.incirc {
                self.inmount += 1;
            }
        }
    }

    fn finalize(self) -> Option<f64> {
        use std::f64::consts::PI;

        if self.mcount == 0 {
            None
        } else {
            let mpi = 4.0 * f64::from(self.inmount) / f64::from(self.mcount);
            Some(((mpi - PI) / PI).abs())
        }
    }
}

fn compute_from_bytes<T: MathDigest>(data: &[u8], mut digest: T) -> Option<f64> {
    digest.update(data);
    digest.finalize()
}

fn compute_from_mem<T: MathDigest>(
    ctx: &mut EvalContext,
    offset: i64,
    length: i64,
    mut digest: T,
) -> Option<f64> {
    let (start, end) = offset_length_to_start_end(offset, length)?;
    ctx.mem.on_range(start, end, |data| digest.update(data))?;
    digest.finalize()
}

fn compute_deviation(distribution: Distribution, mean: f64) -> f64 {
    let Distribution {
        counters,
        nb_values,
    } = distribution;
    let sum: f64 = counters
        .into_iter()
        .enumerate()
        .filter(|(_, n)| *n != 0)
        .map(|(c, n)| ((c as f64) - mean).abs() * (n as f64))
        .sum();

    sum / (nb_values as f64)
}

fn compute_entropy(distribution: Distribution) -> f64 {
    let Distribution {
        counters,
        nb_values,
    } = distribution;

    let nb_values = nb_values as f64;
    counters
        .into_iter()
        .filter(|n| *n != 0)
        .map(|n| {
            let x = (n as f64) / nb_values;
            -(x * x.log2())
        })
        .sum()
}

struct Distribution {
    counters: Vec<u64>,
    nb_values: usize,
}

fn distribution(ctx: &mut EvalContext, start: usize, length: usize) -> Option<Distribution> {
    let mut distrib = Distribution {
        counters: vec![0u64; 256],
        nb_values: 0,
    };

    let end = start.checked_add(length)?;
    ctx.mem.on_range(start, end, |bytes| {
        for b in bytes {
            distrib.counters[*b as usize] += 1;
        }
        distrib.nb_values += bytes.len();
    })?;

    Some(distrib)
}

#[inline]
fn distribution_from_bytes(bytes: &[u8]) -> Distribution {
    let mut distrib = Distribution {
        counters: vec![0u64; 256],
        nb_values: bytes.len(),
    };

    for b in bytes {
        distrib.counters[*b as usize] += 1;
    }

    distrib
}

fn offset_length_to_start_end(offset: i64, length: i64) -> Option<(usize, usize)> {
    let start: usize = offset.try_into().ok()?;
    let length: usize = length.try_into().ok()?;
    let end = start.checked_add(length)?;
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use crate::memory::Memory;
    use crate::module::{ModuleDataMap, ModuleUserData};

    use super::*;

    macro_rules! ctx {
        ($v:expr) => {
            EvalContext {
                mem: &mut Memory::Direct(b""),
                module_data: &ModuleDataMap::new($v),
                process_memory: false,
            }
        };
    }

    #[test]
    fn test_in_range_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::in_range(&mut ctx, vec![]).is_none());
        assert!(Math::in_range(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::in_range(&mut ctx, vec![0.5.into(), 0.5.into()]).is_none());
        assert!(Math::in_range(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::in_range(&mut ctx, vec![0.5.into(), 0.into()]).is_none());
        assert!(Math::in_range(&mut ctx, vec![0.5.into(), 0.5.into(), 0.into()]).is_none());
    }

    #[test]
    fn test_deviation_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::deviation(&mut ctx, vec![]).is_none());
        assert!(Math::deviation(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::deviation(&mut ctx, vec![b"".to_vec().into()]).is_none());
        assert!(Math::deviation(&mut ctx, vec![b"".to_vec().into(), 0.into()]).is_none());
        assert!(Math::deviation(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::deviation(&mut ctx, vec![0.into(), 0.into()]).is_none());
        assert!(Math::deviation(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
        assert!(Math::deviation(&mut ctx, vec![0.into(), 0.into(), 0.into()]).is_none());
    }

    #[test]
    fn test_mean_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::mean(&mut ctx, vec![]).is_none());
        assert!(Math::mean(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::mean(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::mean(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_serial_correlation_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::serial_correlation(&mut ctx, vec![]).is_none());
        assert!(Math::serial_correlation(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::serial_correlation(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::serial_correlation(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_monte_carlo_pi_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::monte_carlo_pi(&mut ctx, vec![]).is_none());
        assert!(Math::monte_carlo_pi(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::monte_carlo_pi(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::monte_carlo_pi(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_entropy_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::entropy(&mut ctx, vec![]).is_none());
        assert!(Math::entropy(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::entropy(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::entropy(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_min_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::min(&mut ctx, vec![]).is_none());
        assert!(Math::min(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::min(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::min(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_max_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::max(&mut ctx, vec![]).is_none());
        assert!(Math::max(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::max(&mut ctx, vec![0.into()]).is_none());
        assert!(Math::max(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_to_number_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::to_number(&mut ctx, vec![]).is_none());
        assert!(Math::to_number(&mut ctx, vec![0.into()]).is_none());
    }

    #[test]
    fn test_abs_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::abs(&mut ctx, vec![]).is_none());
        assert!(Math::abs(&mut ctx, vec![0.5.into()]).is_none());
    }

    #[test]
    fn test_count_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::count(&mut ctx, vec![]).is_none());
        assert!(Math::count(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::count(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_percentage_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::percentage(&mut ctx, vec![]).is_none());
        assert!(Math::percentage(&mut ctx, vec![0.5.into()]).is_none());
        assert!(Math::percentage(&mut ctx, vec![0.into(), 0.5.into()]).is_none());
    }

    #[test]
    fn test_mode_invalid_args() {
        let user_data = ModuleUserData::default();
        let mut ctx = ctx!(&user_data);

        assert!(Math::mode(&mut ctx, vec![0.5.into()]).is_none());
    }
}
