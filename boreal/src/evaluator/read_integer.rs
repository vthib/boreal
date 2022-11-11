//! Provides methods to evaluate the read integer expressions
use crate::compiler::expression::Expression;
use boreal_parser::ReadIntegerType;

use super::{Evaluator, Value};

macro_rules! read {
    ($ty:ty, $slice:expr, $fun:expr) => {{
        let size = std::mem::size_of::<$ty>();
        if size > $slice.len() {
            None
        } else {
            let (int_bytes, _) = $slice.split_at(size);
            int_bytes.try_into().ok().map(|v| $fun(v) as i64)
        }
    }};
}

macro_rules! read_le {
    ($ty:ty, $slice:expr) => {
        read!($ty, $slice, <$ty>::from_le_bytes)
    };
}

macro_rules! read_be {
    ($ty:ty, $slice:expr) => {
        read!($ty, $slice, <$ty>::from_be_bytes)
    };
}

pub(super) fn evaluate_read_integer(
    evaluator: &mut Evaluator,
    addr: &Expression,
    ty: ReadIntegerType,
) -> Option<Value> {
    let addr = evaluator.evaluate_expr(addr)?.unwrap_number()?;

    let addr = usize::try_from(addr).ok()?;
    if addr >= evaluator.mem.len() {
        return None;
    }
    let mem = &evaluator.mem[addr..];

    let v = match ty {
        ReadIntegerType::Int8 => read_le!(i8, mem),
        ReadIntegerType::Uint8 => read_le!(u8, mem),
        ReadIntegerType::Int16 => read_le!(i16, mem),
        ReadIntegerType::Uint16 => read_le!(u16, mem),
        ReadIntegerType::Int32 => read_le!(i32, mem),
        ReadIntegerType::Uint32 => read_le!(u32, mem),

        ReadIntegerType::Int16BE => read_be!(i16, mem),
        ReadIntegerType::Uint16BE => read_be!(u16, mem),
        ReadIntegerType::Int32BE => read_be!(i32, mem),
        ReadIntegerType::Uint32BE => read_be!(u32, mem),
    }?;
    Some(Value::Integer(v))
}
