//! Provides methods to evaluate the read integer expressions
use crate::compiler::expression::Expression;
use boreal_parser::expression::ReadIntegerType;

use super::{Evaluator, PoisonKind, Value};

pub(super) fn evaluate_read_integer(
    evaluator: &mut Evaluator,
    addr: &Expression,
    ty: ReadIntegerType,
) -> Result<Value, PoisonKind> {
    let addr = evaluator.evaluate_expr(addr)?.unwrap_number()?;
    let addr = usize::try_from(addr).map_err(|_| PoisonKind::Undefined)?;

    let length = match ty {
        ReadIntegerType::Int8 | ReadIntegerType::Uint8 => 1,
        ReadIntegerType::Int16
        | ReadIntegerType::Uint16
        | ReadIntegerType::Int16BE
        | ReadIntegerType::Uint16BE => 2,
        ReadIntegerType::Int32
        | ReadIntegerType::Uint32
        | ReadIntegerType::Int32BE
        | ReadIntegerType::Uint32BE => 4,
    };

    let mem = addr
        .checked_add(length)
        .and_then(|end| evaluator.mem.get_contiguous(addr, end))
        .ok_or(PoisonKind::Undefined)?;

    match ty {
        ReadIntegerType::Int8 => mem.try_into().map(i8::from_le_bytes).map(i64::from),
        ReadIntegerType::Uint8 => mem.try_into().map(u8::from_le_bytes).map(i64::from),
        ReadIntegerType::Int16 => mem.try_into().map(i16::from_le_bytes).map(i64::from),
        ReadIntegerType::Uint16 => mem.try_into().map(u16::from_le_bytes).map(i64::from),
        ReadIntegerType::Int32 => mem.try_into().map(i32::from_le_bytes).map(i64::from),
        ReadIntegerType::Uint32 => mem.try_into().map(u32::from_le_bytes).map(i64::from),

        ReadIntegerType::Int16BE => mem.try_into().map(i16::from_be_bytes).map(i64::from),
        ReadIntegerType::Uint16BE => mem.try_into().map(u16::from_be_bytes).map(i64::from),
        ReadIntegerType::Int32BE => mem.try_into().map(i32::from_be_bytes).map(i64::from),
        ReadIntegerType::Uint32BE => mem.try_into().map(u32::from_be_bytes).map(i64::from),
    }
    .map(Value::Integer)
    .map_err(|_| PoisonKind::Undefined)
}
