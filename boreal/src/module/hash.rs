use std::collections::HashMap;

use super::{Module, ScanContext, StaticValue, Type, Value};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

/// `hash` module. Exposes functions to compute hashes and checksums.
#[derive(Debug)]
pub struct Hash;

// TODO: yara has a cache for computed hashes. To be investigated if needed.

impl Module for Hash {
    fn get_name(&self) -> String {
        "hash".to_owned()
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "md5",
                StaticValue::function(
                    Self::md5,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::String]],
                    Type::String,
                ),
            ),
            (
                "sha1",
                StaticValue::function(
                    Self::sha1,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::String]],
                    Type::String,
                ),
            ),
            (
                "sha256",
                StaticValue::function(
                    Self::sha2,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::String]],
                    Type::String,
                ),
            ),
            (
                "checksum32",
                StaticValue::function(
                    Self::checksum32,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::String]],
                    Type::Integer,
                ),
            ),
            (
                "crc32",
                StaticValue::function(
                    Self::crc32,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::String]],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }
}

impl Hash {
    fn md5(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| Value::String(hex::encode(Md5::digest(s))))
    }

    fn sha1(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| Value::String(hex::encode(Sha1::digest(s))))
    }

    fn sha2(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| Value::String(hex::encode(Sha256::digest(s))))
    }

    fn checksum32(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| {
            let checksum = s
                .iter()
                .fold(0u32, |acc, byte| acc.wrapping_add(u32::from(*byte)));
            Value::Integer(i64::from(checksum))
        })
    }

    fn crc32(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| {
            let crc = crc32fast::hash(s);
            Value::Integer(i64::from(crc))
        })
    }
}

fn apply<F>(ctx: &ScanContext, args: Vec<Value>, fun: F) -> Option<Value>
where
    F: FnOnce(&[u8]) -> Value,
{
    let mut args = args.into_iter();
    let v = args.next()?;
    match v {
        Value::String(s) => Some(fun(s.as_bytes())),
        Value::Integer(offset) => {
            let length = i64::try_from(args.next()?).ok()?;
            match (usize::try_from(offset), usize::try_from(length)) {
                (Ok(offset), _) if offset >= ctx.mem.len() => None,
                (Ok(offset), Ok(length)) => {
                    let end = std::cmp::min(offset + length, ctx.mem.len());
                    Some(fun(&ctx.mem[offset..end]))
                }
                _ => None,
            }
        }
        _ => None,
    }
}
