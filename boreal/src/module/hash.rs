use std::collections::HashMap;
use std::sync::RwLock;

use super::{EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Type, Value};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

/// `hash` module. Exposes functions to compute hashes and checksums.
#[derive(Debug)]
pub struct Hash;

impl Module for Hash {
    fn get_name(&self) -> &'static str {
        "hash"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "md5",
                StaticValue::function(
                    Self::md5,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Bytes,
                ),
            ),
            (
                "sha1",
                StaticValue::function(
                    Self::sha1,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Bytes,
                ),
            ),
            (
                "sha256",
                StaticValue::function(
                    Self::sha2,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Bytes,
                ),
            ),
            (
                "checksum32",
                StaticValue::function(
                    Self::checksum32,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Integer,
                ),
            ),
            (
                "crc32",
                StaticValue::function(
                    Self::crc32,
                    vec![vec![Type::Integer, Type::Integer], vec![Type::Bytes]],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        data_map.insert::<Self>(Data::default());
    }
}

#[derive(Default)]
pub struct Data {
    cache: RwLock<Cache>,
}

#[derive(Default)]
pub struct Cache {
    md5: HashMap<(usize, usize), Value>,
    sha1: HashMap<(usize, usize), Value>,
    sha256: HashMap<(usize, usize), Value>,
}

impl ModuleData for Hash {
    type Data = Data;
}

fn compute_hash<D: Digest>(bytes: &[u8]) -> Value {
    Value::bytes(hex::encode(D::digest(bytes)))
}

impl Hash {
    fn md5(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        match get_args(args)? {
            Args::Bytes(s) => Some(compute_hash::<Md5>(&s)),
            Args::Range(offset, end) => {
                let data = ctx.module_data.get::<Hash>()?;

                {
                    if let Some(v) = data.cache.read().ok()?.md5.get(&(offset, end)) {
                        return Some(v.clone());
                    }
                }

                let hash = compute_hash::<Md5>(ctx.mem.get(offset, end)?);
                let _r = data
                    .cache
                    .write()
                    .ok()?
                    .md5
                    .insert((offset, end), hash.clone());
                Some(hash)
            }
        }
    }

    fn sha1(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        match get_args(args)? {
            Args::Bytes(s) => Some(compute_hash::<Sha1>(&s)),
            Args::Range(offset, end) => {
                let data = ctx.module_data.get::<Hash>()?;

                {
                    if let Some(v) = data.cache.read().ok()?.sha1.get(&(offset, end)) {
                        return Some(v.clone());
                    }
                }

                let hash = compute_hash::<Sha1>(ctx.mem.get(offset, end)?);
                let _r = data
                    .cache
                    .write()
                    .ok()?
                    .sha1
                    .insert((offset, end), hash.clone());
                Some(hash)
            }
        }
    }

    fn sha2(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        match get_args(args)? {
            Args::Bytes(s) => Some(compute_hash::<Sha256>(&s)),
            Args::Range(offset, end) => {
                let data = ctx.module_data.get::<Hash>()?;

                {
                    if let Some(v) = data.cache.read().ok()?.sha256.get(&(offset, end)) {
                        return Some(v.clone());
                    }
                }

                let hash = compute_hash::<Sha256>(ctx.mem.get(offset, end)?);
                let _r = data
                    .cache
                    .write()
                    .ok()?
                    .sha256
                    .insert((offset, end), hash.clone());
                Some(hash)
            }
        }
    }

    fn checksum32(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| {
            let checksum = s
                .iter()
                .fold(0u32, |acc, byte| acc.wrapping_add(u32::from(*byte)));
            Value::Integer(i64::from(checksum))
        })
    }

    fn crc32(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        apply(ctx, args, |s| {
            let crc = crc32fast::hash(s);
            Value::Integer(i64::from(crc))
        })
    }
}

enum Args {
    Bytes(Vec<u8>),
    Range(usize, usize),
}

fn get_args(args: Vec<Value>) -> Option<Args> {
    let mut args = args.into_iter();
    let v = args.next()?;

    match v {
        Value::Bytes(s) => Some(Args::Bytes(s)),
        Value::Integer(offset) => {
            let length = i64::try_from(args.next()?).ok()?;
            match (usize::try_from(offset), usize::try_from(length)) {
                (Ok(offset), Ok(length)) => {
                    let end = offset.checked_add(length)?;
                    Some(Args::Range(offset, end))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn apply<F>(ctx: &mut EvalContext, args: Vec<Value>, fun: F) -> Option<Value>
where
    F: FnOnce(&[u8]) -> Value,
{
    match get_args(args)? {
        Args::Bytes(s) => Some(fun(&s)),
        Args::Range(offset, end) => Some(fun(ctx.mem.get(offset, end)?)),
    }
}
