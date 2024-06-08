use std::collections::HashMap;
use std::sync::RwLock;

use super::{hex_encode, EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Type, Value};
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
    type PrivateData = Data;
    type UserData = ();
}

fn compute_hash_from_bytes<D: Digest>(bytes: &[u8]) -> Value {
    Value::Bytes(hex_encode(D::digest(bytes)))
}

fn compute_hash_from_mem<D: Digest>(
    ctx: &mut EvalContext,
    offset: usize,
    end: usize,
) -> Option<Value> {
    let mut digest = D::new();

    ctx.mem.on_range(offset, end, |data| digest.update(data))?;
    Some(Value::Bytes(hex_encode(digest.finalize())))
}

impl Hash {
    fn md5(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        match get_args(args)? {
            Args::Bytes(s) => Some(compute_hash_from_bytes::<Md5>(&s)),
            Args::Range(offset, end) => {
                let data = ctx.module_data.get::<Hash>()?;

                {
                    if let Some(v) = data.cache.read().ok()?.md5.get(&(offset, end)) {
                        return Some(v.clone());
                    }
                }

                let hash = compute_hash_from_mem::<Md5>(ctx, offset, end)?;
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
            Args::Bytes(s) => Some(compute_hash_from_bytes::<Sha1>(&s)),
            Args::Range(offset, end) => {
                let data = ctx.module_data.get::<Hash>()?;

                {
                    if let Some(v) = data.cache.read().ok()?.sha1.get(&(offset, end)) {
                        return Some(v.clone());
                    }
                }

                let hash = compute_hash_from_mem::<Sha1>(ctx, offset, end)?;
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
            Args::Bytes(s) => Some(compute_hash_from_bytes::<Sha256>(&s)),
            Args::Range(offset, end) => {
                let data = ctx.module_data.get::<Hash>()?;

                {
                    if let Some(v) = data.cache.read().ok()?.sha256.get(&(offset, end)) {
                        return Some(v.clone());
                    }
                }

                let hash = compute_hash_from_mem::<Sha256>(ctx, offset, end)?;
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
        let mut checksum: u32 = 0;
        match get_args(args)? {
            Args::Bytes(s) => {
                for b in s {
                    checksum = checksum.wrapping_add(u32::from(b));
                }
            }
            Args::Range(offset, end) => {
                ctx.mem.on_range(offset, end, |data| {
                    for b in data {
                        checksum = checksum.wrapping_add(u32::from(*b));
                    }
                })?;
            }
        }
        Some(Value::Integer(i64::from(checksum)))
    }

    fn crc32(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        match get_args(args)? {
            Args::Bytes(s) => {
                let crc = crc32fast::hash(&s);
                Some(Value::Integer(i64::from(crc)))
            }
            Args::Range(offset, end) => {
                let mut hasher = crc32fast::Hasher::new();
                ctx.mem.on_range(offset, end, |data| hasher.update(data))?;
                Some(Value::Integer(i64::from(hasher.finalize())))
            }
        }
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
