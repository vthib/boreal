use std::{collections::HashMap, sync::RwLock};

use magic::cookie::{Cookie, DatabasePaths, Flags};

use super::{EvalContext, Module, ModuleData, ModuleDataMap, StaticValue, Type, Value};

/// `magic` module.
#[derive(Debug)]
pub struct Magic;

impl Module for Magic {
    fn get_name(&self) -> &'static str {
        "magic"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            (
                "mime_type",
                StaticValue::function(Self::get_mime_type, vec![], Type::Bytes),
            ),
            (
                "type",
                StaticValue::function(Self::get_type, vec![], Type::Bytes),
            ),
        ]
        .into()
    }

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        data_map.insert::<Self>(Data {
            cache: RwLock::new(Cache {
                magic_mime_type: CacheEntry::NotComputed,
                magic_type: CacheEntry::NotComputed,
            }),
        });
    }
}

pub struct Data {
    cache: RwLock<Cache>,
}

pub struct Cache {
    magic_mime_type: CacheEntry,
    magic_type: CacheEntry,
}

pub enum CacheEntry {
    NotComputed,
    Computed(Option<Value>),
}

impl ModuleData for Magic {
    type PrivateData = Data;
    type UserData = ();
}

impl Magic {
    fn get_mime_type(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Self>()?;

        {
            let cache = data.cache.read().ok()?;
            if let CacheEntry::Computed(v) = &cache.magic_mime_type {
                return v.clone();
            }
        }

        let res = get_magic_value(ctx, Flags::MIME_TYPE);
        data.cache.write().ok()?.magic_mime_type = CacheEntry::Computed(res.clone());
        res
    }

    fn get_type(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Self>()?;

        {
            let cache = data.cache.read().ok()?;
            if let CacheEntry::Computed(v) = &cache.magic_type {
                return v.clone();
            }
        }

        let res = get_magic_value(ctx, Flags::default());
        data.cache.write().ok()?.magic_type = CacheEntry::Computed(res.clone());
        res
    }
}

fn get_magic_value(ctx: &EvalContext, flags: Flags) -> Option<Value> {
    let cookie = Cookie::open(flags).ok()?;
    let cookie = cookie.load(&DatabasePaths::default()).ok()?;

    let mem = ctx.mem.get_direct()?;
    let mime_type = cookie.buffer(mem).ok()?;

    Some(Value::Bytes(mime_type.into_bytes()))
}
