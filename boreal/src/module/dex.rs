use std::collections::HashMap;

use object::{Bytes, LittleEndian as LE, Pod, U16, U32};

use super::{
    EvalContext, Module, ModuleData, ModuleDataMap, ScanContext, StaticValue, Type, Value,
};

const DEX_FILE_MAGIC_035: &[u8] = b"dex\n035\0";
const DEX_FILE_MAGIC_036: &[u8] = b"dex\n036\0";
const DEX_FILE_MAGIC_037: &[u8] = b"dex\n037\0";
const DEX_FILE_MAGIC_038: &[u8] = b"dex\n038\0";
const DEX_FILE_MAGIC_039: &[u8] = b"dex\n039\0";

/// `dex` module. Allows inspecting dalvik binaries
#[derive(Debug)]
pub struct Dex;

impl Module for Dex {
    fn get_name(&self) -> &'static str {
        "dex"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            ("DEX_FILE_MAGIC_035", StaticValue::bytes(DEX_FILE_MAGIC_035)),
            ("DEX_FILE_MAGIC_036", StaticValue::bytes(DEX_FILE_MAGIC_036)),
            ("DEX_FILE_MAGIC_037", StaticValue::bytes(DEX_FILE_MAGIC_037)),
            ("DEX_FILE_MAGIC_038", StaticValue::bytes(DEX_FILE_MAGIC_038)),
            ("DEX_FILE_MAGIC_039", StaticValue::bytes(DEX_FILE_MAGIC_039)),
            ("ENDIAN_CONSTANT", StaticValue::Integer(0x1234_5678)),
            ("REVERSE_ENDIAN_CONSTANT", StaticValue::Integer(0x7856_3412)),
            ("NO_INDEX", StaticValue::Integer(0xffff_ffff)),
            ("ACC_PUBLIC", StaticValue::Integer(0x1)),
            ("ACC_PRIVATE", StaticValue::Integer(0x2)),
            ("ACC_PROTECTED", StaticValue::Integer(0x4)),
            ("ACC_STATIC", StaticValue::Integer(0x8)),
            ("ACC_FINAL", StaticValue::Integer(0x10)),
            ("ACC_SYNCHRONIZED", StaticValue::Integer(0x20)),
            ("ACC_VOLATILE", StaticValue::Integer(0x40)),
            ("ACC_BRIDGE", StaticValue::Integer(0x40)),
            ("ACC_TRANSIENT", StaticValue::Integer(0x80)),
            ("ACC_VARARGS", StaticValue::Integer(0x80)),
            ("ACC_NATIVE", StaticValue::Integer(0x01_00)),
            ("ACC_INTERFACE", StaticValue::Integer(0x02_00)),
            ("ACC_ABSTRACT", StaticValue::Integer(0x04_00)),
            ("ACC_STRICT", StaticValue::Integer(0x08_00)),
            ("ACC_SYNTHETIC", StaticValue::Integer(0x10_00)),
            ("ACC_ANNOTATION", StaticValue::Integer(0x20_00)),
            ("ACC_ENUM", StaticValue::Integer(0x40_00)),
            ("ACC_CONSTRUCTOR", StaticValue::Integer(0x01_00_00)),
            (
                "ACC_DECLARED_SYNCHRONIZED",
                StaticValue::Integer(0x02_00_00),
            ),
            ("TYPE_HEADER_ITEM", StaticValue::Integer(0x00_00)),
            ("TYPE_STRING_ID_ITEM", StaticValue::Integer(0x00_01)),
            ("TYPE_TYPE_ID_ITEM", StaticValue::Integer(0x00_02)),
            ("TYPE_PROTO_ID_ITEM", StaticValue::Integer(0x00_03)),
            ("TYPE_FIELD_ID_ITEM", StaticValue::Integer(0x00_04)),
            ("TYPE_METHOD_ID_ITEM", StaticValue::Integer(0x00_05)),
            ("TYPE_CLASS_DEF_ITEM", StaticValue::Integer(0x00_06)),
            ("TYPE_CALL_SITE_ID_ITEM", StaticValue::Integer(0x00_07)),
            ("TYPE_METHOD_HANDLE_ITEM", StaticValue::Integer(0x00_08)),
            ("TYPE_MAP_LIST", StaticValue::Integer(0x10_00)),
            ("TYPE_TYPE_LIST", StaticValue::Integer(0x10_01)),
            (
                "TYPE_ANNOTATION_SET_REF_LIST",
                StaticValue::Integer(0x10_02),
            ),
            ("TYPE_ANNOTATION_SET_ITEM", StaticValue::Integer(0x10_03)),
            ("TYPE_CLASS_DATA_ITEM", StaticValue::Integer(0x20_00)),
            ("TYPE_CODE_ITEM", StaticValue::Integer(0x20_01)),
            ("TYPE_STRING_DATA_ITEM", StaticValue::Integer(0x20_02)),
            ("TYPE_DEBUG_INFO_ITEM", StaticValue::Integer(0x20_03)),
            ("TYPE_ANNOTATION_ITEM", StaticValue::Integer(0x20_04)),
            ("TYPE_ENCODED_ARRAY_ITEM", StaticValue::Integer(0x20_05)),
            (
                "TYPE_ANNOTATIONS_DIRECTORY_ITEM",
                StaticValue::Integer(0x20_06),
            ),
            (
                "has_method",
                StaticValue::function(
                    Self::has_method,
                    vec![
                        vec![Type::Bytes],
                        vec![Type::Bytes, Type::Bytes],
                        vec![Type::Regex],
                        vec![Type::Regex, Type::Regex],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "has_class",
                StaticValue::function(
                    Self::has_class,
                    vec![vec![Type::Bytes], vec![Type::Regex]],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        [
            (
                "header",
                Type::object([
                    ("magic", Type::Bytes),
                    ("checksum", Type::Integer),
                    ("signature", Type::Bytes),
                    ("file_size", Type::Integer),
                    ("header_size", Type::Integer),
                    ("endian_tag", Type::Integer),
                    ("link_size", Type::Integer),
                    ("link_offset", Type::Integer),
                    ("map_offset", Type::Integer),
                    ("string_ids_size", Type::Integer),
                    ("string_ids_offset", Type::Integer),
                    ("type_ids_size", Type::Integer),
                    ("type_ids_offset", Type::Integer),
                    ("proto_ids_size", Type::Integer),
                    ("proto_ids_offset", Type::Integer),
                    ("field_ids_size", Type::Integer),
                    ("field_ids_offset", Type::Integer),
                    ("method_ids_size", Type::Integer),
                    ("method_ids_offset", Type::Integer),
                    ("class_defs_size", Type::Integer),
                    ("class_defs_offset", Type::Integer),
                    ("data_size", Type::Integer),
                    ("data_offset", Type::Integer),
                ]),
            ),
            (
                "string_ids",
                Type::array(Type::object([
                    ("offset", Type::Integer),
                    ("size", Type::Integer),
                    ("value", Type::Bytes),
                ])),
            ),
            (
                "type_ids",
                Type::array(Type::object([("descriptor_idx", Type::Integer)])),
            ),
            (
                "proto_ids",
                Type::array(Type::object([
                    ("shorty_idx", Type::Integer),
                    ("return_type_idx", Type::Integer),
                    ("parameters_offset", Type::Integer),
                ])),
            ),
            (
                "field_ids",
                Type::array(Type::object([
                    ("class_idx", Type::Integer),
                    ("type_idx", Type::Integer),
                    ("name_idx", Type::Integer),
                ])),
            ),
            (
                "method_ids",
                Type::array(Type::object([
                    ("class_idx", Type::Integer),
                    ("proto_idx", Type::Integer),
                    ("name_idx", Type::Integer),
                ])),
            ),
            (
                "class_defs",
                Type::array(Type::object([
                    ("class_idx", Type::Integer),
                    ("access_flags", Type::Integer),
                    ("super_class_idx", Type::Integer),
                    ("interfaces_offset", Type::Integer),
                    ("source_file_idx", Type::Integer),
                    ("annotations_offset", Type::Integer),
                    ("class_data_offset", Type::Integer),
                    ("static_values_offset", Type::Integer),
                ])),
            ),
            (
                "class_data_item",
                Type::array(Type::object([
                    ("static_fields_size", Type::Integer),
                    ("instance_fields_size", Type::Integer),
                    ("direct_methods_size", Type::Integer),
                    ("virtual_methods_size", Type::Integer),
                ])),
            ),
            (
                "map_list",
                Type::object([
                    ("size", Type::Integer),
                    (
                        "map_item",
                        Type::array(Type::object([
                            ("type", Type::Integer),
                            ("unused", Type::Integer),
                            ("size", Type::Integer),
                            ("offset", Type::Integer),
                        ])),
                    ),
                ]),
            ),
            ("number_of_fields", Type::Integer),
            (
                "field",
                Type::array(Type::object([
                    ("class_name", Type::Bytes),
                    ("name", Type::Bytes),
                    ("proto", Type::Bytes),
                    ("field_idx_diff", Type::Integer),
                    ("access_flags", Type::Integer),
                ])),
            ),
            ("number_of_methods", Type::Integer),
            (
                "method",
                Type::array(Type::object([
                    ("class_name", Type::Bytes),
                    ("name", Type::Bytes),
                    ("proto", Type::Bytes),
                    ("direct", Type::Integer),
                    ("virtual", Type::Integer),
                    ("method_idx_diff", Type::Integer),
                    ("access_flags", Type::Integer),
                    ("code_off", Type::Integer),
                    (
                        "code_item",
                        Type::object([
                            ("registers_size", Type::Integer),
                            ("ins_size", Type::Integer),
                            ("outs_size", Type::Integer),
                            ("tries_size", Type::Integer),
                            ("debug_info_off", Type::Integer),
                            ("insns_size", Type::Integer),
                            ("insns", Type::Bytes),
                            ("padding", Type::Integer),
                            ("tries", Type::object([])),
                            ("handlers", Type::array(Type::object([]))),
                        ]),
                    ),
                ])),
            ),
        ]
        .into()
    }

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        data_map.insert::<Self>(Data::default());
    }

    fn get_dynamic_values(&self, ctx: &mut ScanContext, out: &mut HashMap<&'static str, Value>) {
        let Some(data) = ctx.module_data.get_mut::<Self>() else {
            return;
        };

        if data.found_dex {
            // We already found a dex in a region, so ignore the others
            return;
        }

        if let Some(values) = parse_file(ctx.region.mem) {
            *out = values;
            data.found_dex = true;
        }
    }
}

impl Dex {
    fn has_method(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }

    fn has_class(_: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        todo!()
    }
}

#[derive(Default)]
pub struct Data {
    found_dex: bool,
}

impl ModuleData for Dex {
    type Data = Data;
}

fn parse_file(mem: &[u8]) -> Option<HashMap<&'static str, Value>> {
    let header = parse_dex_header(mem)?;

    let string_ids_size = header.string_ids_size.get(LE);
    let string_ids_off = header.string_ids_off.get(LE);
    let string_ids = parse_string_ids(mem, string_ids_size, string_ids_off);

    let type_ids_size = header.type_ids_size.get(LE);
    let type_ids_off = header.type_ids_off.get(LE);
    let type_ids = parse_type_ids(mem, type_ids_size, type_ids_off);

    let proto_ids_size = header.proto_ids_size.get(LE);
    let proto_ids_off = header.proto_ids_off.get(LE);
    let proto_ids = parse_proto_ids(mem, proto_ids_size, proto_ids_off);

    let field_ids_size = header.field_ids_size.get(LE);
    let field_ids_off = header.field_ids_off.get(LE);
    let field_ids = parse_field_ids(mem, field_ids_size, field_ids_off);

    let method_ids_size = header.method_ids_size.get(LE);
    let method_ids_off = header.method_ids_off.get(LE);
    let method_ids = parse_method_ids(mem, method_ids_size, method_ids_off);

    let class_defs_size = header.class_defs_size.get(LE);
    let class_defs_off = header.class_defs_off.get(LE);

    let map_off = header.map_off.get(LE);
    let map_list = parse_map_list(mem, map_off);

    let mut out = [
        (
            "header",
            Value::object([
                ("magic", Value::bytes(header.magic)),
                ("checksum", header.checksum.get(LE).into()),
                ("signature", Value::bytes(header.signature)),
                ("file_size", header.filesize.get(LE).into()),
                ("header_size", header.header_size.get(LE).into()),
                ("endian_tag", header.endian_tag.get(LE).into()),
                ("link_size", header.link_size.get(LE).into()),
                ("link_offset", header.link_off.get(LE).into()),
                ("map_offset", map_off.into()),
                ("string_ids_size", string_ids_size.into()),
                ("string_ids_offset", string_ids_off.into()),
                ("type_ids_size", type_ids_size.into()),
                ("type_ids_offset", type_ids_off.into()),
                ("proto_ids_size", proto_ids_size.into()),
                ("proto_ids_offset", proto_ids_off.into()),
                ("field_ids_size", field_ids_size.into()),
                ("field_ids_offset", field_ids_off.into()),
                ("method_ids_size", method_ids_size.into()),
                ("method_ids_offset", method_ids_off.into()),
                ("class_defs_size", class_defs_size.into()),
                ("class_defs_offset", class_defs_off.into()),
                ("data_size", header.data_size.get(LE).into()),
                ("data_offset", header.data_off.get(LE).into()),
            ]),
        ),
        ("string_ids", string_ids.into()),
        ("type_ids", type_ids.into()),
        ("proto_ids", proto_ids.into()),
        ("field_ids", field_ids.into()),
        ("method_ids", method_ids.into()),
        ("map_list", map_list.into()),
    ]
    .into();

    parse_class_defs(mem, class_defs_size, class_defs_off, &mut out);

    Some(out)
}

fn parse_dex_header(mem: &[u8]) -> Option<&Header> {
    // Do a quick check on the magic first
    if mem.len() < 8 {
        return None;
    }
    let magic = &mem[0..8];
    if magic != DEX_FILE_MAGIC_035
        && magic != DEX_FILE_MAGIC_036
        && magic != DEX_FILE_MAGIC_037
        && magic != DEX_FILE_MAGIC_038
        && magic != DEX_FILE_MAGIC_039
    {
        return None;
    }

    Bytes(mem).read::<Header>().ok()
}

fn parse_string_ids(mem: &[u8], count: u32, offset: u32) -> Option<Value> {
    let count = usize::try_from(count).ok()?;
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#string-item>
    let string_data_offsets: &[U32<LE>] = Bytes(mem).read_slice_at(offset, count).ok()?;

    let values = string_data_offsets
        .iter()
        .map(|string_offset| {
            let string_offset = string_offset.get(LE) as usize;

            let mut data = Bytes(mem);
            let (string_size, string_data) = match data.skip(string_offset) {
                Ok(()) => {
                    // data is a "string_data_item"
                    let string_size = data.read_uleb128().ok();
                    let string_data = string_size
                        .and_then(|size| usize::try_from(size).ok())
                        .and_then(|size| data.read_slice(size).ok());
                    (string_size, string_data)
                }
                Err(()) => (None, None),
            };

            Value::object([
                ("offset", string_offset.into()),
                ("size", string_size.into()),
                ("value", string_data.map(Value::bytes).into()),
            ])
        })
        .collect();

    Some(Value::Array(values))
}

fn parse_type_ids(mem: &[u8], count: u32, offset: u32) -> Option<Value> {
    let count = usize::try_from(count).ok()?;
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#type-id-item>
    let type_ids: &[U32<LE>] = Bytes(mem).read_slice_at(offset, count).ok()?;

    let values = type_ids
        .iter()
        .map(|type_id| {
            let descriptor_index = type_id.get(LE);
            Value::object([("descriptor_idx", Value::Integer(descriptor_index.into()))])
        })
        .collect();

    Some(Value::Array(values))
}

fn parse_proto_ids(mem: &[u8], count: u32, offset: u32) -> Option<Value> {
    let count = usize::try_from(count).ok()?;
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#proto-id-item>
    let proto_ids: &[ProtoIdItem] = Bytes(mem).read_slice_at(offset, count).ok()?;

    let values = proto_ids
        .iter()
        .map(|item| {
            Value::object([
                ("shorty_idx", item.shorty_idx.get(LE).into()),
                ("return_type_idx", item.return_type_idx.get(LE).into()),
                ("parameters_offset", item.parameters_off.get(LE).into()),
            ])
        })
        .collect();

    Some(Value::Array(values))
}

fn parse_field_ids(mem: &[u8], count: u32, offset: u32) -> Option<Value> {
    let count = usize::try_from(count).ok()?;
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#field-id-item>
    let field_ids: &[FieldIdItem] = Bytes(mem).read_slice_at(offset, count).ok()?;

    let values = field_ids
        .iter()
        .map(|item| {
            Value::object([
                ("class_idx", item.class_idx.get(LE).into()),
                ("type_idx", item.type_idx.get(LE).into()),
                ("name_idx", item.name_idx.get(LE).into()),
            ])
        })
        .collect();

    Some(Value::Array(values))
}

fn parse_method_ids(mem: &[u8], count: u32, offset: u32) -> Option<Value> {
    let count = usize::try_from(count).ok()?;
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#method-id-item>
    let method_ids: &[MethodIdItem] = Bytes(mem).read_slice_at(offset, count).ok()?;

    let values = method_ids
        .iter()
        .map(|item| {
            Value::object([
                ("class_idx", item.class_idx.get(LE).into()),
                ("proto_idx", item.proto_idx.get(LE).into()),
                ("name_idx", item.name_idx.get(LE).into()),
            ])
        })
        .collect();

    Some(Value::Array(values))
}

fn parse_class_defs(mem: &[u8], count: u32, offset: u32, out: &mut HashMap<&'static str, Value>) {
    let Ok(count) = usize::try_from(count) else {
        return;
    };
    let Ok(offset) = usize::try_from(offset) else {
        return;
    };

    // See <https://source.android.com/docs/core/runtime/dex-format#class-def-item>
    let Ok(class_defs) = Bytes(mem).read_slice_at::<ClassDefItem>(offset, count) else {
        return;
    };

    let mut class_data_items = Vec::new();
    let mut fields = Vec::new();
    let mut methods = Vec::new();

    let values = class_defs
        .iter()
        .map(|item| {
            let data_offset = item.class_data_off.get(LE);

            if data_offset != 0 {
                let _r = parse_class_data_item(
                    mem,
                    data_offset,
                    &mut class_data_items,
                    &mut fields,
                    &mut methods,
                );
            }

            Value::object([
                ("class_idx", item.class_idx.get(LE).into()),
                ("access_flags", item.access_flags.get(LE).into()),
                ("super_class_idx", item.superclass_idx.get(LE).into()),
                ("interfaces_offset", item.interfaces_off.get(LE).into()),
                ("source_file_idx", item.source_file_idx.get(LE).into()),
                ("annotations_offset", item.annotations_off.get(LE).into()),
                ("class_data_offset", data_offset.into()),
                (
                    "static_values_offset",
                    item.static_values_off.get(LE).into(),
                ),
            ])
        })
        .collect();

    out.extend([
        ("class_defs", Value::Array(values)),
        ("class_data_item", Value::Array(class_data_items)),
        ("number_of_fields", fields.len().into()),
        ("field", Value::Array(fields)),
        ("number_of_methods", methods.len().into()),
        ("method", Value::Array(methods)),
    ]);
}

fn parse_class_data_item(
    mem: &[u8],
    offset: u32,
    class_data_items: &mut Vec<Value>,
    fields: &mut Vec<Value>,
    methods: &mut Vec<Value>,
) -> Option<()> {
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#class-data-item>
    let mut mem = Bytes(mem);
    mem.skip(offset).ok()?;

    let static_fields_size = mem.read_uleb128().ok()?;
    let instance_fields_size = mem.read_uleb128().ok()?;
    let direct_methods_size = mem.read_uleb128().ok()?;
    let virtual_methods_size = mem.read_uleb128().ok()?;

    class_data_items.push(Value::object([
        ("static_fields_size", static_fields_size.into()),
        ("instance_fields_size", instance_fields_size.into()),
        ("direct_methods_size", direct_methods_size.into()),
        ("virtual_methods_size", virtual_methods_size.into()),
    ]));

    for _ in 0..static_fields_size {
        fields.push(parse_encoded_field(&mut mem)?);
    }
    for _ in 0..instance_fields_size {
        fields.push(parse_encoded_field(&mut mem)?);
    }
    for _ in 0..direct_methods_size {
        methods.push(parse_encoded_method(&mut mem)?);
    }
    for _ in 0..virtual_methods_size {
        methods.push(parse_encoded_method(&mut mem)?);
    }

    Some(())
}

fn parse_encoded_field(mem: &mut Bytes) -> Option<Value> {
    // See <https://source.android.com/docs/core/runtime/dex-format#encoded-field-format>
    let field_idx_diff = mem.read_uleb128().ok()?;
    let access_flags = mem.read_uleb128().ok()?;

    Some(Value::object([
        ("field_idx_diff", field_idx_diff.into()),
        ("access_flags", access_flags.into()),
    ]))
}

fn parse_encoded_method(mem: &mut Bytes) -> Option<Value> {
    // See <https://source.android.com/docs/core/runtime/dex-format#encoded-method>
    let method_idx_diff = mem.read_uleb128().ok()?;
    let access_flags = mem.read_uleb128().ok()?;
    let code_off = mem.read_uleb128().ok()?;

    Some(Value::object([
        ("method_idx_diff", method_idx_diff.into()),
        ("access_flags", access_flags.into()),
        ("code_off", code_off.into()),
    ]))
}

fn parse_map_list(mem: &[u8], offset: u32) -> Option<Value> {
    let offset = usize::try_from(offset).ok()?;

    // See <https://source.android.com/docs/core/runtime/dex-format#map-list
    let mut mem = Bytes(mem);
    mem.skip(offset).ok()?;

    let count = mem.read::<U32<LE>>().ok()?.get(LE);
    let count_usize = usize::try_from(count).ok()?;

    let list: &[MapItem] = mem.read_slice(count_usize).ok()?;

    let values = list
        .iter()
        .map(|item| {
            Value::object([
                ("type", item.r#type.get(LE).into()),
                ("unused", item.unused.get(LE).into()),
                ("size", item.size.get(LE).into()),
                ("offset", item.offset.get(LE).into()),
            ])
        })
        .collect();

    Some(Value::object([
        ("size", count.into()),
        ("map_item", Value::Array(values)),
    ]))
}

/// Dex header, see <https://source.android.com/docs/core/runtime/dex-format#header-item>
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Header {
    magic: [u8; 8],
    checksum: U32<LE>,
    signature: [u8; 20],
    filesize: U32<LE>,
    header_size: U32<LE>,
    endian_tag: U32<LE>,
    link_size: U32<LE>,
    link_off: U32<LE>,
    map_off: U32<LE>,
    string_ids_size: U32<LE>,
    string_ids_off: U32<LE>,
    type_ids_size: U32<LE>,
    type_ids_off: U32<LE>,
    proto_ids_size: U32<LE>,
    proto_ids_off: U32<LE>,
    field_ids_size: U32<LE>,
    field_ids_off: U32<LE>,
    method_ids_size: U32<LE>,
    method_ids_off: U32<LE>,
    class_defs_size: U32<LE>,
    class_defs_off: U32<LE>,
    data_size: U32<LE>,
    data_off: U32<LE>,
}

// Safety:
// - Header is `#[repr(C)]`
// - has no invalid byte values.
// - has no padding
unsafe impl Pod for Header {}

/// Proto id item, see <https://source.android.com/docs/core/runtime/dex-format#proto-id-item>
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct ProtoIdItem {
    shorty_idx: U32<LE>,
    return_type_idx: U32<LE>,
    parameters_off: U32<LE>,
}

// Safety:
// - ProtoIdItem is `#[repr(C)]`
// - has no invalid byte values.
// - has no padding
unsafe impl Pod for ProtoIdItem {}

/// Field id item, see <https://source.android.com/docs/core/runtime/dex-format#field-id-item>
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct FieldIdItem {
    class_idx: U16<LE>,
    type_idx: U16<LE>,
    name_idx: U32<LE>,
}

// Safety:
// - FieldIdItem is `#[repr(C)]`
// - has no invalid byte values.
// - has no padding
unsafe impl Pod for FieldIdItem {}

/// Method id item, see <https://source.android.com/docs/core/runtime/dex-format#method-id-item>
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct MethodIdItem {
    class_idx: U16<LE>,
    proto_idx: U16<LE>,
    name_idx: U32<LE>,
}

// Safety:
// - MethodIdItem is `#[repr(C)]`
// - has no invalid byte values.
// - has no padding
unsafe impl Pod for MethodIdItem {}

/// Class def item, see <https://source.android.com/docs/core/runtime/dex-format#class-def-item>
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct ClassDefItem {
    class_idx: U32<LE>,
    access_flags: U32<LE>,
    superclass_idx: U32<LE>,
    interfaces_off: U32<LE>,
    source_file_idx: U32<LE>,
    annotations_off: U32<LE>,
    class_data_off: U32<LE>,
    static_values_off: U32<LE>,
}

// Safety:
// - ClassDefItem is `#[repr(C)]`
// - has no invalid byte values.
// - has no padding
unsafe impl Pod for ClassDefItem {}

/// Map item, see <https://source.android.com/docs/core/runtime/dex-format#map-item>
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct MapItem {
    r#type: U16<LE>,
    unused: U16<LE>,
    size: U32<LE>,
    offset: U32<LE>,
}

// Safety:
// - MapItem is `#[repr(C)]`
// - has no invalid byte values.
// - has no padding
unsafe impl Pod for MapItem {}
