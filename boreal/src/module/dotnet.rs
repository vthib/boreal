use std::collections::HashMap;

use object::coff::SectionTable;
use object::pe::{
    ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
};
use object::read::pe::ImageNtHeaders;
use object::{Bytes, FileKind, LittleEndian as LE, Pod, ReadRef, U16, U32, U64};

use super::{Module, ScanContext, StaticValue, Type, Value};

/// `dotnet` module. Allows inspecting dotnet binaries
#[derive(Debug)]
pub struct Dotnet;

impl Module for Dotnet {
    fn get_name(&self) -> &'static str {
        "dotnet"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        HashMap::new()
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        [
            // Integers depending on scan
            ("is_dotnet", Type::Integer),
            ("version", Type::Bytes),
            ("module_name", Type::Integer),
            (
                "streams",
                Type::array(Type::object([
                    ("name", Type::Bytes),
                    ("offset", Type::Integer),
                    ("size", Type::Integer),
                ])),
            ),
            ("number_of_streams", Type::Integer),
            ("guids", Type::array(Type::Bytes)),
            ("number_of_guids", Type::Integer),
            (
                "resources",
                Type::array(Type::object([
                    ("offset", Type::Integer),
                    ("length", Type::Integer),
                    ("name", Type::Bytes),
                ])),
            ),
            ("number_of_resources", Type::Integer),
            (
                "classes",
                Type::array(Type::object([
                    ("fullname", Type::Bytes),
                    ("name", Type::Bytes),
                    ("namespace", Type::Bytes),
                    ("visibility", Type::Bytes),
                    ("type", Type::Bytes),
                    ("abstract", Type::Integer),
                    ("sealed", Type::Integer),
                    ("number_of_generic_parameters", Type::Integer),
                    ("generic_parameters", Type::array(Type::Bytes)),
                    ("number_of_base_types", Type::Integer),
                    ("base_types", Type::array(Type::Bytes)),
                    ("number_of_methods", Type::Integer),
                    (
                        "methods",
                        Type::array(Type::object([
                            ("generic_parameters", Type::array(Type::Bytes)),
                            ("number_of_generic_parameters", Type::Integer),
                            (
                                "parameters",
                                Type::array(Type::object([
                                    ("name", Type::Bytes),
                                    ("type", Type::Bytes),
                                ])),
                            ),
                            ("number_of_parameters", Type::Integer),
                            ("return_type", Type::Bytes),
                            ("abstract", Type::Integer),
                            ("final", Type::Integer),
                            ("virtual", Type::Integer),
                            ("static", Type::Integer),
                            ("visibility", Type::Bytes),
                            ("name", Type::Bytes),
                        ])),
                    ),
                ])),
            ),
            ("number_of_classes", Type::Integer),
            (
                "assembly_refs",
                Type::array(Type::object([
                    (
                        "version",
                        Type::object([
                            ("major", Type::Integer),
                            ("minor", Type::Integer),
                            ("build_number", Type::Integer),
                            ("revision_number", Type::Integer),
                        ]),
                    ),
                    ("public_key_or_token", Type::Bytes),
                    ("name", Type::Bytes),
                ])),
            ),
            ("number_of_assembly_refs", Type::Integer),
            (
                "assembly",
                Type::object([
                    (
                        "version",
                        Type::object([
                            ("major", Type::Integer),
                            ("minor", Type::Integer),
                            ("build_number", Type::Integer),
                            ("revision_number", Type::Integer),
                        ]),
                    ),
                    ("name", Type::Bytes),
                    ("culture", Type::Bytes),
                ]),
            ),
            ("modulerefs", Type::array(Type::Bytes)),
            ("number_of_modulerefs", Type::Integer),
            ("user_strings", Type::array(Type::Bytes)),
            ("number_of_user_strings", Type::Integer),
            ("typelib", Type::Bytes),
            ("constants", Type::array(Type::Bytes)),
            ("number_of_constants", Type::Integer),
            ("field_offsets", Type::array(Type::Integer)),
            ("number_of_field_offsets", Type::Integer),
        ]
        .into()
    }

    fn get_dynamic_values(&self, ctx: &mut ScanContext, out: &mut HashMap<&'static str, Value>) {
        let res = match FileKind::parse(ctx.region.mem) {
            Ok(FileKind::Pe32) => parse_file::<ImageNtHeaders32>(ctx.region.mem),
            Ok(FileKind::Pe64) => parse_file::<ImageNtHeaders64>(ctx.region.mem),
            _ => None,
        };

        match res {
            Some(values) => {
                *out = values;
            }
            None => *out = [("is_dotnet", 0.into())].into(),
        };
    }
}

fn parse_file<HEADERS: ImageNtHeaders>(mem: &[u8]) -> Option<HashMap<&'static str, Value>> {
    // A dotnet file is a PE, with details stored in it. First, parse the PE headers.
    let dos_header = ImageDosHeader::parse(mem).ok()?;
    let mut offset = dos_header.nt_headers_offset().into();
    let (nt_headers, data_dirs) = HEADERS::parse(mem, &mut offset).ok()?;
    let sections = nt_headers.sections(mem, offset).ok()?;

    // II.25.3.3 : the PE contains a data directory named "CLI header"
    let dir = data_dirs.get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
    let cli_data = dir.data(mem, &sections).ok()?;
    let cli_data = Bytes(cli_data);
    let cli_header = cli_data.read_at::<CliHeader>(0).ok()?;

    let metadata_root_offset: u64 = sections
        .pe_file_range_at(cli_header.metadata_rva.get(LE))?
        .0
        .into();
    let metadata = cli_header.metadata(mem, &sections).ok()?;

    let streams = get_streams(&metadata, metadata_root_offset);

    let mut res: HashMap<&'static str, Value> = [
        ("is_dotnet", Value::Integer(1)),
        ("version", Value::bytes(metadata.version)),
        ("module_name", Value::Undefined),
        ("streams", Value::Array(streams)),
        (
            "number_of_streams",
            Value::Integer(metadata.number_of_streams.into()),
        ),
    ]
    .into();

    add_guids(&metadata, &mut res);
    add_user_strings(&metadata, &mut res);
    add_metadata_tables(&metadata, &mut res);

    // TODO

    res.extend([
        ("resources", Value::Undefined),
        ("number_of_resources", Value::Undefined),
        ("classes", Value::Undefined),
        ("number_of_classes", Value::Undefined),
        ("assembly_refs", Value::Undefined),
        ("number_of_assembly_refs", Value::Undefined),
        ("assembly", Value::Undefined),
        ("modulerefs", Value::Undefined),
        ("number_of_modulerefs", Value::Undefined),
        ("typelib", Value::Undefined),
        ("constants", Value::Undefined),
        ("number_of_constants", Value::Undefined),
        ("field_offsets", Value::Undefined),
        ("number_of_field_offsets", Value::Undefined),
    ]);
    Some(res)
}

fn add_guids(metadata: &MetadataRoot, res: &mut HashMap<&'static str, Value>) {
    let Some(stream_data) = metadata.get_stream(b"#GUID") else {
        return;
    };

    // The stream data is a sequence of GUIDS.
    // See ECMA 335 II.24.2.5
    let nb_guids = stream_data.len() / 16;
    let guids = stream_data
        .chunks_exact(16)
        .map(|g| {
            // ECMA 335 does not, afaict, define how GUID are stored. It tends to be
            // parsed as a u32-u16-u16-u8[8] object, so lets parse it as such.
            let a = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
            let b = u16::from_le_bytes([g[4], g[5]]);
            let c = u16::from_le_bytes([g[6], g[7]]);
            let guid = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                a, b, c, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
            );

            Value::Bytes(guid.into_bytes())
        })
        .collect();

    res.extend([
        ("number_of_guids", nb_guids.into()),
        ("guids", Value::Array(guids)),
    ]);
}

fn add_user_strings(metadata: &MetadataRoot, res: &mut HashMap<&'static str, Value>) {
    let Some(stream_data) = metadata.get_stream(b"#US") else {
        return;
    };

    // See ECMA 335 II.24.2.4
    // The stream data is a sequence of UTF-16 unicode strings with some special encoding.
    let mut strings = Vec::new();
    let mut bytes = Bytes(stream_data);
    // Skip the "empty" blob.
    let _ = bytes.skip(1);
    while let Some(v) = read_user_string(&mut bytes) {
        // XXX: the yara module seems to ignore strings if they are empty.
        if !v.is_empty() {
            strings.push(Value::bytes(v));
        }
    }

    res.extend([
        ("number_of_user_strings", strings.len().into()),
        ("user_strings", Value::Array(strings)),
    ]);
}

fn add_metadata_tables(metadata: &MetadataRoot, res: &mut HashMap<&'static str, Value>) {
    let Some(stream_data) = metadata.get_stream(b"#~") else {
        return;
    };

    // See ECMA 335 II.24.2.6
    let mut bytes = Bytes(stream_data);
    let Ok(header) = bytes.read::<MetadataStreamHeader>() else {
        return;
    };

    // After the header, there is 'n' u32 values, where n is the number of table kinds.
    let valid = header.valid.get(LE);
    let nb_table_kinds = valid.count_ones();
    let rows = match bytes.read_bytes((nb_table_kinds as usize) * 4) {
        Ok(v) => v.0,
        Err(()) => return,
    };

    let mut tables_data = TablesData::new(bytes, header.heap_sizes);

    // First, set the index sizes in tables_data, which depends on the number
    // of tables of different kinds.
    // Technically, a table B with an index into table A seems to always have
    // an index greater than the index of table A. So, we could probably parse
    // rows directly and store those sizes as they come. I'd rather be safe though,
    // and properly set those in advance.
    for (nb_tables, table_index) in TablesIterator::new(valid, rows) {
        tables_data.set_table_index_size(table_index, nb_tables);
    }

    // We can now parse the tables
    for (nb_tables, table_index) in TablesIterator::new(valid, rows) {
        for _ in 0..nb_tables {
            if tables_data.parse_table(table_index, res).is_err() {
                return;
            }
        }
    }
}

struct TablesIterator<'data> {
    valid: u64,
    rows: &'data [u8],
    rows_index: usize,
    current_index: u8,
}

impl<'data> TablesIterator<'data> {
    fn new(valid: u64, rows: &'data [u8]) -> Self {
        Self {
            valid,
            rows,
            current_index: 0,
            rows_index: 0,
        }
    }
}

impl Iterator for TablesIterator<'_> {
    type Item = (u32, u8);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < 64 {
            let i = self.current_index;
            self.current_index += 1;

            if self.valid & (1 << i) == 0 {
                continue;
            }

            // Get the number of tables of this kind from the rows field.
            let nb_tables = u32::from_le_bytes([
                self.rows[self.rows_index],
                self.rows[self.rows_index + 1],
                self.rows[self.rows_index + 2],
                self.rows[self.rows_index + 3],
            ]);
            self.rows_index += 4;

            return Some((nb_tables, i));
        }
        None
    }
}

struct TablesData<'data> {
    data: Bytes<'data>,

    // These values are the size of indexes used in tables.
    // They are either equal to 2 or 4.
    string_index_size: u8,
    guid_index_size: u8,
    blob_index_size: u8,
    field_index_size: u8,
    assembly_ref_index_size: u8,
}

#[derive(Copy, Clone, Debug)]
enum IndexKind {
    String,
    Guid,
    Blob,
}

impl<'data> TablesData<'data> {
    fn new(data: Bytes<'data>, heap_sizes: u8) -> Self {
        // Get index sizes for indexing in other streams
        let wide_string_index = heap_sizes & 0x01 != 0;
        let wide_guid_index = heap_sizes & 0x02 != 0;
        let wide_blob_index = heap_sizes & 0x04 != 0;

        Self {
            data,
            string_index_size: if wide_string_index { 4 } else { 2 },
            guid_index_size: if wide_guid_index { 4 } else { 2 },
            blob_index_size: if wide_blob_index { 4 } else { 2 },

            // Those sizes will be set properly by the `set_table_index_size` call.
            field_index_size: 2,
            assembly_ref_index_size: 2,
        }
    }

    fn set_table_index_size(&mut self, table_index: u8, nb_tables: u32) {
        if nb_tables < (1 << 16) {
            // Values are initialized to the default size (2 bytes), we only
            // need to fix them if the indexes are wide
            return;
        }

        match table_index {
            0x04 => self.field_index_size = 4,
            0x23 => self.assembly_ref_index_size = 4,
            _ => (),
        }
    }
    // Parse a table of the given index code.
    //
    // If Err is returned, the end of the data has been reached and nothing more can be read.
    fn parse_table(
        &mut self,
        table_index: u8,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        match table_index {
            // Module, see II.22.30
            0x00 => self.skip(2 + self.string_index_size + 3 * self.guid_index_size),
            // TypeRef, see II.22.38
            0x01 => todo!(),
            // TypeDef, see II.22.37
            0x02 => todo!(),
            // Field, see II.22.15
            0x04 => self.skip(2 + self.string_index_size + self.blob_index_size),
            // MethodDef, see II.22.26
            0x06 => todo!(),
            // Param, see II.22.33
            0x08 => self.skip(4 + self.string_index_size),
            // InterfaceImpl, see II.22.23
            0x09 => todo!(),
            // MemberRef, see II.22.25
            0x0A => todo!(),
            // Constant, see II.22.9
            0x0B => todo!(),
            // CustomAttribute, see II.22.10
            0x0C => todo!(),
            // FieldMarshall, see II.22.17
            0x0D => todo!(),
            // DeclSecurity, see II.22.11
            0x0E => todo!(),
            // ClassLayout, see II.22.8
            0x0F => todo!(),
            // FieldLayout, see II.22.16
            0x10 => self.skip(4 + self.field_index_size),
            // StandAloneSig, see II.22.36
            0x11 => self.skip(self.blob_index_size),
            // EventMap, see II.22.12
            0x12 => todo!(),
            // Event, see II.22.13
            0x14 => todo!(),
            // PropertyMap, see II.22.35
            0x15 => todo!(),
            // Property, see II.22.34
            0x17 => self.skip(2 + self.string_index_size + self.blob_index_size),
            // MethodSemantics, see II.22.28
            0x18 => todo!(),
            // MethodImpl, see II.22.27
            0x19 => todo!(),
            // ModuleRef, see II.22.31
            0x1A => self.skip(self.string_index_size),
            // TypeSpec, see II.22.39
            0x1B => self.skip(self.blob_index_size),
            // ImplMap, see II.22.22
            0x1C => todo!(),
            // FieldRVA, see II.22.18
            0x1D => self.skip(4 + self.field_index_size),
            // Assembly, see II.22.2
            0x20 => self.parse_assembly_table(res),
            // Assembly Processor, see II.22.4
            0x21 => self.skip(4),
            // Assembly OS, see II.22.3
            0x22 => self.skip(12),
            // Assembly Ref, see II.22.5
            0x23 => self.parse_assembly_ref_table(res),
            // Assembly Ref Processor, see II.22.7
            0x24 => self.skip(4 + self.assembly_ref_index_size),
            // Assembly Ref OS, see II.22.6
            0x25 => self.skip(12 + self.assembly_ref_index_size),
            // File, see II.22.19
            0x26 => self.skip(4 + self.string_index_size + self.blob_index_size),
            // ExportedType, see II.22.14
            0x27 => todo!(),
            // ManifestResource, see II.22.24
            0x28 => todo!(),
            // NestedClass, see II.22.32
            0x29 => todo!(),
            // GenericParam, see II.22.20
            0x2A => todo!(),
            // MethodSpec, see II.22.29
            0x2B => todo!(),
            // GenericParamConstraint, see II.22.21
            0x2C => todo!(),
            _ => {
                // We are matching an unknown table. This means we are no longer to parse
                // anything, since we do not know the size of this table, and can't parse the
                // rest. We thus abort the parsing.
                Err(())
            }
        }
    }

    // ECMA 335, II.22.2
    fn parse_assembly_table(&mut self, res: &mut HashMap<&'static str, Value>) -> Result<(), ()> {
        self.skip(4)?; // hash_alg_id
        let major_version = self.read_u16()?;
        let minor_version = self.read_u16()?;
        let build_number = self.read_u16()?;
        let revision_number = self.read_u16()?;
        self.skip(4)?; // flags
        self.skip_index(IndexKind::Blob)?; // public key
        let _name = self.read_index(IndexKind::String)?;
        let _culture = self.read_index(IndexKind::String)?;

        res.extend([(
            "assembly",
            Value::object([
                (
                    "version",
                    Value::object([
                        ("major", major_version.into()),
                        ("minor_version", minor_version.into()),
                        ("build_number", build_number.into()),
                        ("revision_number", revision_number.into()),
                    ]),
                ),
                // TODO
                ("name", Value::Undefined),
                ("culture", Value::Undefined),
            ]),
        )]);
        Ok(())
    }

    // ECMA 335, II.22.5
    fn parse_assembly_ref_table(
        &mut self,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        let major_version = self.read_u16()?;
        let minor_version = self.read_u16()?;
        let build_number = self.read_u16()?;
        let revision_number = self.read_u16()?;
        self.skip(4)?; // flags
        let _public_key_or_token = self.read_index(IndexKind::Blob)?;
        let _name = self.read_index(IndexKind::String)?;
        self.skip_index(IndexKind::String)?; // culture
        self.skip_index(IndexKind::Blob)?; // hash value

        let len = match res
            .entry("assembly_refs")
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(vec) => {
                vec.push(Value::object([
                    (
                        "version",
                        Value::object([
                            ("major", major_version.into()),
                            ("minor_version", minor_version.into()),
                            ("build_number", build_number.into()),
                            ("revision_number", revision_number.into()),
                        ]),
                    ),
                    // TODO
                    ("public_key_or_token", Value::Undefined),
                    ("name", Value::Undefined),
                ]));
                vec.len()
            }
            // Safety: the "assembly_refs" key can only contain a Value::Array by construction
            // in this module.
            _ => unreachable!(),
        };
        let _ = res.insert("number_of_assembly_refs", len.into());

        Ok(())
    }

    fn skip(&mut self, nb_bytes: u8) -> Result<(), ()> {
        self.data.skip(usize::from(nb_bytes))
    }

    #[inline(always)]
    fn skip_index(&mut self, kind: IndexKind) -> Result<(), ()> {
        self.skip(match kind {
            IndexKind::String => self.string_index_size,
            IndexKind::Guid => self.guid_index_size,
            IndexKind::Blob => self.blob_index_size,
        })
    }

    #[inline(always)]
    fn read_index(&mut self, kind: IndexKind) -> Result<u32, ()> {
        let size = match kind {
            IndexKind::String => self.string_index_size,
            IndexKind::Guid => self.guid_index_size,
            IndexKind::Blob => self.blob_index_size,
        };
        if size == 4 {
            self.read_u32()
        } else {
            self.read_u16().map(u32::from)
        }
    }

    fn read_u16(&mut self) -> Result<u16, ()> {
        self.data.read::<U16<LE>>().map(|v| v.get(LE))
    }

    fn read_u32(&mut self) -> Result<u32, ()> {
        self.data.read::<U32<LE>>().map(|v| v.get(LE))
    }
}

fn read_user_string<'data>(bytes: &mut Bytes<'data>) -> Option<&'data [u8]> {
    // See II.24.2.4 in ECMA 335 for details on the encoding.

    // The first part, is the length.
    // It is either encoded in one byte, two bytes or four bytes.
    let length = {
        fn get_byte(bytes: &mut Bytes) -> Option<u8> {
            let b = bytes.0.first()?;
            let _ = bytes.skip(1);
            Some(*b)
        }

        let a = get_byte(bytes)?;
        if a & 0x80 == 0 {
            a as usize
        } else if a & 0xC0 == 0x80 {
            let a = a & 0x4F;
            let b = get_byte(bytes)?;

            ((a as usize) << 8) | (b as usize)
        } else if a & 0xE0 == 0xC0 {
            let a = a & 0x1F;
            let b = get_byte(bytes)?;
            let c = get_byte(bytes)?;
            let d = get_byte(bytes)?;

            ((a as usize) << 24) | ((b as usize) << 16) | ((c as usize) << 8) | (d as usize)
        } else {
            return None;
        }
    };

    // The length is the number of bytes and not of utf-16 characters. However, it includes the
    // additional byte that we do not care about, so ignore it
    let length = length.checked_sub(1)?;
    let string = bytes.read_slice(length).ok()?;
    // Skip the additional byte, we do not care about it.
    bytes.skip(1).ok()?;
    Some(string)
}

fn get_streams(metadata: &MetadataRoot, metadata_root_offset: u64) -> Vec<Value> {
    metadata
        .streams()
        .map(|stream| match stream {
            Ok(stream) => {
                // The offset is relative to the metadata root. Since for the analysis,
                // it is more useful to return the offset in the file, add the offset
                // of the metadata root.
                Value::object([
                    ("name", Value::bytes(stream.name)),
                    (
                        "offset",
                        metadata_root_offset
                            .checked_add(stream.offset.into())
                            .into(),
                    ),
                    ("size", Value::Integer(stream.size.into())),
                ])
            }
            Err(_) => Value::Undefined,
        })
        .collect()
}

/// Metadata stream header, as defined in ECMA 335 II.24.2.6
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MetadataStreamHeader {
    pub reserved: U32<LE>,
    pub major_version: u8,
    pub minor_version: u8,
    pub heap_sizes: u8,
    pub reserved2: u8,
    pub valid: U64<LE>,
    pub sorted: U64<LE>,
}

// Safety:
// - MetadataStreamHeader is `#[repr(C)]`
// - has no invalid byte values (all values are unsigned integers)
// - has no padding
unsafe impl Pod for MetadataStreamHeader {}

/// CLI Header, as defined in ECMA 335 II.25.3.3
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CliHeader {
    pub cb: U32<LE>,
    pub major_runtime_version: U16<LE>,
    pub minor_runtime_version: U16<LE>,
    pub metadata_rva: U32<LE>,
    pub metadata_size: U32<LE>,
    pub flags: U32<LE>,
    pub entry_point_token: U32<LE>,
    pub resources_metadata: U32<LE>,
    pub resources_size: U32<LE>,
    pub strong_name_signature: U64<LE>,
    pub code_manager_table: U64<LE>,
    pub vtable_fixups: U64<LE>,
    pub extra_address_table_jumps: U64<LE>,
    pub managed_native_header: U64<LE>,
}

// Safety:
// - CliHeader is `#[repr(C)]`
// - has no invalid byte values (all values are unsigned integers)
// - has no padding
unsafe impl Pod for CliHeader {}

impl CliHeader {
    fn metadata<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<MetadataRoot<'data>, &'static str> {
        let data = sections
            .pe_data_at(data, self.metadata_rva.get(LE))
            .ok_or("Invalid CLI metadata virtual address")?
            .get(..self.metadata_size.get(LE) as usize)
            .ok_or("Invalid CLI metadata size")?;

        MetadataRoot::parse(data)
    }
}

/// Metadata root header, as defined in ECMA 335 II.24.2.1
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MetadataRootHeader {
    pub signature: U32<LE>,
    pub major_version: U16<LE>,
    pub minor_version: U16<LE>,
    pub reserved: U32<LE>,
    pub length: U32<LE>,
}

// Safety:
// - CliHeader is `#[repr(C)]`
// - has no invalid byte values (all values are unsigned integers)
// - has no padding
unsafe impl Pod for MetadataRootHeader {}

#[derive(Debug, Clone, Copy)]
struct MetadataRoot<'data> {
    _header: MetadataRootHeader,
    version: &'data [u8],
    _flags: u16,
    number_of_streams: u16,
    streams_data: Bytes<'data>,
    data: &'data [u8],
}

impl<'data> MetadataRoot<'data> {
    fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let mut bytes = Bytes(data);

        let header = *bytes
            .read::<MetadataRootHeader>()
            .map_err(|()| "Cannot read metadata root header")?;
        let version = bytes
            .read_slice(header.length.get(LE) as usize)
            .map_err(|()| "Cannot read metadata root version")?;
        let flags = bytes
            .read::<U16<LE>>()
            .map_err(|()| "Cannot read metadata root flags")?
            .get(LE);
        let number_of_streams = bytes
            .read::<U16<LE>>()
            .map_err(|()| "Cannot read number of streams")?
            .get(LE);

        // Cut version to the c-string + null byte. The rest is considered padding and
        // thus not included. The null byte is also not included for convenient purposes.
        let null_pos = version
            .iter()
            .position(|c| *c == b'\0')
            .ok_or("Invalid version string in metadata root")?;

        Ok(Self {
            _header: header,
            version: &version[..null_pos],
            _flags: flags,
            number_of_streams,
            streams_data: bytes,
            data,
        })
    }

    fn streams(&self) -> StreamIterator {
        StreamIterator {
            nb_streams_left: self.number_of_streams,
            data: self.streams_data,
        }
    }

    fn get_stream(&self, name: &[u8]) -> Option<&'data [u8]> {
        let stream = self
            .streams()
            .filter_map(Result::ok)
            .find(|stream| stream.name == name)?;

        self.data
            .read_slice_at(u64::from(stream.offset), stream.size as usize)
            .ok()
    }
}

#[derive(Debug, Clone)]
struct StreamIterator<'data> {
    nb_streams_left: u16,
    data: Bytes<'data>,
}

impl<'data> Iterator for StreamIterator<'data> {
    type Item = Result<StreamHeader<'data>, &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.nb_streams_left > 0 {
            self.nb_streams_left -= 1;
            Some(StreamHeader::parse(&mut self.data))
        } else {
            None
        }
    }
}

/// Stream header, as defined in ECMA 335 II.24.2.2
#[derive(Debug, Clone, Copy)]
pub struct StreamHeader<'data> {
    pub offset: u32,
    pub size: u32,
    pub name: &'data [u8],
}

impl<'data> StreamHeader<'data> {
    fn parse(data: &mut Bytes<'data>) -> Result<Self, &'static str> {
        let offset = data
            .read::<U32<LE>>()
            .map_err(|()| "Cannot read stream header offset")?
            .get(LE);
        let size = data
            .read::<U32<LE>>()
            .map_err(|()| "Cannot read stream header offset")?
            .get(LE);

        // Clone to avoid data
        let name = data
            .clone()
            .read_string()
            .map_err(|()| "Cannot read stream header name")?;
        // Advance data to the next 4-byte boundary
        let nb_bytes = ((name.len() + 1) + 3) & !3;
        data.skip(nb_bytes)
            .map_err(|()| "Cannot skip past stream header name")?;

        Ok(Self { offset, size, name })
    }
}
