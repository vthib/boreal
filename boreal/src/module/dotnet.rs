use std::collections::HashMap;

use object::coff::SectionTable;
use object::pe::{
    ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
};
use object::read::pe::ImageNtHeaders;
use object::{Bytes, FileKind, LittleEndian as LE, Pod, ReadRef, U16, U32, U64};

use super::pe::va_to_file_offset;
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
    add_metadata_tables(mem, &metadata, sections, &mut res);

    // TODO

    res.extend([
        ("classes", Value::Undefined),
        ("number_of_classes", Value::Undefined),
        ("typelib", Value::Undefined),
        ("constants", Value::Undefined),
        ("number_of_constants", Value::Undefined),
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
    while let Some(v) = read_blob(&mut bytes) {
        // XXX: the yara module seems to ignore strings if they are empty.
        // Since there is an additional byte that we we filter, this means
        // we want a blob that has at least two bytes (one valid, and the additional
        // one).
        if v.len() >= 2 {
            strings.push(Value::bytes(&v[..(v.len() - 1)]));
        }
    }

    res.extend([
        ("number_of_user_strings", strings.len().into()),
        ("user_strings", Value::Array(strings)),
    ]);
}

fn add_metadata_tables<'data>(
    mem: &'data [u8],
    metadata: &MetadataRoot<'data>,
    sections: SectionTable<'data>,
    res: &mut HashMap<&'static str, Value>,
) {
    let Some(stream_data) = metadata.get_stream(b"#~") else {
        return;
    };
    let strings_stream = metadata.get_stream(b"#Strings");
    let blobs_stream = metadata.get_stream(b"#Blob");

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

    // Instead of having a variable sized array, compute a static array
    // holding the number of rows for each table type.
    // This will make all of the rest of the code much cleaner and simpler.
    let mut table_counts = [0_u32; 64];
    let mut rows_index = 0;
    for (i, count) in table_counts.iter_mut().enumerate() {
        if valid & (1 << i) == 0 {
            continue;
        }

        // Get the number of tables of this kind from the rows field.
        *count = u32::from_le_bytes([
            rows[rows_index],
            rows[rows_index + 1],
            rows[rows_index + 2],
            rows[rows_index + 3],
        ]);
        rows_index += 4;
    }

    // Build our parsing helper: this will hold the current cursor on
    // the data, as well as the sizes of all the indexes.
    let mut tables_data = TablesData::new(
        mem,
        bytes,
        sections,
        strings_stream,
        blobs_stream,
        &table_counts,
        header.heap_sizes,
    );

    // Then, parsing every table in order
    for table_index in 0..64 {
        let nb_tables = table_counts[usize::from(table_index)];
        for _ in 0..nb_tables {
            if tables_data.parse_table(table_index, res).is_err() {
                return;
            }
        }
    }
}

mod table_type {
    // II.22.30
    pub const MODULE: u8 = 0x00;
    // II.22.38
    pub const TYPE_REF: u8 = 0x01;
    // II.22.37
    pub const TYPE_DEF: u8 = 0x02;
    // II.22.15
    pub const FIELD: u8 = 0x04;
    // II.22.26
    pub const METHOD_DEF: u8 = 0x06;
    // II.22.33
    pub const PARAM: u8 = 0x08;
    // II.22.23
    pub const INTERFACE_IMPL: u8 = 0x09;
    // II.22.25
    pub const MEMBER_REF: u8 = 0x0A;
    // II.22.9
    pub const CONSTANT: u8 = 0x0B;
    // II.22.10
    pub const CUSTOM_ATTRIBUTE: u8 = 0x0C;
    // II.22.17
    pub const FIELD_MARSHALL: u8 = 0x0D;
    // II.22.11
    pub const DECL_SECURITY: u8 = 0x0E;
    // II.22.8
    pub const CLASS_LAYOUT: u8 = 0x0F;
    // II.22.16
    pub const FIELD_LAYOUT: u8 = 0x10;
    // II.22.36
    pub const STAND_ALONE_SIG: u8 = 0x11;
    // II.22.12
    pub const EVENT_MAP: u8 = 0x12;
    // II.22.13
    pub const EVENT: u8 = 0x14;
    // II.22.35
    pub const PROPERTY_MAP: u8 = 0x15;
    // II.22.34
    pub const PROPERTY: u8 = 0x17;
    // II.22.28
    pub const METHOD_SEMANTICS: u8 = 0x18;
    // II.22.27
    pub const METHOD_IMPL: u8 = 0x19;
    // II.22.31
    pub const MODULE_REF: u8 = 0x1A;
    // II.22.39
    pub const TYPE_SPEC: u8 = 0x1B;
    // II.22.22
    pub const IMPL_MAP: u8 = 0x1C;
    // II.22.18
    pub const FIELD_RVA: u8 = 0x1D;
    // II.22.2
    pub const ASSEMBLY: u8 = 0x20;
    // II.22.4
    pub const ASSEMBLY_PROCESSOR: u8 = 0x21;
    // II.22.3
    pub const ASSEMBLY_OS: u8 = 0x22;
    // II.22.5
    pub const ASSEMBLY_REF: u8 = 0x23;
    // II.22.7
    pub const ASSEMBLY_REF_PROCESSOR: u8 = 0x24;
    // II.22.6
    pub const ASSEMBLY_REF_OS: u8 = 0x25;
    // II.22.19
    pub const FILE: u8 = 0x26;
    // II.22.14
    pub const EXPORTED_TYPE: u8 = 0x27;
    // II.22.24
    pub const MANIFEST_RESOURCE: u8 = 0x28;
    // II.22.32
    pub const NESTED_CLASS: u8 = 0x29;
    // II.22.20
    pub const GENERIC_PARAM: u8 = 0x2A;
    // II.22.29
    pub const METHOD_SPEC: u8 = 0x2B;
    // II.22.21
    pub const GENERIC_PARAM_CONSTRAINT: u8 = 0x2C;
}

struct TablesData<'data> {
    mem: &'data [u8],
    data: Bytes<'data>,

    sections: SectionTable<'data>,

    // Contents of the string stream
    strings_stream: Option<&'data [u8]>,
    // Contents of the blob stream
    blobs_stream: Option<&'data [u8]>,

    // The following values are the size of indexes used in tables.
    // They are either equal to 2 or 4.

    // Indexes into other streams
    string_index_size: u8,
    guid_index_size: u8,
    blob_index_size: u8,

    // Simple indexes into other tables
    type_def_index_size: u8,
    field_index_size: u8,
    method_def_index_size: u8,
    param_index_size: u8,
    event_index_size: u8,
    property_index_size: u8,
    module_ref_index_size: u8,
    assembly_ref_index_size: u8,
    generic_param_index_size: u8,

    // Coded indexes into other tables
    type_def_or_ref_index_size: u8,
    has_constant_index_size: u8,
    has_custom_attribute_index_size: u8,
    has_field_marshall_index_size: u8,
    has_decl_security_index_size: u8,
    member_ref_parent_index_size: u8,
    has_semantics_index_size: u8,
    method_def_or_ref_index_size: u8,
    member_forwarded_index_size: u8,
    implementation_index_size: u8,
    custom_attribute_type_index_size: u8,
    resolution_scope_index_size: u8,
    type_or_method_def_index_size: u8,
}

impl<'data> TablesData<'data> {
    fn new(
        mem: &'data [u8],
        data: Bytes<'data>,
        sections: SectionTable<'data>,
        strings_stream: Option<&'data [u8]>,
        blobs_stream: Option<&'data [u8]>,
        table_counts: &[u32; 64],
        heap_sizes: u8,
    ) -> Self {
        // Get index sizes for indexing in other streams
        let wide_string_index = heap_sizes & 0x01 != 0;
        let wide_guid_index = heap_sizes & 0x02 != 0;
        let wide_blob_index = heap_sizes & 0x04 != 0;

        let compute_index_size = |table_type: u8| {
            if table_counts[usize::from(table_type)] >= (1 << 16) {
                4
            } else {
                2
            }
        };
        let compute_coded_index_size = |table_types: &[u8], max_log: u8| {
            for table_type in table_types {
                if table_counts[usize::from(*table_type)] >= (1 << max_log) {
                    return 4;
                }
            }
            2
        };

        Self {
            mem,
            data,
            sections,
            strings_stream,
            blobs_stream,

            string_index_size: if wide_string_index { 4 } else { 2 },
            guid_index_size: if wide_guid_index { 4 } else { 2 },
            blob_index_size: if wide_blob_index { 4 } else { 2 },

            // Simple indexes
            type_def_index_size: compute_index_size(table_type::TYPE_DEF),
            field_index_size: compute_index_size(table_type::FIELD),
            method_def_index_size: compute_index_size(table_type::METHOD_DEF),
            param_index_size: compute_index_size(table_type::PARAM),
            event_index_size: compute_index_size(table_type::EVENT),
            property_index_size: compute_index_size(table_type::PROPERTY),
            module_ref_index_size: compute_index_size(table_type::MODULE_REF),
            assembly_ref_index_size: compute_index_size(table_type::ASSEMBLY_REF),
            generic_param_index_size: compute_index_size(table_type::GENERIC_PARAM),

            type_def_or_ref_index_size: compute_coded_index_size(
                &[
                    table_type::TYPE_REF,
                    table_type::TYPE_DEF,
                    table_type::TYPE_SPEC,
                ],
                14,
            ),
            has_constant_index_size: compute_coded_index_size(
                &[table_type::FIELD, table_type::PARAM, table_type::PROPERTY],
                14,
            ),
            has_custom_attribute_index_size: compute_coded_index_size(
                &[
                    table_type::MODULE,
                    table_type::TYPE_REF,
                    table_type::TYPE_DEF,
                    table_type::FIELD,
                    table_type::METHOD_DEF,
                    table_type::PARAM,
                    table_type::INTERFACE_IMPL,
                    table_type::MEMBER_REF,
                    table_type::STAND_ALONE_SIG,
                    table_type::EVENT,
                    table_type::PROPERTY,
                    table_type::MODULE_REF,
                    table_type::TYPE_SPEC,
                    table_type::ASSEMBLY,
                    table_type::ASSEMBLY_REF,
                    table_type::FILE,
                    table_type::EXPORTED_TYPE,
                    table_type::MANIFEST_RESOURCE,
                    table_type::GENERIC_PARAM,
                    table_type::METHOD_SPEC,
                    table_type::GENERIC_PARAM_CONSTRAINT,
                ],
                11,
            ),
            has_field_marshall_index_size: compute_coded_index_size(
                &[table_type::FIELD, table_type::PARAM],
                15,
            ),
            has_decl_security_index_size: compute_coded_index_size(
                &[
                    table_type::TYPE_DEF,
                    table_type::METHOD_DEF,
                    table_type::ASSEMBLY,
                ],
                14,
            ),
            member_ref_parent_index_size: compute_coded_index_size(
                &[
                    table_type::TYPE_REF,
                    table_type::TYPE_DEF,
                    table_type::METHOD_DEF,
                    table_type::MODULE_REF,
                    table_type::TYPE_SPEC,
                ],
                13,
            ),
            has_semantics_index_size: compute_coded_index_size(
                &[table_type::EVENT, table_type::PROPERTY],
                15,
            ),
            method_def_or_ref_index_size: compute_coded_index_size(
                &[table_type::MEMBER_REF, table_type::METHOD_DEF],
                15,
            ),
            member_forwarded_index_size: compute_coded_index_size(
                &[table_type::FIELD, table_type::METHOD_DEF],
                15,
            ),
            implementation_index_size: compute_coded_index_size(
                &[
                    table_type::FILE,
                    table_type::ASSEMBLY_REF,
                    table_type::EXPORTED_TYPE,
                ],
                14,
            ),
            custom_attribute_type_index_size: compute_coded_index_size(
                &[table_type::METHOD_DEF, table_type::MEMBER_REF],
                13,
            ),
            resolution_scope_index_size: compute_coded_index_size(
                &[
                    table_type::MODULE,
                    table_type::MODULE_REF,
                    table_type::ASSEMBLY_REF,
                    table_type::TYPE_REF,
                ],
                14,
            ),
            type_or_method_def_index_size: compute_coded_index_size(
                &[table_type::TYPE_DEF, table_type::METHOD_DEF],
                15,
            ),
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
            table_type::MODULE => self.skip(2 + self.string_index_size + 3 * self.guid_index_size),
            table_type::TYPE_REF => {
                self.skip(self.resolution_scope_index_size + 2 * self.string_index_size)
            }
            table_type::TYPE_DEF => self.skip(
                4 + 2 * self.string_index_size
                    + self.type_def_or_ref_index_size
                    + self.field_index_size
                    + self.method_def_index_size,
            ),
            table_type::FIELD => self.skip(2 + self.string_index_size + self.blob_index_size),
            table_type::METHOD_DEF => {
                self.skip(8 + self.string_index_size + self.blob_index_size + self.param_index_size)
            }
            table_type::PARAM => self.skip(4 + self.string_index_size),
            table_type::INTERFACE_IMPL => {
                self.skip(self.type_def_index_size + self.type_def_or_ref_index_size)
            }
            table_type::MEMBER_REF => self.skip(
                self.member_ref_parent_index_size + self.string_index_size + self.blob_index_size,
            ),
            table_type::CONSTANT => {
                self.skip(2 + self.blob_index_size + self.has_constant_index_size)
            }
            table_type::CUSTOM_ATTRIBUTE => self.skip(
                self.has_custom_attribute_index_size
                    + self.custom_attribute_type_index_size
                    + self.blob_index_size,
            ),
            table_type::FIELD_MARSHALL => {
                self.skip(self.has_field_marshall_index_size + self.blob_index_size)
            }
            table_type::DECL_SECURITY => {
                self.skip(2 + self.has_decl_security_index_size + self.blob_index_size)
            }
            table_type::CLASS_LAYOUT => self.skip(6 + self.type_def_index_size),
            table_type::FIELD_LAYOUT => self.skip(4 + self.field_index_size),
            table_type::STAND_ALONE_SIG => self.skip(self.blob_index_size),
            table_type::EVENT_MAP => self.skip(self.type_def_index_size + self.event_index_size),
            table_type::EVENT => {
                self.skip(2 + self.string_index_size + self.type_def_or_ref_index_size)
            }
            table_type::PROPERTY_MAP => {
                self.skip(self.type_def_index_size + self.property_index_size)
            }
            table_type::PROPERTY => self.skip(2 + self.string_index_size + self.blob_index_size),
            table_type::METHOD_SEMANTICS => {
                self.skip(2 + self.method_def_index_size + self.has_semantics_index_size)
            }
            table_type::METHOD_IMPL => {
                self.skip(self.type_def_index_size + 2 * self.method_def_or_ref_index_size)
            }
            table_type::MODULE_REF => self.parse_module_ref(res),
            table_type::TYPE_SPEC => self.skip(self.blob_index_size),
            table_type::IMPL_MAP => self.skip(
                2 + self.member_forwarded_index_size
                    + self.string_index_size
                    + self.module_ref_index_size,
            ),
            table_type::FIELD_RVA => self.parse_field_rva(res),
            table_type::ASSEMBLY => self.parse_assembly_table(res),
            table_type::ASSEMBLY_PROCESSOR => self.skip(4),
            table_type::ASSEMBLY_OS => self.skip(12),
            table_type::ASSEMBLY_REF => self.parse_assembly_ref_table(res),
            table_type::ASSEMBLY_REF_PROCESSOR => self.skip(4 + self.assembly_ref_index_size),
            table_type::ASSEMBLY_REF_OS => self.skip(12 + self.assembly_ref_index_size),
            table_type::FILE => self.skip(4 + self.string_index_size + self.blob_index_size),
            table_type::EXPORTED_TYPE => {
                self.skip(8 + 2 * self.string_index_size + self.implementation_index_size)
            }
            table_type::MANIFEST_RESOURCE => self.parse_manifest_resource_table(res),
            table_type::NESTED_CLASS => self.skip(2 * self.type_def_index_size),
            table_type::GENERIC_PARAM => {
                self.skip(4 + self.type_or_method_def_index_size + self.string_index_size)
            }
            table_type::METHOD_SPEC => {
                self.skip(self.method_def_or_ref_index_size + self.blob_index_size)
            }
            table_type::GENERIC_PARAM_CONSTRAINT => {
                self.skip(self.generic_param_index_size + self.type_def_or_ref_index_size)
            }
            _ => {
                // We are matching an unknown table. This means we are no longer to parse
                // anything, since we do not know the size of this table, and can't parse the
                // rest. We thus abort the parsing.
                Err(())
            }
        }
    }

    // ECMA 335, II.22.31
    fn parse_module_ref(&mut self, res: &mut HashMap<&'static str, Value>) -> Result<(), ()> {
        let name = self.read_string()?;

        let len = match res
            .entry("modulerefs")
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(vec) => {
                vec.push(name.map(Value::bytes).into());
                vec.len()
            }
            // Safety: the "modulesrefs" key can only contain a Value::Array by construction
            // in this module.
            _ => unreachable!(),
        };

        let _ = res.insert("number_of_modulerefs", len.into());
        Ok(())
    }

    // ECMA 335, II.22.18
    fn parse_field_rva(&mut self, res: &mut HashMap<&'static str, Value>) -> Result<(), ()> {
        let rva = self.read_u32()?;
        self.skip(self.field_index_size)?;

        let len = match res
            .entry("field_offsets")
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(vec) => {
                vec.push(va_to_file_offset(self.mem, &self.sections, rva).into());
                vec.len()
            }
            // Safety: the "field_offsets" key can only contain a Value::Array by construction
            // in this module.
            _ => unreachable!(),
        };

        let _ = res.insert("number_of_field_offsets", len.into());
        Ok(())
    }

    // ECMA 335, II.22.2
    fn parse_assembly_table(&mut self, res: &mut HashMap<&'static str, Value>) -> Result<(), ()> {
        self.skip(4)?; // hash_alg_id
        let major_version = self.read_u16()?;
        let minor_version = self.read_u16()?;
        let build_number = self.read_u16()?;
        let revision_number = self.read_u16()?;
        self.skip(4 + self.blob_index_size)?; // flags
        let name = self.read_string()?;
        let culture = self.read_string()?;

        res.extend([(
            "assembly",
            Value::object([
                (
                    "version",
                    Value::object([
                        ("major", major_version.into()),
                        ("minor", minor_version.into()),
                        ("build_number", build_number.into()),
                        ("revision_number", revision_number.into()),
                    ]),
                ),
                ("name", name.map(Value::bytes).into()),
                ("culture", culture.map(Value::bytes).into()),
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
        let public_key_or_token = self.read_blob()?;
        let name = self.read_string()?;
        self.skip(self.string_index_size + self.blob_index_size)?;

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
                            ("minor", minor_version.into()),
                            ("build_number", build_number.into()),
                            ("revision_number", revision_number.into()),
                        ]),
                    ),
                    (
                        "public_key_or_token",
                        public_key_or_token.map(Value::bytes).into(),
                    ),
                    ("name", name.map(Value::bytes).into()),
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

    // ECMA 335, II.22.24
    fn parse_manifest_resource_table(
        &mut self,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        let offset = self.read_u32()?;
        self.skip(4)?;
        let name = self.read_string()?;
        self.skip(self.implementation_index_size)?;

        let len = match res
            .entry("resources")
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(vec) => {
                vec.push(Value::object([
                    ("offset", offset.into()),
                    // TODO
                    ("length", Value::Undefined),
                    ("name", name.map(Value::bytes).into()),
                ]));
                vec.len()
            }
            // Safety: the "resources" key can only contain a Value::Array by construction
            // in this module.
            _ => unreachable!(),
        };
        let _ = res.insert("number_of_resources", len.into());

        Ok(())
    }

    fn skip(&mut self, nb_bytes: u8) -> Result<(), ()> {
        self.data.skip(usize::from(nb_bytes))
    }

    fn read_index(&mut self, index_size: u8) -> Result<u32, ()> {
        if index_size == 4 {
            self.read_u32()
        } else {
            self.read_u16().map(u32::from)
        }
    }

    fn read_string(&mut self) -> Result<Option<&'data [u8]>, ()> {
        let index = self.read_index(self.string_index_size)? as usize;
        if index == 0 {
            return Ok(None);
        }

        let Some(slice) = self.strings_stream.and_then(|v| v.get(index..)) else {
            return Ok(None);
        };

        match slice.iter().position(|c| *c == b'\0') {
            Some(pos) => Ok(Some(&slice[..pos])),
            None => Ok(None),
        }
    }

    fn read_blob(&mut self) -> Result<Option<&'data [u8]>, ()> {
        let index = self.read_index(self.blob_index_size)? as usize;
        if index == 0 {
            return Ok(None);
        }

        Ok(self
            .blobs_stream
            .and_then(|v| v.get(index..))
            .and_then(|slice| read_blob(&mut Bytes(slice))))
    }

    fn read_u16(&mut self) -> Result<u16, ()> {
        self.data.read::<U16<LE>>().map(|v| v.get(LE))
    }

    fn read_u32(&mut self) -> Result<u32, ()> {
        self.data.read::<U32<LE>>().map(|v| v.get(LE))
    }
}

fn read_blob<'data>(bytes: &mut Bytes<'data>) -> Option<&'data [u8]> {
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

    bytes.read_slice(length).ok()
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
