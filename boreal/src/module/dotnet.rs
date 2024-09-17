use std::collections::HashMap;

use object::pe::{
    ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_FILE_DLL,
};
use object::read::pe::{DataDirectories, ImageNtHeaders};
use object::{Bytes, FileKind, LittleEndian as LE, Pod, ReadRef, U16, U32, U64};

use super::pe::utils as pe_utils;
use super::{Module, ModuleData, ModuleDataMap, ScanContext, StaticValue, Type, Value};

const MAX_PARAM_COUNT: u32 = 2000;
const MAX_GEN_PARAM_COUNT: u32 = 1000;

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
            ("module_name", Type::Bytes),
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

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        data_map.insert::<Self>(Data::default());
    }

    fn get_dynamic_values(&self, ctx: &mut ScanContext, out: &mut HashMap<&'static str, Value>) {
        let Some(data) = ctx.module_data.get_mut::<Self>() else {
            return;
        };

        if data.found_pe {
            // We already found a PE in a region, so ignore the others
            return;
        }

        let res = match FileKind::parse(ctx.region.mem) {
            Ok(FileKind::Pe32) => {
                parse_file::<ImageNtHeaders32>(ctx.region.mem, ctx.process_memory)
            }
            Ok(FileKind::Pe64) => {
                parse_file::<ImageNtHeaders64>(ctx.region.mem, ctx.process_memory)
            }
            _ => None,
        };

        if let Some(values) = res {
            *out = values;
            data.found_pe = true;
        }
    }
}

#[derive(Default)]
pub struct Data {
    found_pe: bool,
}

impl ModuleData for Dotnet {
    type PrivateData = Data;
    type UserData = ();
}

fn parse_file<HEADERS: ImageNtHeaders>(
    mem: &[u8],
    process_memory: bool,
) -> Option<HashMap<&'static str, Value>> {
    // A dotnet file is a PE, with details stored in it. First, parse the PE headers.
    let dos_header = ImageDosHeader::parse(mem).ok()?;
    let mut offset = dos_header.nt_headers_offset().into();
    let (nt_headers, data_dirs) = HEADERS::parse(mem, &mut offset).ok()?;

    if process_memory {
        let hdr = nt_headers.file_header();
        let characteristics = hdr.characteristics.get(LE);
        if (characteristics & IMAGE_FILE_DLL) != 0 {
            return None;
        }
    }

    // Once we passed those checks, we always at least set is_dotnet, but not before.
    // This is annoying, would be nice to change this behavior in YARA.
    let sections = pe_utils::SectionTable::new(nt_headers, mem, offset)?;
    Some(
        parse_file_inner(mem, data_dirs, sections)
            .unwrap_or_else(|| [("is_dotnet", 0.into())].into()),
    )
}

fn parse_file_inner(
    mem: &[u8],
    data_dirs: DataDirectories,
    sections: pe_utils::SectionTable,
) -> Option<HashMap<&'static str, Value>> {
    // II.25.3.3 : the PE contains a data directory named "CLI header"
    let dir = data_dirs.get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
    let cli_data = sections.get_dir_data(mem, *dir)?;
    let cli_data = Bytes(cli_data);
    let cli_header = cli_data.read_at::<CliHeader>(0).ok()?;

    let metadata_root_offset: u64 = sections
        .get_file_range_at(cli_header.metadata_rva.get(LE))?
        .0
        .into();
    let metadata = cli_header.metadata(mem, &sections).ok()?;

    let streams = get_streams(&metadata, metadata_root_offset);

    let mut res: HashMap<&'static str, Value> = [
        ("is_dotnet", Value::Integer(1)),
        ("version", Value::bytes(metadata.version)),
        ("streams", Value::Array(streams)),
        (
            "number_of_streams",
            Value::Integer(metadata.number_of_streams.into()),
        ),
    ]
    .into();

    add_guids(&metadata, &mut res);
    add_user_strings(&metadata, &mut res);

    let resource_base = sections
        .get_file_range_at(cli_header.resources_metadata.get(LE))
        .map(|v| u64::from(v.0));

    add_metadata_tables(mem, &metadata, resource_base, sections, &mut res);

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
        // Only pick 16 guids max
        .take(16)
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
        // Since there is an additional byte that we filter, this means
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
    resource_base: Option<u64>,
    sections: pe_utils::SectionTable<'data>,
    res: &mut HashMap<&'static str, Value>,
) {
    let Some(stream_data) = metadata
        .get_stream(b"#~")
        .or_else(|| metadata.get_stream(b"#-"))
    else {
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

        // Apply the same sanity check as done in YARA.
        if *count > 15_000 {
            return;
        }
    }

    // Build our parsing helper: this will hold the current cursor on
    // the data, as well as the sizes of all the indexes.
    let mut tables_data = TablesData::new(
        mem,
        bytes,
        sections,
        resource_base,
        strings_stream,
        blobs_stream,
        &table_counts,
        header.heap_sizes,
    );

    // Then, parsing every table in order
    for table_index in 0..64 {
        let nb_tables = table_counts[usize::from(table_index)];
        if nb_tables == 0 {
            continue;
        }

        if tables_data
            .parse_table_type(table_index, nb_tables, res)
            .is_err()
        {
            break;
        }
    }

    tables_data.finalize(res);
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

    // The following tables are undocumented in ECMA 335
    // However, we can find traces of them in microsoft's documentation
    // and the CLR source code.
    // See for example in
    // <https://learn.microsoft.com/en-us/dotnet/api/system.reflection.metadata.ecma335.tableindex>
    pub const FIELD_PTR: u8 = 0x03;
    pub const METHOD_PTR: u8 = 0x05;
    pub const PARAM_PTR: u8 = 0x07;
    pub const EVENT_PTR: u8 = 0x13;
    pub const PROPERTY_PTR: u8 = 0x16;
    pub const ENC_LOG: u8 = 0x1E;
    pub const ENC_MAP: u8 = 0x1F;
}

struct TablesData<'data> {
    mem: &'data [u8],
    data: Bytes<'data>,

    resource_base: Option<u64>,
    sections: pe_utils::SectionTable<'data>,

    // Contents of the string stream
    strings_stream: Option<&'data [u8]>,
    // Contents of the blob stream
    blobs_stream: Option<&'data [u8]>,

    // Slices matching some tables. Used to parse
    // on demand some tables when retrieving details for
    // some fields (eg typelib).
    // Those are filled on demand: the table type must have been
    // already parsed, otherwise the field will always be None.
    type_ref_table_data: Option<Bytes<'data>>,
    type_spec_table_data: Option<Bytes<'data>>,
    interface_impl_table_data: Option<Bytes<'data>>,
    member_ref_table_data: Option<Bytes<'data>>,

    // Details on classes.
    //
    // Since we get data for classes from multiple tables,
    // this object is used to stored the details while we are
    // processing tables.
    classes: Vec<Class>,
    // Details on methods.
    methods: Vec<Method>,
    // Details on param names.
    param_names: Vec<Value>,

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
    #[allow(clippy::too_many_arguments)]
    fn new(
        mem: &'data [u8],
        mut data: Bytes<'data>,
        sections: pe_utils::SectionTable<'data>,
        resource_base: Option<u64>,
        strings_stream: Option<&'data [u8]>,
        blobs_stream: Option<&'data [u8]>,
        table_counts: &[u32; 64],
        heap_sizes: u8,
    ) -> Self {
        // Get index sizes for indexing in other streams
        let wide_string_index = heap_sizes & 0x01 != 0;
        let wide_guid_index = heap_sizes & 0x02 != 0;
        let wide_blob_index = heap_sizes & 0x04 != 0;

        if (heap_sizes & 0x40) != 0 {
            // See
            // <https://github.com/dotnet/coreclr/blob/fcd2d327/src/md/inc/metamodel.h#L247>
            let _r = data.skip(4);
        }

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
            resource_base,
            strings_stream,
            blobs_stream,

            type_ref_table_data: None,
            type_spec_table_data: None,
            interface_impl_table_data: None,
            member_ref_table_data: None,

            string_index_size: if wide_string_index { 4 } else { 2 },
            guid_index_size: if wide_guid_index { 4 } else { 2 },
            blob_index_size: if wide_blob_index { 4 } else { 2 },

            classes: Vec::new(),
            methods: Vec::new(),
            param_names: Vec::new(),

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

    fn finalize(mut self, res: &mut HashMap<&'static str, Value>) {
        // The classes and methods details are built using many tables, with some not in
        // the right order to build everything progressively. In those cases, the computation
        // of details is delayed until this method, when we have finished parsing all tables and
        // can cross reference everything.

        // First, compute the types of the methods.
        // To do so, we iterate over methods in reverse: this allows us to always know
        // the end of the range of params for a given method.
        // This is delayed until now because we need the class generic params to do this.
        let mut last_method_index = self.methods.len();
        for class in self.classes.iter().rev() {
            if let Some(idx) = class.method_def_first_index {
                let idx = idx as usize;
                if idx <= self.methods.len() {
                    for i in idx..last_method_index {
                        if let Some(sig) = self.methods[i].signature.as_ref() {
                            let mut sig = Bytes(sig);
                            if let Some(sig) = self.parse_method_def_signature(
                                &mut sig,
                                &class.generic_params,
                                &self.methods[i].generic_params,
                                0,
                            ) {
                                self.methods[i].set_signature(sig);
                            }
                        }
                    }
                }
                last_method_index = idx;
            }
        }

        // Then, add the param names to the right methods, using the same reverse trick.
        for method in self.methods.iter_mut().rev() {
            if let Some(idx) = method.param_name_first_index {
                let idx = idx as usize;

                for (i, param) in method.params.iter_mut().enumerate() {
                    match self.param_names.get(idx + i) {
                        Some(param_name) => {
                            param.name = param_name.clone();
                        }
                        None => {
                            param.name = Value::Bytes(format!("P_{i}").into_bytes());
                        }
                    }
                }
            }
        }

        // Then, add the methods to the right classes, using the same reverse trick.
        for class in self.classes.iter_mut().rev() {
            if let Some(idx) = class.method_def_first_index {
                let idx = idx as usize;
                if idx <= self.methods.len() {
                    class.methods = self.methods.drain(idx..).map(Method::into_value).collect();
                }
            }
        }

        // Then, resolve the 'extends' index
        for i in 0..self.classes.len() {
            let extends_index = self.classes[i].extends_index;
            if let Some(base_class) =
                self.get_type_fullname(extends_index, &self.classes[i].generic_params, &[], 0)
            {
                self.classes[i].base_types.push(Value::Bytes(base_class));
            }
        }

        // Then, resolve the interface implementations
        if let Some(mut interface_impl_table) = self.interface_impl_table_data.take() {
            while let Some((class_index, type_def_or_ref_index)) =
                self.read_interface(&mut interface_impl_table)
            {
                let Ok(class_index) = usize::try_from(class_index) else {
                    continue;
                };
                // 0 is invalid index, and 1 points to the first class, which we do not include.
                // So remove 2 to get the real index into our vec
                if class_index <= 1 || (class_index - 2) >= self.classes.len() {
                    continue;
                }
                if let Some(interface_name) = self.get_type_fullname(
                    type_def_or_ref_index,
                    &self.classes[class_index - 2].generic_params,
                    &[],
                    0,
                ) {
                    self.classes[class_index - 2]
                        .base_types
                        .push(Value::Bytes(interface_name));
                }
            }
        }

        // Finally, convert to the final value
        let classes: Vec<Value> = self.classes.into_iter().map(Class::into_value).collect();

        res.extend([
            ("number_of_classes", classes.len().into()),
            ("classes", Value::Array(classes)),
        ]);
    }

    // Parse a table of the given index code.
    //
    // If Err is returned, the end of the data has been reached and nothing more can be read.
    fn parse_table_type(
        &mut self,
        table_index: u8,
        nb_tables: u32,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        fn get_tables_len(nb_tables: u32, table_size: u8) -> Result<usize, ()> {
            (nb_tables as usize)
                .checked_mul(usize::from(table_size))
                .ok_or(())
        }

        match table_index {
            table_type::MODULE => self.parse_modules(nb_tables, res),
            table_type::TYPE_REF => {
                let len = get_tables_len(nb_tables, self.type_ref_table_size())?;
                self.type_ref_table_data = Some(self.data.read_bytes(len)?);
                Ok(())
            }
            table_type::TYPE_DEF => self.parse_type_defs(nb_tables),
            table_type::FIELD => {
                let len =
                    get_tables_len(nb_tables, 2 + self.string_index_size + self.blob_index_size)?;
                self.data.skip(len)
            }
            table_type::METHOD_DEF => self.parse_method_defs(nb_tables),
            table_type::PARAM => self.parse_params(nb_tables),
            table_type::INTERFACE_IMPL => {
                let len = get_tables_len(
                    nb_tables,
                    self.type_def_index_size + self.type_def_or_ref_index_size,
                )?;
                self.interface_impl_table_data = Some(self.data.read_bytes(len)?);
                Ok(())
            }
            table_type::MEMBER_REF => {
                let len = get_tables_len(nb_tables, self.member_ref_table_size())?;
                self.member_ref_table_data = Some(self.data.read_bytes(len)?);
                Ok(())
            }
            table_type::CONSTANT => self.parse_constants(nb_tables, res),
            table_type::CUSTOM_ATTRIBUTE => self.parse_custom_attributes(nb_tables, res),
            table_type::FIELD_MARSHALL => {
                let len = get_tables_len(
                    nb_tables,
                    self.has_field_marshall_index_size + self.blob_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::DECL_SECURITY => {
                let len = get_tables_len(
                    nb_tables,
                    2 + self.has_decl_security_index_size + self.blob_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::CLASS_LAYOUT => {
                let len = get_tables_len(nb_tables, 6 + self.type_def_index_size)?;
                self.data.skip(len)
            }
            table_type::FIELD_LAYOUT => {
                let len = get_tables_len(nb_tables, 4 + self.field_index_size)?;
                self.data.skip(len)
            }
            table_type::STAND_ALONE_SIG => {
                let len = get_tables_len(nb_tables, self.blob_index_size)?;
                self.data.skip(len)
            }
            table_type::EVENT_MAP => {
                let len =
                    get_tables_len(nb_tables, self.type_def_index_size + self.event_index_size)?;
                self.data.skip(len)
            }
            table_type::EVENT => {
                let len = get_tables_len(
                    nb_tables,
                    2 + self.string_index_size + self.type_def_or_ref_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::PROPERTY_MAP => {
                let len = get_tables_len(
                    nb_tables,
                    self.type_def_index_size + self.property_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::PROPERTY => {
                let len =
                    get_tables_len(nb_tables, 2 + self.string_index_size + self.blob_index_size)?;
                self.data.skip(len)
            }
            table_type::METHOD_SEMANTICS => {
                let len = get_tables_len(
                    nb_tables,
                    2 + self.method_def_index_size + self.has_semantics_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::METHOD_IMPL => {
                let len = get_tables_len(
                    nb_tables,
                    self.type_def_index_size + 2 * self.method_def_or_ref_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::MODULE_REF => self.parse_module_ref(nb_tables, res),
            table_type::TYPE_SPEC => {
                let len = get_tables_len(nb_tables, self.type_spec_table_size())?;
                self.type_spec_table_data = Some(self.data.read_bytes(len)?);
                Ok(())
            }
            table_type::IMPL_MAP => {
                let len = get_tables_len(
                    nb_tables,
                    2 + self.member_forwarded_index_size
                        + self.string_index_size
                        + self.module_ref_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::FIELD_RVA => self.parse_field_rva(nb_tables, res),
            table_type::ASSEMBLY => self.parse_assembly_table(nb_tables, res),
            table_type::ASSEMBLY_PROCESSOR => {
                let len = get_tables_len(nb_tables, 4)?;
                self.data.skip(len)
            }
            table_type::ASSEMBLY_OS => {
                let len = get_tables_len(nb_tables, 12)?;
                self.data.skip(len)
            }
            table_type::ASSEMBLY_REF => self.parse_assembly_ref_table(nb_tables, res),
            table_type::ASSEMBLY_REF_PROCESSOR => {
                let len = get_tables_len(nb_tables, 4 + self.assembly_ref_index_size)?;
                self.data.skip(len)
            }
            table_type::ASSEMBLY_REF_OS => {
                let len = get_tables_len(nb_tables, 12 + self.assembly_ref_index_size)?;
                self.data.skip(len)
            }
            table_type::FILE => {
                let len =
                    get_tables_len(nb_tables, 4 + self.string_index_size + self.blob_index_size)?;
                self.data.skip(len)
            }
            table_type::EXPORTED_TYPE => {
                let len = get_tables_len(
                    nb_tables,
                    8 + 2 * self.string_index_size + self.implementation_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::MANIFEST_RESOURCE => self.parse_manifest_resource_table(nb_tables, res),
            table_type::NESTED_CLASS => self.parse_nested_class(nb_tables),
            table_type::GENERIC_PARAM => self.parse_generic_params(nb_tables),
            table_type::METHOD_SPEC => {
                let len = get_tables_len(
                    nb_tables,
                    self.method_def_or_ref_index_size + self.blob_index_size,
                )?;
                self.data.skip(len)
            }
            table_type::GENERIC_PARAM_CONSTRAINT => {
                let len = get_tables_len(
                    nb_tables,
                    self.generic_param_index_size + self.type_def_or_ref_index_size,
                )?;
                self.data.skip(len)
            }

            // Undocumented table types.
            // To find out their sizes, the CLR source code can be used.
            // See for example:
            // <https://github.com/dotnet/coreclr/blob/ed5dc83/src/inc/metamodelpub.h#L208>
            table_type::FIELD_PTR => {
                let len = get_tables_len(nb_tables, self.field_index_size)?;
                self.data.skip(len)
            }
            table_type::METHOD_PTR => {
                let len = get_tables_len(nb_tables, self.method_def_index_size)?;
                self.data.skip(len)
            }
            table_type::PARAM_PTR => {
                let len = get_tables_len(nb_tables, self.param_index_size)?;
                self.data.skip(len)
            }
            table_type::EVENT_PTR => {
                let len = get_tables_len(nb_tables, self.event_index_size)?;
                self.data.skip(len)
            }
            table_type::PROPERTY_PTR => {
                let len = get_tables_len(nb_tables, self.property_index_size)?;
                self.data.skip(len)
            }
            table_type::ENC_LOG => {
                let len = get_tables_len(nb_tables, 8)?;
                self.data.skip(len)
            }
            table_type::ENC_MAP => {
                let len = get_tables_len(nb_tables, 4)?;
                self.data.skip(len)
            }
            _ => {
                // We are matching an unknown table. This means we are no longer to parse
                // anything, since we do not know the size of this table, and can't parse the
                // rest. We thus abort the parsing.
                Err(())
            }
        }
    }

    // EMCA 335, II.22.30
    fn parse_modules(&mut self, nb_tables: u32, res: &mut HashMap<&str, Value>) -> Result<(), ()> {
        for i in 0..nb_tables {
            self.data.skip(2)?; // generation
            let name = self.read_string()?;
            self.data.skip(3 * usize::from(self.guid_index_size))?;

            if i == 0 {
                let _r = res.insert("module_name", name.map(Value::bytes).into());
            }
        }
        Ok(())
    }

    // ECMA 335, II.22.37
    fn parse_type_defs(&mut self, nb_tables: u32) -> Result<(), ()> {
        for i in 0..nb_tables {
            let flags = read_u32(&mut self.data)?; // Flags
            let mut name = self.read_string()?;

            // Generic names end with the ` character and an number indicating the number
            // of generic types, we remove it.
            if let Some(name) = name.as_mut() {
                if let Some(pos) = name.iter().position(|b| *b == b'`') {
                    *name = &name[..pos];
                }
            }

            let namespace = self.read_string()?;

            let extends_index = read_index(&mut self.data, self.type_def_or_ref_index_size)?;
            self.data.skip(usize::from(self.field_index_size))?;
            let method_def_index = read_index(&mut self.data, self.method_def_index_size)?;

            // Ignore the first row, it's always set to a pseudo class
            if i == 0 {
                continue;
            }

            self.classes.push(Class {
                flags,
                name: name.map(ToOwned::to_owned),
                namespace: namespace.map(ToOwned::to_owned),
                methods: Vec::new(),
                generic_params: Vec::new(),
                method_def_first_index: if method_def_index == 0 {
                    None
                } else {
                    Some(method_def_index - 1)
                },
                extends_index,
                base_types: Vec::new(),
            });
        }

        Ok(())
    }

    // ECMA 335, II.22.26
    fn parse_method_defs(&mut self, nb_tables: u32) -> Result<(), ()> {
        for _ in 0..nb_tables {
            // skip RVA, ImplFlags
            self.data.skip(6)?;
            let flags = read_u16(&mut self.data)?;
            let name = self.read_string()?;
            let signature = self.read_blob()?;
            let param_index = read_index(&mut self.data, self.param_index_size)?;

            self.methods.push(Method {
                flags,
                name: name.map(ToOwned::to_owned),
                generic_params: Vec::new(),
                return_type: None,
                params: Vec::new(),
                param_name_first_index: if param_index == 0 {
                    None
                } else {
                    Some(param_index - 1)
                },
                // TODO: avoid cloning the slice here, we should be able to keep it as a slice.
                signature: signature.map(<[u8]>::to_vec),
            });
        }
        Ok(())
    }

    // ECMA 335, II.22.33
    fn parse_params(&mut self, nb_tables: u32) -> Result<(), ()> {
        for _ in 0..nb_tables {
            // skip Flags and Sequence
            self.data.skip(4)?;
            let name = self.read_string()?;

            // YARA uses an empty string here instead of undefined for index=0
            self.param_names
                .push(Value::bytes(name.unwrap_or_default()));
        }
        Ok(())
    }

    // ECMA 335, II.22.9
    fn parse_constants(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&str, Value>,
    ) -> Result<(), ()> {
        let mut constants = Vec::new();
        for _ in 0..nb_tables {
            // Parse the constant table, keep the type and blob index
            let ty = read_u16(&mut self.data)?;
            self.data.skip(usize::from(self.has_constant_index_size))?;
            let value = read_index(&mut self.data, self.blob_index_size)?;

            // We only keep the string constants, see II.23.1.16
            if ty != 0x0e {
                continue;
            }

            constants.push(if value == 0 {
                Value::Bytes(Vec::new())
            } else {
                match self.get_blob(value as usize) {
                    Some(v) => Value::bytes(v),
                    None => Value::Undefined,
                }
            });
        }

        res.extend([
            ("number_of_constants", constants.len().into()),
            ("constants", Value::Array(constants)),
        ]);
        Ok(())
    }

    // ECMA 335, II.22.10
    fn parse_custom_attributes(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&str, Value>,
    ) -> Result<(), ()> {
        let mut found_typelib = false;
        let mut typelib = None;

        for _ in 0..nb_tables {
            let parent = read_index(&mut self.data, self.has_custom_attribute_index_size)?;
            let typ = read_index(&mut self.data, self.custom_attribute_type_index_size)?;

            if !found_typelib && self.custom_attribute_is_typelib(parent, typ) {
                found_typelib = true;
                // See II.23.3
                typelib = self
                    .read_blob()?
                    .and_then(|blob| {
                        // Remove prolog
                        blob.strip_prefix(b"\x01\x00")
                    })
                    .and_then(|v| {
                        // We expect the length in a single byte, then the string
                        if v.is_empty() {
                            None
                        } else {
                            let packed_len = v[0];
                            if packed_len == 0x00 || packed_len == 0xFF {
                                None
                            } else {
                                v.get(1..=usize::from(packed_len))
                            }
                        }
                    });
            } else {
                self.data.skip(usize::from(self.blob_index_size))?;
            }
        }

        let _r = res.insert("typelib", typelib.map(Value::bytes).into());
        Ok(())
    }

    fn custom_attribute_is_typelib(&self, parent: u32, typ: u32) -> bool {
        // Try to find typelib from the custom attribute.
        // We want to find a custom attribute:
        // - with a parent that must be an Assembly table
        // - with a type that must be a MemberRef table
        // - this member must have a class that is a TypeRef table
        // - type name must be "GuidAttribute"

        // Check parent points to an assembly table.
        // See "HasCustomAttribute" coded index in ECMA 335 II.24.2.6:
        // Assembly is the tag 14.
        if (parent & 0x1F) != 14 {
            return false;
        }

        // Check type is a MemberRef table.
        // See "CustomAttributeType" coded index in ECMA 335 II.24.2.6:
        // MemberRef is the tag 3.
        if (typ & 0x07) != 3 {
            return false;
        }

        // Get the data for the memberref table, and skip all previous memberref
        // until we reach our index.
        let member_ref_index = typ >> 3;
        let Some(mut member_ref_data) = self.member_ref_table_data.and_then(|table| {
            get_record_in_table(table, self.member_ref_table_size(), member_ref_index)
        }) else {
            return false;
        };

        // Read the first field, which is the class linked to the member ref.
        // See ECMA 335 II.22.25
        let Ok(class) = read_index(&mut member_ref_data, self.member_ref_parent_index_size) else {
            return false;
        };

        // This class must be an index into the TypeRef table.
        // See "MemberRefParent" coded index in ECMA 335 II.24.2.6:
        // TypeRef is the tag 1.
        if (class & 0x07) != 1 {
            return false;
        }

        // Get the data for the typeref table, and skip all previous typeref
        // until we reach our index.
        let type_ref_index = class >> 3;
        let Some(mut type_ref_data) = self.type_ref_table_data.and_then(|table| {
            get_record_in_table(table, self.type_ref_table_size(), type_ref_index)
        }) else {
            return false;
        };

        // See ECMA 335 II.22.38
        // Skip ResolutionScope and read name index
        if type_ref_data
            .skip(usize::from(self.resolution_scope_index_size))
            .is_err()
        {
            return false;
        }
        let Ok(name) = read_index(&mut type_ref_data, self.string_index_size) else {
            return false;
        };
        let Some(type_ref_name) = self.get_string(name as usize) else {
            return false;
        };

        type_ref_name == b"GuidAttribute"
    }

    // ECMA 335, II.22.31
    fn parse_module_ref(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        let modulerefs: Vec<Value> = (0..nb_tables)
            .map(|_| match self.read_string()? {
                Some(v) => Ok(Value::bytes(v)),
                None => Ok(Value::Undefined),
            })
            .collect::<Result<Vec<Value>, ()>>()?;

        res.extend([
            ("number_of_modulerefs", modulerefs.len().into()),
            ("modulerefs", Value::Array(modulerefs)),
        ]);
        Ok(())
    }

    // ECMA 335, II.22.18
    fn parse_field_rva(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        let modulerefs: Vec<Value> = (0..nb_tables)
            .map(|_| {
                let rva = read_u32(&mut self.data)?;
                self.data.skip(usize::from(self.field_index_size))?;

                Ok(pe_utils::va_to_file_offset(self.mem, &self.sections, rva).into())
            })
            .collect::<Result<Vec<Value>, ()>>()?;

        res.extend([
            ("number_of_field_offsets", modulerefs.len().into()),
            ("field_offsets", Value::Array(modulerefs)),
        ]);
        Ok(())
    }

    // ECMA 335, II.22.2
    fn parse_assembly_table(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        for i in 0..nb_tables {
            self.data.skip(4)?; // hash_alg_id
            let major_version = read_u16(&mut self.data)?;
            let minor_version = read_u16(&mut self.data)?;
            let build_number = read_u16(&mut self.data)?;
            let revision_number = read_u16(&mut self.data)?;
            self.data.skip(usize::from(4 + self.blob_index_size))?; // flags
            let name = self.read_string()?;
            let culture = self.read_string()?;

            if i == 0 {
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
            }
        }
        Ok(())
    }

    // ECMA 335, II.22.5
    fn parse_assembly_ref_table(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        let assembly_refs: Vec<Value> = (0..nb_tables)
            .map(|_| {
                let major_version = read_u16(&mut self.data)?;
                let minor_version = read_u16(&mut self.data)?;
                let build_number = read_u16(&mut self.data)?;
                let revision_number = read_u16(&mut self.data)?;
                self.data.skip(4)?; // flags
                let public_key_or_token = match self.read_blob()? {
                    Some(v) if !v.is_empty() => Some(v),
                    _ => None,
                };
                let name = self.read_string()?;
                self.data
                    .skip(usize::from(self.string_index_size + self.blob_index_size))?;

                Ok(Value::object([
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
                ]))
            })
            .collect::<Result<Vec<Value>, ()>>()?;

        res.extend([
            ("number_of_assembly_refs", assembly_refs.len().into()),
            ("assembly_refs", Value::Array(assembly_refs)),
        ]);
        Ok(())
    }

    // ECMA 335, II.22.24
    fn parse_manifest_resource_table(
        &mut self,
        nb_tables: u32,
        res: &mut HashMap<&'static str, Value>,
    ) -> Result<(), ()> {
        let mut resources = Vec::new();
        for _ in 0..nb_tables {
            let offset = read_u32(&mut self.data)?;
            self.data.skip(4)?;
            let name = self.read_string()?;
            let implementation = read_index(&mut self.data, self.implementation_index_size)?;

            let (real_offset, length) = if implementation == 0 {
                // Resource is in this file, retrieve offset and length

                // Offset is relative to the resource entry in this file.
                let real_offset = self
                    .resource_base
                    .and_then(|base| base.checked_add(u64::from(offset)));

                // We can get the length from reading into the entry
                // XXX: this comes from the yara logic, I haven't really understood where
                // this length comes from
                let length = real_offset
                    .and_then(|offset| self.mem.read_at::<U32<LE>>(offset).ok())
                    .map(|v| v.get(LE));

                // Add 4 to skip the length we just read
                (real_offset.and_then(|v| v.checked_add(4)), length)
            } else {
                (None, None)
            };

            resources.push(Value::object([
                // Add 4 to skip the size we just read
                ("offset", real_offset.into()),
                ("length", length.into()),
                ("name", name.map(Value::bytes).into()),
            ]));
        }

        res.extend([
            ("number_of_resources", resources.len().into()),
            ("resources", Value::Array(resources)),
        ]);
        Ok(())
    }

    // ECMA 335, II.22.32
    fn parse_nested_class(&mut self, nb_tables: u32) -> Result<(), ()> {
        for _ in 0..nb_tables {
            let nested_class = read_index(&mut self.data, self.type_def_index_size)? as usize;
            let enclosing_class = read_index(&mut self.data, self.type_def_index_size)? as usize;

            // 0 is unset, and we skip the first class, so this only makes sense
            // with indexes >= 2.
            if nested_class <= 1 || enclosing_class <= 1 {
                continue;
            }

            // Fix nested namespace by setting it from the enclosing class fullname
            // XXX: if the enclosing is also nested, this depends on the order in the nested class
            // table. If there an issue here?
            let namespace = self
                .classes
                .get(enclosing_class - 2)
                .and_then(Class::get_fullname);
            if let Some(nested) = self.classes.get_mut(nested_class - 2) {
                nested.namespace = namespace;
            }
        }
        Ok(())
    }

    // ECMA 335, II.22.20
    fn parse_generic_params(&mut self, nb_tables: u32) -> Result<(), ()> {
        for _ in 0..nb_tables {
            self.data.skip(4)?; // "Number" and "Flags"
            let owner = read_index(&mut self.data, self.type_or_method_def_index_size)?;
            let name = self.read_string()?;

            // Indexing is 1-based, 0 means unset.
            let Some(owner_index) = ((owner >> 1) as usize).checked_sub(1) else {
                continue;
            };

            // II.24.2.6:
            // 0 if the index points to a TypeDef
            // 1 if the index points to a MethodDef
            if owner & 0x01 == 0 {
                // We skip the first class in the classes vec.
                if owner_index >= 1 {
                    if let Some(class) = self.classes.get_mut(owner_index - 1) {
                        class.generic_params.push(name.map(ToOwned::to_owned));
                    }
                }
            } else if let Some(method) = self.methods.get_mut(owner_index) {
                method.generic_params.push(name.map(ToOwned::to_owned));
            }
        }

        Ok(())
    }

    fn read_interface(&self, interface_impl_table: &mut Bytes) -> Option<(u32, u32)> {
        let class_index = read_index(interface_impl_table, self.type_def_index_size).ok()?;
        let type_index = read_index(interface_impl_table, self.type_def_or_ref_index_size).ok()?;

        Some((class_index, type_index))
    }

    // retrieve the name of the type referred to by a TypeDefOrRef index.
    fn get_type_fullname(
        &self,
        type_def_or_ref_index: u32,
        class_gen_params: &[Option<Vec<u8>>],
        method_gen_params: &[Option<Vec<u8>>],
        rec_level: u8,
    ) -> Option<Vec<u8>> {
        let tag = type_def_or_ref_index & 0x03;
        let index = type_def_or_ref_index >> 2;

        #[allow(clippy::if_same_then_else)]
        if tag == 0 {
            // TypeDef. This is a Class which has been parsed already.
            if index <= 1 {
                None
            } else {
                let class = self.classes.get((index - 2) as usize)?;
                class
                    .name
                    .as_ref()
                    .map(|name| build_fullname(class.namespace.as_deref(), name))
            }
        } else if tag == 1 {
            // TypeRef
            let mut data =
                get_record_in_table(self.type_ref_table_data?, self.type_ref_table_size(), index)?;
            // Skip resolution scope, then get name and namespace
            data.skip(usize::from(self.resolution_scope_index_size))
                .ok()?;

            let name_index = read_index(&mut data, self.string_index_size).ok()? as usize;
            let mut name = self.get_string(name_index)?;

            // Generic names end with the ` character and an number indicating the number
            // of generic types, we remove it.
            if let Some(pos) = name.iter().position(|b| *b == b'`') {
                name = &name[..pos];
            }

            let ns_index = read_index(&mut data, self.string_index_size).ok()? as usize;
            let ns = self.get_string(ns_index);

            Some(build_fullname(ns, name))
        } else if tag == 2 {
            // TypeSpec
            let mut data = get_record_in_table(
                self.type_spec_table_data?,
                self.type_spec_table_size(),
                index,
            )?;
            let blob_index = read_index(&mut data, self.blob_index_size).ok()? as usize;
            let mut sig = Bytes(self.get_blob(blob_index)?);

            // II.23.2.14 : the signature is directly a type.
            // The type is more restrictive than what we parse, but since we would rather
            // be permissive in this module, this is perfectly fine.
            self.parse_sig_type(&mut sig, class_gen_params, method_gen_params, rec_level)
        } else {
            None
        }
    }

    // See II.23.2.1
    fn parse_method_def_signature(
        &self,
        sig: &mut Bytes,
        class_gen_params: &[Option<Vec<u8>>],
        method_gen_params: &[Option<Vec<u8>>],
        rec_level: u8,
    ) -> Option<Signature> {
        // First byte has flags
        let flags = sig.read::<u8>().ok()?;
        // If the generic flags is set, it is followed by the generic param count,
        // we do not care about it
        if (flags & 0x10) != 0 {
            let _ = read_encoded_uint(sig)?;
        }
        // Then we have the param count
        let param_count = read_encoded_uint(sig)?;
        if param_count > MAX_PARAM_COUNT {
            return None;
        }

        // And then the return type
        let return_type =
            self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level)?;

        let params_types = (0..param_count)
            .map(|_| self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level))
            .collect();

        Some(Signature {
            return_type,
            params_types,
        })
    }

    // See II.23.1.16
    fn parse_sig_type(
        &self,
        sig: &mut Bytes,
        class_gen_params: &[Option<Vec<u8>>],
        method_gen_params: &[Option<Vec<u8>>],
        rec_level: u8,
    ) -> Option<Vec<u8>> {
        let ty = sig.read::<u8>().ok()?;

        if rec_level > 16 {
            return None;
        }

        match ty {
            // ELEMENT_TYPE_VOID
            0x01 => Some(b"void".to_vec()),
            // ELEMENT_TYPE_BOOLEAN
            0x02 => Some(b"bool".to_vec()),
            // ELEMENT_TYPE_CHAR
            0x03 => Some(b"char".to_vec()),
            // ELEMENT_TYPE_I1
            0x04 => Some(b"sbyte".to_vec()),
            // ELEMENT_TYPE_U1
            0x05 => Some(b"byte".to_vec()),
            // ELEMENT_TYPE_I2
            0x06 => Some(b"short".to_vec()),
            // ELEMENT_TYPE_U2
            0x07 => Some(b"ushort".to_vec()),
            // ELEMENT_TYPE_I4
            0x08 => Some(b"int".to_vec()),
            // ELEMENT_TYPE_U4
            0x09 => Some(b"uint".to_vec()),
            // ELEMENT_TYPE_I8
            0x0a => Some(b"long".to_vec()),
            // ELEMENT_TYPE_U8
            0x0b => Some(b"ulong".to_vec()),
            // ELEMENT_TYPE_R4
            0x0c => Some(b"float".to_vec()),
            // ELEMENT_TYPE_R8
            0x0d => Some(b"double".to_vec()),
            // ELEMENT_TYPE_STRING
            0x0e => Some(b"string".to_vec()),
            // ELEMENT_TYPE_PTR
            0x0f => {
                // followed by a type
                let inner_type =
                    self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level + 1)?;
                let mut res = Vec::new();
                res.extend(b"Ptr<");
                res.extend(inner_type);
                res.push(b'>');
                Some(res)
            }
            // ELEMENT_TYPE_BYREF
            0x10 => {
                // followed by a type
                let inner_type =
                    self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level + 1)?;
                let mut res = Vec::new();
                res.extend(b"ref ");
                res.extend(inner_type);
                Some(res)
            }
            // ELEMENT_TYPE_VALUETYPE and ELEMENT_TYPE_CLASS
            0x11 | 0x12 => {
                // followed by a typed ref or typed def token
                let index = read_encoded_uint(sig)?;
                self.get_type_fullname(index, class_gen_params, method_gen_params, rec_level + 1)
            }
            // ELEMENT_TYPE_VAR
            0x13 => {
                let index = read_encoded_uint(sig)? as usize;
                class_gen_params
                    .get(index)
                    .and_then(|v| v.as_ref())
                    .cloned()
            }
            // ELEMENT_TYPE_ARRAY
            0x14 => {
                // type rank boundsCount bound1 .. loCount lo1 ..

                let ty =
                    self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level + 1)?;
                let mut res = Vec::new();
                res.extend(ty);
                res.push(b'[');

                // See II.23.2.13
                let rank = read_encoded_uint(sig)? as usize;
                let num_sizes = read_encoded_uint(sig)?;
                let sizes: Vec<i64> = (0..num_sizes)
                    .map(|_| read_encoded_uint(sig).map(i64::from))
                    .collect::<Option<Vec<_>>>()?;

                let num_lo_bounds = read_encoded_uint(sig)?;
                let lo_bounds: Vec<i32> = (0..num_lo_bounds)
                    .map(|_| read_encoded_sint(sig))
                    .collect::<Option<Vec<_>>>()?;

                for i in 0..rank {
                    if i > 0 {
                        res.push(b',');
                    }
                    match (sizes.get(i), lo_bounds.get(i)) {
                        (Some(size), Some(lo)) if *lo != 0 => {
                            res.extend(lo.to_string().as_bytes());
                            res.extend(b"...");
                            res.extend((i64::from(*lo) + *size - 1).to_string().as_bytes());
                        }
                        (Some(size), _) => res.extend(size.to_string().as_bytes()),
                        (None, Some(lo)) if *lo != 0 => {
                            res.extend(lo.to_string().as_bytes());
                            res.extend(b"...");
                        }
                        _ => (),
                    }
                }

                res.push(b']');

                Some(res)
            }
            // ELEMENT_TYPE_GENERICINST
            0x15 => {
                // type type-arg-count type-1 ... type-n
                let generic_type =
                    self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level)?;
                let count = read_encoded_uint(sig)?;
                if count > MAX_GEN_PARAM_COUNT {
                    return None;
                }

                let mut res = Vec::new();
                res.extend(generic_type);
                res.push(b'<');
                for i in 0..count {
                    if i != 0 {
                        res.push(b',');
                    }
                    res.extend(self.parse_sig_type(
                        sig,
                        class_gen_params,
                        method_gen_params,
                        rec_level,
                    )?);
                }
                res.push(b'>');
                Some(res)
            }
            // ELEMENT_TYPE_TYPEDBYREF
            0x16 => Some(b"TypedReference".to_vec()),
            // ELEMENT_TYPE_I
            0x18 => Some(b"IntPtr".to_vec()),
            // ELEMENT_TYPE_U
            0x19 => Some(b"UIntPtr".to_vec()),
            // ELEMENT_TYPE_FNPTR
            0x1b => {
                let Signature {
                    return_type,
                    params_types,
                } = self.parse_method_def_signature(
                    sig,
                    class_gen_params,
                    method_gen_params,
                    rec_level + 1,
                )?;

                let mut res = Vec::new();
                res.extend(b"FnPtr<");
                res.extend(return_type);
                res.push(b'(');
                for (i, ptype) in params_types.into_iter().enumerate() {
                    if let Some(ptype) = ptype {
                        if i != 0 {
                            res.extend(b", ");
                        }
                        res.extend(ptype);
                    }
                }
                res.extend(b")>");
                Some(res)
            }
            // ELEMENT_TYPE_OBJECT
            0x1c => Some(b"object".to_vec()),
            // ELEMENT_TYPE_SZARRAY
            0x1d => {
                let inner_type =
                    self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level)?;
                let mut res = Vec::new();
                res.extend(inner_type);
                res.extend(b"[]");
                Some(res)
            }
            // ELEMENT_TYPE_MVAR
            0x1e => {
                let index = read_encoded_uint(sig)? as usize;
                method_gen_params
                    .get(index)
                    .and_then(|v| v.as_ref())
                    .cloned()
            }
            // ELEMENT_TYPE_CMOD_REDQ and ELEMENT_TYPE_CMOD_OPT
            0x1f | 0x20 => {
                // Ignore the type def or ref index, and return the following type
                let _index = read_encoded_uint(sig)?;
                self.parse_sig_type(sig, class_gen_params, method_gen_params, rec_level)
            }
            _ => None,
        }
    }

    fn type_ref_table_size(&self) -> u8 {
        self.resolution_scope_index_size + 2 * self.string_index_size
    }

    fn type_spec_table_size(&self) -> u8 {
        self.blob_index_size
    }

    fn member_ref_table_size(&self) -> u8 {
        self.member_ref_parent_index_size + self.string_index_size + self.blob_index_size
    }

    fn read_string(&mut self) -> Result<Option<&'data [u8]>, ()> {
        let index = read_index(&mut self.data, self.string_index_size)? as usize;

        Ok(self.get_string(index))
    }

    fn get_string(&self, index: usize) -> Option<&'data [u8]> {
        if index == 0 {
            return None;
        }
        let slice = self.strings_stream?.get(index..)?;
        let pos = slice.iter().position(|c| *c == b'\0')?;

        Some(&slice[..pos])
    }

    fn read_blob(&mut self) -> Result<Option<&'data [u8]>, ()> {
        let index = read_index(&mut self.data, self.blob_index_size)? as usize;

        Ok(self.get_blob(index))
    }

    fn get_blob(&self, index: usize) -> Option<&'data [u8]> {
        let slice = self.blobs_stream?.get(index..)?;
        read_blob(&mut Bytes(slice))
    }
}

fn get_record_in_table(mut table: Bytes, record_size: u8, index: u32) -> Option<Bytes> {
    if index == 0 {
        // 0 means null reference
        return None;
    }

    let record_size = usize::from(record_size);
    let offset = record_size.checked_mul((index - 1) as usize)?;
    table.skip(offset).ok()?;

    table.read_bytes(record_size).ok()
}

#[derive(Debug)]
struct Signature {
    return_type: Vec<u8>,
    params_types: Vec<Option<Vec<u8>>>,
}

#[derive(Debug)]
struct Class {
    flags: u32,
    name: Option<Vec<u8>>,
    namespace: Option<Vec<u8>>,
    methods: Vec<Value>,
    method_def_first_index: Option<u32>,
    generic_params: Vec<Option<Vec<u8>>>,
    base_types: Vec<Value>,
    extends_index: u32,
}

impl Class {
    fn get_fullname(&self) -> Option<Vec<u8>> {
        self.name
            .as_ref()
            .map(|name| build_fullname(self.namespace.as_deref(), name))
    }

    fn into_value(self) -> Value {
        // Values for flags can be found in II.23.1.15
        let typ = if self.flags & 0x20 != 0 {
            b"interface".as_slice()
        } else {
            b"class"
        };

        let fullname = self.get_fullname();
        let visibility = match self.flags & 0x07 {
            // NotPublic or NestedAssembly
            0x00 | 0x05 => "internal",
            // Public or NestedPublic
            0x01 | 0x02 => "public",
            // NestedPrivate
            0x03 => "private",
            // NestedFamily
            0x04 => "protected",
            // NestedFamANDAssem
            0x06 => "private protected",
            // NestedFamORAssem
            0x07 => "protected internal",
            _ => "private",
        };
        let abstrac = i64::from((self.flags & 0x80) != 0);
        let sealed = i64::from((self.flags & 0x100) != 0);

        Value::object([
            ("fullname", fullname.into()),
            ("name", self.name.into()),
            ("namespace", self.namespace.unwrap_or_default().into()),
            ("visibility", Value::bytes(visibility)),
            ("type", Value::bytes(typ)),
            ("abstract", abstrac.into()),
            ("sealed", sealed.into()),
            ("number_of_methods", self.methods.len().into()),
            ("methods", Value::Array(self.methods)),
            (
                "number_of_generic_parameters",
                self.generic_params.len().into(),
            ),
            (
                "generic_parameters",
                Value::Array(self.generic_params.into_iter().map(Into::into).collect()),
            ),
            ("number_of_base_types", self.base_types.len().into()),
            ("base_types", Value::Array(self.base_types)),
        ])
    }
}

#[derive(Debug)]
struct Method {
    flags: u16,
    name: Option<Vec<u8>>,
    generic_params: Vec<Option<Vec<u8>>>,
    return_type: Option<Vec<u8>>,
    params: Vec<Param>,
    param_name_first_index: Option<u32>,
    signature: Option<Vec<u8>>,
}

#[derive(Debug)]
struct Param {
    name: Value,
    typ: Value,
}

impl Method {
    fn set_signature(&mut self, signature: Signature) {
        let Signature {
            return_type,
            params_types,
        } = signature;
        self.return_type = Some(return_type);
        self.params = params_types
            .into_iter()
            .map(|param_type| Param {
                name: Value::Undefined,
                typ: param_type.map(Value::Bytes).into(),
            })
            .collect();
    }

    fn into_value(self) -> Value {
        let Self {
            flags,
            name,
            generic_params,
            mut return_type,
            params,
            param_name_first_index: _param_name_first_index,
            signature: _sig,
        } = self;

        // Values for flags can be found in II.23.1.10
        let flag_static = i64::from((flags & 0x10) != 0);
        let flag_final = i64::from((flags & 0x20) != 0);
        let flag_virtual = i64::from((flags & 0x40) != 0);
        let flag_abstract = i64::from((flags & 0x400) != 0);

        let visibility = match flags & 0x07 {
            // Private
            0x01 => "private",
            // FamANDAssem
            0x02 => "private protected",
            // Assem
            0x03 => "internal",
            // Family
            0x04 => "protected",
            // FamORAssem
            0x05 => "protected internal",
            // Public
            0x06 => "public",
            _ => "private",
        };

        let parameters: Vec<_> = params
            .into_iter()
            .map(|Param { name, typ }| Value::object([("name", name), ("type", typ)]))
            .collect();

        // For some reason, in yara, the return_type is forced to undefined for constructors.
        if let Some(name) = name.as_ref() {
            if name == b".ctor" || name == b".cctor" {
                return_type = None;
            }
        }

        Value::object([
            ("abstract", flag_abstract.into()),
            ("final", flag_final.into()),
            ("virtual", flag_virtual.into()),
            ("static", flag_static.into()),
            ("visibility", Value::bytes(visibility)),
            ("name", name.into()),
            ("number_of_generic_parameters", generic_params.len().into()),
            (
                "generic_parameters",
                Value::Array(generic_params.into_iter().map(Into::into).collect()),
            ),
            ("return_type", return_type.map(Value::Bytes).into()),
            ("number_of_parameters", parameters.len().into()),
            ("parameters", Value::Array(parameters)),
        ])
    }
}

fn read_index(data: &mut Bytes, index_size: u8) -> Result<u32, ()> {
    if index_size == 4 {
        read_u32(data)
    } else {
        read_u16(data).map(u32::from)
    }
}

fn read_u16(data: &mut Bytes) -> Result<u16, ()> {
    data.read::<U16<LE>>().map(|v| v.get(LE))
}

fn read_u32(data: &mut Bytes) -> Result<u32, ()> {
    data.read::<U32<LE>>().map(|v| v.get(LE))
}

fn read_blob<'data>(bytes: &mut Bytes<'data>) -> Option<&'data [u8]> {
    // See II.24.2.4 in ECMA 335 for details on the encoding.
    let length = read_encoded_uint(bytes)? as usize;
    bytes.read_slice(length).ok()
}

fn get_byte(bytes: &mut Bytes) -> Option<u8> {
    let b = bytes.0.first()?;
    let _ = bytes.skip(1);
    Some(*b)
}

fn read_encoded_uint(bytes: &mut Bytes) -> Option<u32> {
    // See II.24.2.4 and II.23.2
    // Both use the same encoding for unsigned int, so we use the same helper.
    let a = get_byte(bytes)?;
    if a & 0x80 == 0 {
        Some(u32::from(a))
    } else if a & 0xC0 == 0x80 {
        let a = a & 0x3F;
        let b = get_byte(bytes)?;

        Some(u32::from_le_bytes([b, a, 0, 0]))
    } else if a & 0xE0 == 0xC0 {
        let a = a & 0x1F;
        let b = get_byte(bytes)?;
        let c = get_byte(bytes)?;
        let d = get_byte(bytes)?;

        Some(u32::from_le_bytes([d, c, b, a]))
    } else {
        None
    }
}

#[allow(clippy::cast_possible_wrap)]
fn read_encoded_sint(bytes: &mut Bytes) -> Option<i32> {
    // See II.23.2
    let a = get_byte(bytes)?;
    if a & 0x80 == 0 {
        // Value was rotated left 1 bit on 7 bits.
        // Rotate it back right to retrieve right value.
        let mut res = i32::from(a) >> 1;
        if (a & 0x01) != 0 {
            res |= 0xFF_FF_FF_C0u32 as i32;
        }
        Some(res)
    } else if a & 0xC0 == 0x80 {
        let a = a & 0x3F;
        let b = get_byte(bytes)?;

        let mut res = i32::from_le_bytes([b, a, 0, 0]) >> 1;
        if (b & 0x01) != 0 {
            res |= 0xFF_FF_E0_00u32 as i32;
        }
        Some(res)
    } else if a & 0xE0 == 0xC0 {
        let a = a & 0x1F;
        let b = get_byte(bytes)?;
        let c = get_byte(bytes)?;
        let d = get_byte(bytes)?;

        let mut res = i32::from_le_bytes([d, c, b, a]) >> 1;
        if (d & 0x01) != 0 {
            res |= 0xF0_00_00_00u32 as i32;
        }
        Some(res)
    } else {
        None
    }
}

fn build_fullname(ns: Option<&[u8]>, name: &[u8]) -> Vec<u8> {
    match ns {
        Some(ns) => {
            let mut full = Vec::with_capacity(ns.len() + name.len() + 1);
            full.extend(ns);
            full.push(b'.');
            full.extend(name);
            full
        }
        None => name.to_vec(),
    }
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
        sections: &pe_utils::SectionTable<'data>,
    ) -> Result<MetadataRoot<'data>, &'static str> {
        let (offset, size) = sections
            .get_file_range_at(self.metadata_rva.get(LE))
            .ok_or("Invalid CLI metadata virtual address")?;

        let data = data
            .read_bytes_at(offset.into(), size.into())
            .map_err(|()| "Invalid section file range")?
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
