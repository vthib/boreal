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

    Some(
        [
            ("is_dotnet", Value::Integer(1)),
            ("version", Value::bytes(metadata.version)),
            ("module_name", Value::Undefined),
            (
                "streams",
                Value::Array(get_streams(&metadata, metadata_root_offset)),
            ),
            (
                "number_of_streams",
                Value::Integer(metadata.number_of_streams.into()),
            ),
            // TODO
            ("guids", Value::Undefined),
            ("number_of_guids", Value::Undefined),
            ("resources", Value::Undefined),
            ("number_of_resources", Value::Undefined),
            ("classes", Value::Undefined),
            ("number_of_classes", Value::Undefined),
            ("assembly_refs", Value::Undefined),
            ("number_of_assembly_refs", Value::Undefined),
            ("assembly", Value::Undefined),
            ("modulerefs", Value::Undefined),
            ("number_of_modulerefs", Value::Undefined),
            ("user_strings", Value::Undefined),
            ("number_of_user_strings", Value::Undefined),
            ("typelib", Value::Undefined),
            ("constants", Value::Undefined),
            ("number_of_constants", Value::Undefined),
            ("field_offsets", Value::Undefined),
            ("number_of_field_offsets", Value::Undefined),
        ]
        .into(),
    )
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
    streams_data: &'data [u8],
}

impl<'data> MetadataRoot<'data> {
    fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let mut data = Bytes(data);

        let header = *data
            .read::<MetadataRootHeader>()
            .map_err(|()| "Cannot read metadata root header")?;
        let version = data
            .read_slice(header.length.get(LE) as usize)
            .map_err(|()| "Cannot read metadata root version")?;
        let flags = data
            .read::<U16<LE>>()
            .map_err(|()| "Cannot read metadata root flags")?
            .get(LE);
        let number_of_streams = data
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
            streams_data: data.0,
        })
    }

    fn streams(&self) -> StreamIterator {
        StreamIterator {
            nb_streams_left: self.number_of_streams,
            data: Bytes(self.streams_data),
        }
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
