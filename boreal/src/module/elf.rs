use std::collections::HashMap;

use object::elf::{self, FileHeader32, FileHeader64};
use object::read::elf::{Dyn, FileHeader, ProgramHeader, SectionHeader, Sym};
use object::{Endianness, FileKind};

use crate::memory::Region;

#[cfg(feature = "hash")]
use super::EvalContext;
use super::{Module, ModuleData, ModuleDataMap, ScanContext, StaticValue, Type, Value};

const MAX_NB_SEGMENTS: usize = 32_768;
const MAX_NB_SECTIONS: usize = 32_768;
const MAX_NB_DYNAMIC: usize = 32_768;
const MAX_NB_SYMBOLS: usize = 32_768;

/// `elf` module. Allows inspecting ELF inputs
#[derive(Debug)]
pub struct Elf;

impl Module for Elf {
    fn get_name(&self) -> &'static str {
        "elf"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            // ET contants
            ("ET_NONE", StaticValue::Integer(elf::ET_NONE.into())),
            ("ET_REL", StaticValue::Integer(elf::ET_REL.into())),
            ("ET_EXEC", StaticValue::Integer(elf::ET_EXEC.into())),
            ("ET_DYN", StaticValue::Integer(elf::ET_DYN.into())),
            ("ET_CORE", StaticValue::Integer(elf::ET_CORE.into())),
            // EM constants
            ("EM_NONE", StaticValue::Integer(elf::EM_NONE.into())),
            ("EM_M32", StaticValue::Integer(elf::EM_M32.into())),
            ("EM_SPARC", StaticValue::Integer(elf::EM_SPARC.into())),
            ("EM_386", StaticValue::Integer(elf::EM_386.into())),
            ("EM_68K", StaticValue::Integer(elf::EM_68K.into())),
            ("EM_88K", StaticValue::Integer(elf::EM_88K.into())),
            ("EM_860", StaticValue::Integer(elf::EM_860.into())),
            ("EM_MIPS", StaticValue::Integer(elf::EM_MIPS.into())),
            (
                "EM_MIPS_RS3_LE",
                StaticValue::Integer(elf::EM_MIPS_RS3_LE.into()),
            ),
            ("EM_PPC", StaticValue::Integer(elf::EM_PPC.into())),
            ("EM_PPC64", StaticValue::Integer(elf::EM_PPC64.into())),
            ("EM_ARM", StaticValue::Integer(elf::EM_ARM.into())),
            ("EM_X86_64", StaticValue::Integer(elf::EM_X86_64.into())),
            ("EM_AARCH64", StaticValue::Integer(elf::EM_AARCH64.into())),
            // SHT constants
            ("SHT_NULL", StaticValue::Integer(elf::SHT_NULL.into())),
            (
                "SHT_PROGBITS",
                StaticValue::Integer(elf::SHT_PROGBITS.into()),
            ),
            ("SHT_SYMTAB", StaticValue::Integer(elf::SHT_SYMTAB.into())),
            ("SHT_STRTAB", StaticValue::Integer(elf::SHT_STRTAB.into())),
            ("SHT_RELA", StaticValue::Integer(elf::SHT_RELA.into())),
            ("SHT_HASH", StaticValue::Integer(elf::SHT_HASH.into())),
            ("SHT_DYNAMIC", StaticValue::Integer(elf::SHT_DYNAMIC.into())),
            ("SHT_NOTE", StaticValue::Integer(elf::SHT_NOTE.into())),
            ("SHT_NOBITS", StaticValue::Integer(elf::SHT_NOBITS.into())),
            ("SHT_REL", StaticValue::Integer(elf::SHT_REL.into())),
            ("SHT_SHLIB", StaticValue::Integer(elf::SHT_SHLIB.into())),
            ("SHT_DYNSYM", StaticValue::Integer(elf::SHT_DYNSYM.into())),
            // SHF constants
            ("SHF_WRITE", StaticValue::Integer(elf::SHF_WRITE.into())),
            ("SHF_ALLOC", StaticValue::Integer(elf::SHF_ALLOC.into())),
            (
                "SHF_EXECINSTR",
                StaticValue::Integer(elf::SHF_EXECINSTR.into()),
            ),
            // PT constants
            ("PT_NULL", StaticValue::Integer(elf::PT_NULL.into())),
            ("PT_LOAD", StaticValue::Integer(elf::PT_LOAD.into())),
            ("PT_DYNAMIC", StaticValue::Integer(elf::PT_DYNAMIC.into())),
            ("PT_INTERP", StaticValue::Integer(elf::PT_INTERP.into())),
            ("PT_NOTE", StaticValue::Integer(elf::PT_NOTE.into())),
            ("PT_SHLIB", StaticValue::Integer(elf::PT_SHLIB.into())),
            ("PT_PHDR", StaticValue::Integer(elf::PT_PHDR.into())),
            ("PT_TLS", StaticValue::Integer(elf::PT_TLS.into())),
            (
                "PT_GNU_EH_FRAME",
                StaticValue::Integer(elf::PT_GNU_EH_FRAME.into()),
            ),
            (
                "PT_GNU_STACK",
                StaticValue::Integer(elf::PT_GNU_STACK.into()),
            ),
            // DT constants
            ("DT_NULL", StaticValue::Integer(elf::DT_NULL.into())),
            ("DT_NEEDED", StaticValue::Integer(elf::DT_NEEDED.into())),
            ("DT_PLTRELSZ", StaticValue::Integer(elf::DT_PLTRELSZ.into())),
            ("DT_PLTGOT", StaticValue::Integer(elf::DT_PLTGOT.into())),
            ("DT_HASH", StaticValue::Integer(elf::DT_HASH.into())),
            ("DT_STRTAB", StaticValue::Integer(elf::DT_STRTAB.into())),
            ("DT_SYMTAB", StaticValue::Integer(elf::DT_SYMTAB.into())),
            ("DT_RELA", StaticValue::Integer(elf::DT_RELA.into())),
            ("DT_RELASZ", StaticValue::Integer(elf::DT_RELASZ.into())),
            ("DT_RELAENT", StaticValue::Integer(elf::DT_RELAENT.into())),
            ("DT_STRSZ", StaticValue::Integer(elf::DT_STRSZ.into())),
            ("DT_SYMENT", StaticValue::Integer(elf::DT_SYMENT.into())),
            ("DT_INIT", StaticValue::Integer(elf::DT_INIT.into())),
            ("DT_FINI", StaticValue::Integer(elf::DT_FINI.into())),
            ("DT_SONAME", StaticValue::Integer(elf::DT_SONAME.into())),
            ("DT_RPATH", StaticValue::Integer(elf::DT_RPATH.into())),
            ("DT_SYMBOLIC", StaticValue::Integer(elf::DT_SYMBOLIC.into())),
            ("DT_REL", StaticValue::Integer(elf::DT_REL.into())),
            ("DT_RELSZ", StaticValue::Integer(elf::DT_RELSZ.into())),
            ("DT_RELENT", StaticValue::Integer(elf::DT_RELENT.into())),
            ("DT_PLTREL", StaticValue::Integer(elf::DT_PLTREL.into())),
            ("DT_DEBUG", StaticValue::Integer(elf::DT_DEBUG.into())),
            ("DT_TEXTREL", StaticValue::Integer(elf::DT_TEXTREL.into())),
            ("DT_JMPREL", StaticValue::Integer(elf::DT_JMPREL.into())),
            ("DT_BIND_NOW", StaticValue::Integer(elf::DT_BIND_NOW.into())),
            (
                "DT_INIT_ARRAY",
                StaticValue::Integer(elf::DT_INIT_ARRAY.into()),
            ),
            (
                "DT_FINI_ARRAY",
                StaticValue::Integer(elf::DT_FINI_ARRAY.into()),
            ),
            (
                "DT_INIT_ARRAYSZ",
                StaticValue::Integer(elf::DT_INIT_ARRAYSZ.into()),
            ),
            (
                "DT_FINI_ARRAYSZ",
                StaticValue::Integer(elf::DT_FINI_ARRAYSZ.into()),
            ),
            ("DT_RUNPATH", StaticValue::Integer(elf::DT_RUNPATH.into())),
            ("DT_FLAGS", StaticValue::Integer(elf::DT_FLAGS.into())),
            ("DT_ENCODING", StaticValue::Integer(elf::DT_ENCODING.into())),
            // STT constants
            ("STT_NOTYPE", StaticValue::Integer(elf::STT_NOTYPE.into())),
            ("STT_OBJECT", StaticValue::Integer(elf::STT_OBJECT.into())),
            ("STT_FUNC", StaticValue::Integer(elf::STT_FUNC.into())),
            ("STT_SECTION", StaticValue::Integer(elf::STT_SECTION.into())),
            ("STT_FILE", StaticValue::Integer(elf::STT_FILE.into())),
            ("STT_COMMON", StaticValue::Integer(elf::STT_COMMON.into())),
            ("STT_TLS", StaticValue::Integer(elf::STT_TLS.into())),
            // STB constants
            ("STB_LOCAL", StaticValue::Integer(elf::STB_LOCAL.into())),
            ("STB_GLOBAL", StaticValue::Integer(elf::STB_GLOBAL.into())),
            ("STB_WEAK", StaticValue::Integer(elf::STB_WEAK.into())),
            // PF constants
            ("PF_X", StaticValue::Integer(elf::PF_X.into())),
            ("PF_W", StaticValue::Integer(elf::PF_W.into())),
            ("PF_R", StaticValue::Integer(elf::PF_R.into())),
            // Hashes of import details
            #[cfg(feature = "hash")]
            (
                "import_md5",
                StaticValue::function(Self::import_md5, vec![], Type::Bytes),
            ),
            #[cfg(feature = "hash")]
            (
                "telfhash",
                StaticValue::function(Self::telfhash, vec![], Type::Bytes),
            ),
        ]
        .into()
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        [
            // Integers depending on scan
            ("type", Type::Integer),
            ("machine", Type::Integer),
            ("entry_point", Type::Integer),
            ("number_of_sections", Type::Integer),
            ("sh_offset", Type::Integer),
            ("sh_entry_size", Type::Integer),
            ("number_of_segments", Type::Integer),
            ("ph_offset", Type::Integer),
            ("ph_entry_size", Type::Integer),
            ("dynamic_section_entries", Type::Integer),
            ("symtab_entries", Type::Integer),
            ("dynsym_entries", Type::Integer),
            // Sections array
            (
                "sections",
                Type::array(Type::object([
                    ("type", Type::Integer),
                    ("flags", Type::Integer),
                    ("address", Type::Integer),
                    ("name", Type::Bytes),
                    ("size", Type::Integer),
                    ("offset", Type::Integer),
                ])),
            ),
            // Segments array
            (
                "segments",
                Type::array(Type::object([
                    ("type", Type::Integer),
                    ("flags", Type::Integer),
                    ("offset", Type::Integer),
                    ("virtual_address", Type::Integer),
                    ("physical_address", Type::Integer),
                    ("file_size", Type::Integer),
                    ("memory_size", Type::Integer),
                    ("alignment", Type::Integer),
                ])),
            ),
            // Dynamic array
            (
                "dynamic",
                Type::array(Type::object([
                    ("type", Type::Integer),
                    ("val", Type::Integer),
                ])),
            ),
            // Symtab array
            (
                "symtab",
                Type::array(Type::object([
                    ("name", Type::Bytes),
                    ("value", Type::Integer),
                    ("size", Type::Integer),
                    ("type", Type::Integer),
                    ("bind", Type::Integer),
                    ("shndx", Type::Integer),
                ])),
            ),
            // Dynsym array
            (
                "dynsym",
                Type::array(Type::object([
                    ("name", Type::Bytes),
                    ("value", Type::Integer),
                    ("size", Type::Integer),
                    ("type", Type::Integer),
                    ("bind", Type::Integer),
                    ("shndx", Type::Integer),
                ])),
            ),
        ]
        .into()
    }

    fn setup_new_scan(&self, data_map: &mut ModuleDataMap) {
        data_map.insert::<Self>(Data::default());
    }

    fn get_dynamic_values(&self, ctx: &mut ScanContext, out: &mut HashMap<&'static str, Value>) {
        if !out.is_empty() {
            // We already found an elf in a scanned region, so ignore the others.
            return;
        }

        if let Some(values) = ctx
            .module_data
            .get_mut::<Self>()
            .and_then(|data| parse_file(ctx.region, ctx.process_memory, data))
        {
            *out = values;
        }
    }
}

impl ModuleData for Elf {
    type PrivateData = Data;
    type UserData = ();
}

#[derive(Default)]
pub struct Data {
    symbols: Vec<DataSymbol>,
}

#[allow(dead_code)]
pub struct DataSymbol {
    name: Vec<u8>,
    shndx: u16,
    bind: u8,
    type_: u8,
    visibility: u8,
}

impl Data {
    #[cfg(feature = "hash")]
    fn get_import_string<F>(&self, f: F) -> Option<Vec<u8>>
    where
        F: Fn(&DataSymbol) -> bool,
    {
        let mut symbols: Vec<_> = self
            .symbols
            .iter()
            .filter(|v| f(v))
            .map(|s| s.name.clone())
            .collect();

        if symbols.is_empty() {
            return None;
        }

        // Lowercase the symbols, then sort them
        for symbol in &mut symbols {
            symbol.make_ascii_lowercase();
        }
        symbols.sort_unstable();

        Some(
            symbols
                .into_iter()
                .fold((Vec::new(), 0), |(mut acc, i), e| {
                    if i != 0 {
                        acc.push(b',');
                    }
                    acc.extend(e);
                    (acc, i + 1)
                })
                .0,
        )
    }
}

fn parse_file(
    region: &Region,
    process_memory: bool,
    data: &mut Data,
) -> Option<HashMap<&'static str, Value>> {
    match FileKind::parse(region.mem).ok()? {
        FileKind::Elf32 => parse_file_inner(
            FileHeader32::parse(region.mem).ok()?,
            region,
            process_memory,
            data,
        ),
        FileKind::Elf64 => parse_file_inner(
            FileHeader64::parse(region.mem).ok()?,
            region,
            process_memory,
            data,
        ),
        _ => None,
    }
}

fn parse_file_inner<Elf: FileHeader<Endian = Endianness>>(
    header: &Elf,
    region: &Region,
    process_memory: bool,
    data: &mut Data,
) -> Option<HashMap<&'static str, Value>> {
    // Safety: cannot fail, as we use `Endian = Endianness`, so we do not force endianness.
    let e = header.endian().unwrap();

    if process_memory && header.e_type(e) != elf::ET_EXEC {
        return None;
    }

    let symtab = get_symbols(header, e, region.mem, elf::SHT_SYMTAB, data);
    let symtab_len = symtab
        .as_ref()
        .and_then(|v| if v.is_empty() { None } else { Some(v.len()) });

    // Get dynsym *after* symtab. This ensures that data.symbols uses
    // the dynsym in priority, if both exists.
    let dynsym = get_symbols(header, e, region.mem, elf::SHT_DYNSYM, data);
    let dynsym_len = dynsym
        .as_ref()
        .and_then(|v| if v.is_empty() { None } else { Some(v.len()) });

    let dynamic = dynamic(header, e, region.mem);
    let dynamic_len = dynamic.as_ref().map(Vec::len);

    let entrypoint = if process_memory {
        let entry: u64 = header.e_entry(e).into();
        let start: Option<u64> = region.start.try_into().ok();
        start.and_then(|v| v.checked_add(entry))
    } else {
        entry_point(header, e, region.mem)
    };

    let res = [
        ("type", Value::from(header.e_type(e))),
        ("machine", header.e_machine(e).into()),
        ("entry_point", entrypoint.into()),
        ("number_of_sections", header.e_shnum(e).into()),
        ("sh_offset", header.e_shoff(e).into().into()),
        ("sh_entry_size", u64::from(header.e_shentsize(e)).into()),
        (
            "number_of_segments",
            header.phnum(e, region.mem).ok().into(),
        ),
        ("ph_offset", header.e_phoff(e).into().into()),
        ("ph_entry_size", u64::from(header.e_phentsize(e)).into()),
        (
            "sections",
            sections(header, e, region.mem).unwrap_or(Value::Undefined),
        ),
        (
            "segments",
            segments(header, e, region.mem).map_or(Value::Undefined, Value::Array),
        ),
        ("symtab", symtab.map_or(Value::Undefined, Value::Array)),
        ("symtab_entries", symtab_len.into()),
        ("dynsym", dynsym.map_or(Value::Undefined, Value::Array)),
        ("dynsym_entries", dynsym_len.into()),
        ("dynamic", dynamic.map_or(Value::Undefined, Value::Array)),
        ("dynamic_section_entries", dynamic_len.into()),
    ]
    .into();
    Some(res)
}

pub(crate) fn entry_point<Elf: FileHeader>(
    header: &Elf,
    e: Elf::Endian,
    mem: &[u8],
) -> Option<u64> {
    let entrypoint: u64 = header.e_entry(e).into();

    // The entrypoint is a VA, find the right segment/section containing it, and
    // adapt the adress to point to the right offset into the ELF file.
    if header.e_type(e) == elf::ET_EXEC {
        header
            .program_headers(e, mem)
            .ok()?
            .iter()
            .find_map(|segment| {
                let addr = segment.p_vaddr(e).into();
                let size = segment.p_memsz(e).into();
                if (addr..addr.saturating_add(size)).contains(&entrypoint) {
                    Some((entrypoint - addr).saturating_add(segment.p_offset(e).into()))
                } else {
                    None
                }
            })
    } else {
        header.sections(e, mem).ok()?.iter().find_map(|section| {
            if matches!(section.sh_type(e), elf::SHT_NULL | elf::SHT_NOBITS) {
                return None;
            }

            let addr = section.sh_addr(e).into();
            let size = section.sh_size(e).into();
            if (addr..addr.saturating_add(size)).contains(&entrypoint) {
                Some((entrypoint - addr).saturating_add(section.sh_offset(e).into()))
            } else {
                None
            }
        })
    }
}

fn sections<Elf: FileHeader>(header: &Elf, e: Elf::Endian, mem: &[u8]) -> Option<Value> {
    let section_table = header.sections(e, mem).ok()?;
    Some(Value::Array(
        section_table
            .iter()
            .take(MAX_NB_SECTIONS)
            .map(|section| {
                Value::object([
                    ("type", section.sh_type(e).into()),
                    ("flags", section.sh_flags(e).into().into()),
                    ("address", section.sh_addr(e).into().into()),
                    ("size", section.sh_size(e).into().into()),
                    ("offset", section.sh_offset(e).into().into()),
                    (
                        "name",
                        section_table
                            .section_name(e, section)
                            .ok()
                            .map(<[u8]>::to_vec)
                            .into(),
                    ),
                ])
            })
            .collect(),
    ))
}

fn segments<Elf: FileHeader>(header: &Elf, e: Elf::Endian, mem: &[u8]) -> Option<Vec<Value>> {
    Some(
        header
            .program_headers(e, mem)
            .ok()?
            .iter()
            .take(MAX_NB_SEGMENTS)
            .map(|segment| {
                Value::object([
                    ("type", segment.p_type(e).into()),
                    ("flags", segment.p_flags(e).into()),
                    ("offset", segment.p_offset(e).into().into()),
                    ("virtual_address", segment.p_vaddr(e).into().into()),
                    ("physical_address", segment.p_paddr(e).into().into()),
                    ("file_size", segment.p_filesz(e).into().into()),
                    ("memory_size", segment.p_memsz(e).into().into()),
                    ("alignment", segment.p_align(e).into().into()),
                ])
            })
            .collect(),
    )
}

fn dynamic<Elf: FileHeader>(header: &Elf, e: Elf::Endian, mem: &[u8]) -> Option<Vec<Value>> {
    let dyn_table = header
        .program_headers(e, mem)
        .ok()?
        .iter()
        .find_map(|segment| segment.dynamic(e, mem).ok().flatten())?;

    let mut res = Vec::new();

    for sym in dyn_table {
        let ty = sym.d_tag(e).into();

        res.push(Value::object([
            ("type", ty.into()),
            ("val", sym.d_val(e).into().into()),
        ]));

        if ty == u64::from(elf::DT_NULL) || res.len() >= MAX_NB_DYNAMIC {
            break;
        }
    }
    Some(res)
}

fn get_symbols<Elf: FileHeader>(
    header: &Elf,
    e: Elf::Endian,
    mem: &[u8],
    symbol_type: u32,
    data: &mut Data,
) -> Option<Vec<Value>> {
    let section_table = header.sections(e, mem).ok()?;
    let symbol_table = section_table.symbols(e, mem, symbol_type).ok()?;
    let strings_table = symbol_table.strings();

    let mut data_symbols = Vec::with_capacity(symbol_table.len());
    let mut symbols = Vec::with_capacity(symbol_table.len());

    for symbol in symbol_table.iter().take(MAX_NB_SYMBOLS) {
        let name = symbol.name(e, strings_table).ok();
        let bind = symbol.st_bind();
        let type_ = symbol.st_type();
        let shndx = symbol.st_shndx(e);
        let obj = Value::object([
            ("name", name.map(<[u8]>::to_vec).into()),
            ("bind", bind.into()),
            ("type", type_.into()),
            ("shndx", shndx.into()),
            ("value", symbol.st_value(e).into().into()),
            ("size", symbol.st_size(e).into().into()),
        ]);

        symbols.push(obj);
        if let Some(name) = name {
            data_symbols.push(DataSymbol {
                name: name.to_vec(),
                shndx,
                bind,
                type_,
                visibility: symbol.st_other() & 0x3,
            });
        }
    }

    data.symbols = data_symbols;

    Some(symbols)
}

impl Elf {
    #[cfg(feature = "hash")]
    fn import_md5(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        use md5::{Digest, Md5};

        let data = ctx.module_data.get::<Self>()?;
        let import_string =
            data.get_import_string(|sym| sym.shndx == elf::SHN_UNDEF && !sym.name.is_empty())?;

        let hash = Md5::digest(import_string);

        Some(Value::Bytes(super::hex_encode(hash)))
    }

    #[cfg(feature = "hash")]
    fn telfhash(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        const EXCLUDED_STRINGS: &[&[u8]; 8] = &[
            b"__libc_start_main",
            b"main",
            b"abort",
            b"cachectl",
            b"cacheflush",
            b"puts",
            b"atol",
            b"malloc_trim",
        ];

        let data = ctx.module_data.get::<Self>()?;
        let import_string = data.get_import_string(|sym| {
            if sym.bind != elf::STB_GLOBAL
                || sym.type_ != elf::STT_FUNC
                || sym.visibility != elf::STV_DEFAULT
            {
                return false;
            }

            if sym.name.starts_with(b".") || sym.name.starts_with(b"_") {
                return false;
            }
            if sym.name.ends_with(b"64") {
                return false;
            }
            if sym.name.starts_with(b"str") || sym.name.starts_with(b"mem") {
                return false;
            }

            if EXCLUDED_STRINGS
                .iter()
                .any(|excluded| *excluded == sym.name)
            {
                return false;
            }

            true
        })?;

        tlsh2::TlshBuilder128_1::build_from(&import_string)
            .map(|v| v.hash())
            .map(Value::bytes)
    }
}
