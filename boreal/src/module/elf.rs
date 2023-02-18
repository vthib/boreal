use std::collections::HashMap;

use object::elf::{self, FileHeader32, FileHeader64};
use object::read::elf::{Dyn, FileHeader, ProgramHeader, SectionHeader, Sym};
use object::{Endianness, FileKind};

use super::{Module, ScanContext, StaticValue, Type, Value};

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

    fn get_dynamic_values(&self, ctx: &mut ScanContext) -> HashMap<&'static str, Value> {
        parse_file(ctx.mem).unwrap_or_default()
    }
}

fn parse_file(mem: &[u8]) -> Option<HashMap<&'static str, Value>> {
    match FileKind::parse(mem).ok()? {
        FileKind::Elf32 => Some(parse_file_inner(FileHeader32::parse(mem).ok()?, mem)),
        FileKind::Elf64 => Some(parse_file_inner(FileHeader64::parse(mem).ok()?, mem)),
        _ => None,
    }
}

fn parse_file_inner<Elf: FileHeader<Endian = Endianness>>(
    header: &Elf,
    mem: &[u8],
) -> HashMap<&'static str, Value> {
    // Safety: cannot fail, as we use `Endian = Endianness`, so we do not force endianness.
    let e = header.endian().unwrap();

    let symtab = get_symbols(header, e, mem, elf::SHT_SYMTAB);
    let symtab_len = symtab
        .as_ref()
        .and_then(|v| if v.is_empty() { None } else { Some(v.len()) });

    let dynsym = get_symbols(header, e, mem, elf::SHT_DYNSYM);
    let dynsym_len = dynsym
        .as_ref()
        .and_then(|v| if v.is_empty() { None } else { Some(v.len()) });

    let dynamic = dynamic(header, e, mem);
    let dynamic_len = dynamic.as_ref().map(Vec::len);

    [
        ("type", Value::from(header.e_type(e))),
        ("machine", header.e_machine(e).into()),
        ("entry_point", entry_point(header, e, mem).into()),
        ("number_of_sections", header.e_shnum(e).into()),
        ("sh_offset", header.e_shoff(e).into().into()),
        ("sh_entry_size", u64::from(header.e_shentsize(e)).into()),
        ("number_of_segments", header.phnum(e, mem).ok().into()),
        ("ph_offset", header.e_phoff(e).into().into()),
        ("ph_entry_size", u64::from(header.e_phentsize(e)).into()),
        (
            "sections",
            sections(header, e, mem).unwrap_or(Value::Undefined),
        ),
        (
            "segments",
            segments(header, e, mem).map_or(Value::Undefined, Value::Array),
        ),
        ("symtab", symtab.map_or(Value::Undefined, Value::Array)),
        ("symtab_entries", symtab_len.into()),
        ("dynsym", dynsym.map_or(Value::Undefined, Value::Array)),
        ("dynsym_entries", dynsym_len.into()),
        ("dynamic", dynamic.map_or(Value::Undefined, Value::Array)),
        ("dynamic_section_entries", dynamic_len.into()),
    ]
    .into()
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
) -> Option<Vec<Value>> {
    let section_table = header.sections(e, mem).ok()?;
    let symbol_table = section_table.symbols(e, mem, symbol_type).ok()?;
    let strings_table = symbol_table.strings();

    Some(
        symbol_table
            .iter()
            .take(MAX_NB_SYMBOLS)
            .map(|symbol| {
                Value::object([
                    (
                        "name",
                        symbol
                            .name(e, strings_table)
                            .ok()
                            .map(<[u8]>::to_vec)
                            .into(),
                    ),
                    ("bind", symbol.st_bind().into()),
                    ("type", symbol.st_type().into()),
                    ("shndx", symbol.st_shndx(e).into()),
                    ("value", symbol.st_value(e).into().into()),
                    ("size", symbol.st_size(e).into().into()),
                ])
            })
            .collect(),
    )
}
