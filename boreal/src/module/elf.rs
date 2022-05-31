use std::collections::HashMap;

// TODO: add tests on all methods, not relying on libyara compat tests

use object::{
    elf,
    read::elf::{
        Dyn, ElfFile, ElfFile32, ElfFile64, FileHeader, ProgramHeader, SectionHeader, Sym,
    },
    FileKind, Object,
};

use super::{Module, ScanContext, Type, Value};

/// `elf` module. Allows inspecting ELF inputs
#[derive(Debug)]
pub struct Elf;

impl Module for Elf {
    fn get_name(&self) -> String {
        "elf".to_owned()
    }

    fn get_static_values(&self) -> HashMap<&'static str, Value> {
        [
            // ET contants
            ("ET_NONE", Value::Integer(elf::ET_NONE.into())),
            ("ET_REL", Value::Integer(elf::ET_REL.into())),
            ("ET_EXEC", Value::Integer(elf::ET_EXEC.into())),
            ("ET_DYN", Value::Integer(elf::ET_DYN.into())),
            ("ET_CORE", Value::Integer(elf::ET_CORE.into())),
            // EM constants
            ("EM_NONE", Value::Integer(elf::EM_NONE.into())),
            ("EM_M32", Value::Integer(elf::EM_M32.into())),
            ("EM_SPARC", Value::Integer(elf::EM_SPARC.into())),
            ("EM_386", Value::Integer(elf::EM_386.into())),
            ("EM_68K", Value::Integer(elf::EM_68K.into())),
            ("EM_88K", Value::Integer(elf::EM_88K.into())),
            ("EM_860", Value::Integer(elf::EM_860.into())),
            ("EM_MIPS", Value::Integer(elf::EM_MIPS.into())),
            ("EM_MIPS_RS3_LE", Value::Integer(elf::EM_MIPS_RS3_LE.into())),
            ("EM_PPC", Value::Integer(elf::EM_PPC.into())),
            ("EM_PPC64", Value::Integer(elf::EM_PPC64.into())),
            ("EM_ARM", Value::Integer(elf::EM_ARM.into())),
            ("EM_X86_64", Value::Integer(elf::EM_X86_64.into())),
            ("EM_AARCH64", Value::Integer(elf::EM_AARCH64.into())),
            // SHT constants
            ("SHT_NULL", Value::Integer(elf::SHT_NULL.into())),
            ("SHT_PROGBITS", Value::Integer(elf::SHT_PROGBITS.into())),
            ("SHT_SYMTAB", Value::Integer(elf::SHT_SYMTAB.into())),
            ("SHT_STRTAB", Value::Integer(elf::SHT_STRTAB.into())),
            ("SHT_RELA", Value::Integer(elf::SHT_RELA.into())),
            ("SHT_HASH", Value::Integer(elf::SHT_HASH.into())),
            ("SHT_DYNAMIC", Value::Integer(elf::SHT_DYNAMIC.into())),
            ("SHT_NOTE", Value::Integer(elf::SHT_NOTE.into())),
            ("SHT_NOBITS", Value::Integer(elf::SHT_NOBITS.into())),
            ("SHT_REL", Value::Integer(elf::SHT_REL.into())),
            ("SHT_SHLIB", Value::Integer(elf::SHT_SHLIB.into())),
            ("SHT_DYNSYM", Value::Integer(elf::SHT_DYNSYM.into())),
            // SHF constants
            ("SHF_WRITE", Value::Integer(elf::SHF_WRITE.into())),
            ("SHF_ALLOC", Value::Integer(elf::SHF_ALLOC.into())),
            ("SHF_EXECINSTR", Value::Integer(elf::SHF_EXECINSTR.into())),
            // PT constants
            ("PT_NULL", Value::Integer(elf::PT_NULL.into())),
            ("PT_LOAD", Value::Integer(elf::PT_LOAD.into())),
            ("PT_DYNAMIC", Value::Integer(elf::PT_DYNAMIC.into())),
            ("PT_INTERP", Value::Integer(elf::PT_INTERP.into())),
            ("PT_NOTE", Value::Integer(elf::PT_NOTE.into())),
            ("PT_SHLIB", Value::Integer(elf::PT_SHLIB.into())),
            ("PT_PHDR", Value::Integer(elf::PT_PHDR.into())),
            ("PT_TLS", Value::Integer(elf::PT_TLS.into())),
            (
                "PT_GNU_EH_FRAME",
                Value::Integer(elf::PT_GNU_EH_FRAME.into()),
            ),
            ("PT_GNU_STACK", Value::Integer(elf::PT_GNU_STACK.into())),
            // DT constants
            ("DT_NULL", Value::Integer(elf::DT_NULL.into())),
            ("DT_NEEDED", Value::Integer(elf::DT_NEEDED.into())),
            ("DT_PLTRELSZ", Value::Integer(elf::DT_PLTRELSZ.into())),
            ("DT_PLTGOT", Value::Integer(elf::DT_PLTGOT.into())),
            ("DT_HASH", Value::Integer(elf::DT_HASH.into())),
            ("DT_STRTAB", Value::Integer(elf::DT_STRTAB.into())),
            ("DT_SYMTAB", Value::Integer(elf::DT_SYMTAB.into())),
            ("DT_RELA", Value::Integer(elf::DT_RELA.into())),
            ("DT_RELASZ", Value::Integer(elf::DT_RELASZ.into())),
            ("DT_RELAENT", Value::Integer(elf::DT_RELAENT.into())),
            ("DT_STRSZ", Value::Integer(elf::DT_STRSZ.into())),
            ("DT_SYMENT", Value::Integer(elf::DT_SYMENT.into())),
            ("DT_INIT", Value::Integer(elf::DT_INIT.into())),
            ("DT_FINI", Value::Integer(elf::DT_FINI.into())),
            ("DT_SONAME", Value::Integer(elf::DT_SONAME.into())),
            ("DT_RPATH", Value::Integer(elf::DT_RPATH.into())),
            ("DT_SYMBOLIC", Value::Integer(elf::DT_SYMBOLIC.into())),
            ("DT_REL", Value::Integer(elf::DT_REL.into())),
            ("DT_RELSZ", Value::Integer(elf::DT_RELSZ.into())),
            ("DT_RELENT", Value::Integer(elf::DT_RELENT.into())),
            ("DT_PLTREL", Value::Integer(elf::DT_PLTREL.into())),
            ("DT_DEBUG", Value::Integer(elf::DT_DEBUG.into())),
            ("DT_TEXTREL", Value::Integer(elf::DT_TEXTREL.into())),
            ("DT_JMPREL", Value::Integer(elf::DT_JMPREL.into())),
            ("DT_BIND_NOW", Value::Integer(elf::DT_BIND_NOW.into())),
            ("DT_INIT_ARRAY", Value::Integer(elf::DT_INIT_ARRAY.into())),
            ("DT_FINI_ARRAY", Value::Integer(elf::DT_FINI_ARRAY.into())),
            (
                "DT_INIT_ARRAYSZ",
                Value::Integer(elf::DT_INIT_ARRAYSZ.into()),
            ),
            (
                "DT_FINI_ARRAYSZ",
                Value::Integer(elf::DT_FINI_ARRAYSZ.into()),
            ),
            ("DT_RUNPATH", Value::Integer(elf::DT_RUNPATH.into())),
            ("DT_FLAGS", Value::Integer(elf::DT_FLAGS.into())),
            ("DT_ENCODING", Value::Integer(elf::DT_ENCODING.into())),
            // STT constants
            ("STT_NOTYPE", Value::Integer(elf::STT_NOTYPE.into())),
            ("STT_OBJECT", Value::Integer(elf::STT_OBJECT.into())),
            ("STT_FUNC", Value::Integer(elf::STT_FUNC.into())),
            ("STT_SECTION", Value::Integer(elf::STT_SECTION.into())),
            ("STT_FILE", Value::Integer(elf::STT_FILE.into())),
            ("STT_COMMON", Value::Integer(elf::STT_COMMON.into())),
            ("STT_TLS", Value::Integer(elf::STT_TLS.into())),
            // STB constants
            ("STB_LOCAL", Value::Integer(elf::STB_LOCAL.into())),
            ("STB_GLOBAL", Value::Integer(elf::STB_GLOBAL.into())),
            ("STB_WEAK", Value::Integer(elf::STB_WEAK.into())),
            // PF constants
            ("PF_X", Value::Integer(elf::PF_X.into())),
            ("PF_W", Value::Integer(elf::PF_W.into())),
            ("PF_R", Value::Integer(elf::PF_R.into())),
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
                    ("name", Type::String),
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
                    ("name", Type::String),
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
                    ("name", Type::String),
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

    fn get_dynamic_values(&self, ctx: &ScanContext) -> HashMap<&'static str, Value> {
        // TODO: fix this
        [
            ("type", Self::r#type(ctx)),
            ("machine", Self::machine(ctx)),
            ("entry_point", Self::entry_point(ctx)),
            ("number_of_sections", Self::number_of_sections(ctx)),
            ("sh_offset", Self::sh_offset(ctx)),
            ("sh_entry_size", Self::sh_entry_size(ctx)),
            ("number_of_segments", Self::number_of_segments(ctx)),
            ("ph_offset", Self::ph_offset(ctx)),
            ("ph_entry_size", Self::ph_entry_size(ctx)),
            (
                "dynamic_section_entries",
                Self::dynamic_section_entries(ctx),
            ),
            ("symtab_entries", Self::symtab_entries(ctx)),
            ("dynsym_entries", Self::dynsym_entries(ctx)),
            ("sections", Self::sections(ctx).map(Value::Array)),
            ("segments", Self::segments(ctx).map(Value::Array)),
            ("dynamic", Self::dynamic(ctx).map(Value::Array)),
            ("symtab", Self::symtab(ctx).map(Value::Array)),
            ("dynsym", Self::dynsym(ctx).map(Value::Array)),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect()
    }
}

enum Data<'a> {
    File32(ElfFile32<'a>),
    File64(ElfFile64<'a>),
}

impl<'a> Data<'a> {
    fn new(mem: &'a [u8]) -> Option<Self> {
        match FileKind::parse(mem).ok()? {
            FileKind::Elf32 => Some(Self::File32(ElfFile32::parse(mem).ok()?)),
            FileKind::Elf64 => Some(Self::File64(ElfFile64::parse(mem).ok()?)),
            _ => None,
        }
    }
}

macro_rules! apply {
    ($self:ident, $file:ident => $code:expr) => {
        match $self {
            Data::File32($file) => $code,
            #[allow(clippy::useless_conversion)]
            Data::File64($file) => $code,
        }
    };
}

impl Elf {
    fn r#type(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(file: &ElfFile<Elf>) -> Value {
            file.raw_header().e_type(file.endian()).into()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => Some(fun(&f)))
    }

    fn machine(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(file: &ElfFile<Elf>) -> Value {
            file.raw_header().e_machine(file.endian()).into()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => Some(fun(&f)))
    }

    fn entry_point(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(file: &ElfFile<Elf>, mem: &[u8]) -> Option<Value> {
            let e = file.endian();
            let entrypoint = file.entry();

            // The entrypoint is a VA, find the right segment/section containing it, and
            // adapt the adress to point to the right offset into the ELF file.
            if file.raw_header().e_type(e) == elf::ET_EXEC {
                file.raw_segments().iter().find_map(|segment| {
                    let addr = segment.p_vaddr(e).into();
                    let size = segment.p_memsz(e).into();
                    if (addr..addr.saturating_add(size)).contains(&entrypoint) {
                        let entrypoint =
                            (entrypoint - addr).saturating_add(segment.p_offset(e).into());
                        entrypoint.try_into().ok()
                    } else {
                        None
                    }
                })
            } else {
                file.raw_header()
                    .sections(e, mem)
                    .ok()?
                    .iter()
                    .find_map(|section| {
                        if matches!(section.sh_type(e), elf::SHT_NULL | elf::SHT_NOBITS) {
                            return None;
                        }

                        let addr = section.sh_addr(e).into();
                        let size = section.sh_size(e).into();
                        if (addr..addr.saturating_add(size)).contains(&entrypoint) {
                            let entrypoint =
                                (entrypoint - addr).saturating_add(section.sh_offset(e).into());
                            entrypoint.try_into().ok()
                        } else {
                            None
                        }
                    })
            }
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f, ctx.mem))
    }

    fn number_of_sections(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>, mem: &[u8]) -> Option<Value> {
            f.raw_header().shnum(f.endian(), mem).ok()?.try_into().ok()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f, ctx.mem))
    }

    fn sh_offset(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>) -> Option<Value> {
            f.raw_header().e_shoff(f.endian()).into().try_into().ok()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f))
    }

    fn sh_entry_size(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>) -> Option<Value> {
            u64::from(f.raw_header().e_shentsize(f.endian()))
                .try_into()
                .ok()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f))
    }

    fn number_of_segments(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>, mem: &[u8]) -> Option<Value> {
            f.raw_header().phnum(f.endian(), mem).ok()?.try_into().ok()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f, ctx.mem))
    }

    fn ph_offset(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>) -> Option<Value> {
            f.raw_header().e_phoff(f.endian()).into().try_into().ok()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f))
    }

    fn ph_entry_size(ctx: &ScanContext) -> Option<Value> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>) -> Option<Value> {
            u64::from(f.raw_header().e_phentsize(f.endian()))
                .try_into()
                .ok()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f))
    }

    fn sections(ctx: &ScanContext) -> Option<Vec<Value>> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>, mem: &[u8]) -> Option<Vec<Value>> {
            let e = f.endian();

            let section_table = f.raw_header().sections(e, mem).ok()?;
            Some(
                section_table
                    .iter()
                    .map(|section| {
                        let mut obj: HashMap<&'static str, Value> = HashMap::with_capacity(6);

                        let _r = obj.insert("type", section.sh_type(e).into());
                        if let Ok(v) = section.sh_flags(e).into().try_into() {
                            let _r = obj.insert("flags", v);
                        }
                        if let Ok(v) = section.sh_addr(e).into().try_into() {
                            let _r = obj.insert("address", v);
                        }
                        if let Ok(v) = section.sh_size(e).into().try_into() {
                            let _r = obj.insert("size", v);
                        }
                        if let Ok(v) = section.sh_offset(e).into().try_into() {
                            let _r = obj.insert("offset", v);
                        }
                        if let Some(v) = section_table
                            .section_name(e, section)
                            .ok()
                            .and_then(|v| std::str::from_utf8(v).ok())
                        {
                            let _r = obj.insert("name", v.to_string().into());
                        }

                        Value::Object(obj)
                    })
                    .collect(),
            )
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f, ctx.mem))
    }

    fn segments(ctx: &ScanContext) -> Option<Vec<Value>> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>) -> Vec<Value> {
            let e = f.endian();

            f.raw_segments()
                .iter()
                .map(|segment| {
                    let mut obj: HashMap<&'static str, Value> = HashMap::with_capacity(6);

                    let _r = obj.insert("type", segment.p_type(e).into());
                    let _r = obj.insert("flags", segment.p_flags(e).into());
                    if let Ok(v) = segment.p_offset(e).into().try_into() {
                        let _r = obj.insert("offset", v);
                    }
                    if let Ok(v) = segment.p_vaddr(e).into().try_into() {
                        let _r = obj.insert("virtual_address", v);
                    }
                    if let Ok(v) = segment.p_paddr(e).into().try_into() {
                        let _r = obj.insert("physical_address", v);
                    }
                    if let Ok(v) = segment.p_filesz(e).into().try_into() {
                        let _r = obj.insert("file_size", v);
                    }
                    if let Ok(v) = segment.p_memsz(e).into().try_into() {
                        let _r = obj.insert("memory_size", v);
                    }
                    if let Ok(v) = segment.p_align(e).into().try_into() {
                        let _r = obj.insert("alignment", v);
                    }

                    Value::Object(obj)
                })
                .collect()
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => Some(fun(&f)))
    }

    fn dynamic_section_entries(ctx: &ScanContext) -> Option<Value> {
        // TODO: compute both dynamic and this len at the same time
        dbg!(Self::dynamic(ctx).and_then(|v| v.len().try_into().ok()))
    }

    fn dynamic(ctx: &ScanContext) -> Option<Vec<Value>> {
        fn fun<Elf: FileHeader>(f: &ElfFile<Elf>, mem: &[u8]) -> Option<Vec<Value>> {
            let e = f.endian();

            let dyn_table = f
                .raw_segments()
                .iter()
                .find_map(|segment| segment.dynamic(e, mem).ok().flatten())?;

            let mut res = Vec::new();

            for sym in dyn_table {
                let ty = sym.d_tag(e).into();

                let mut obj: HashMap<&'static str, Value> = HashMap::with_capacity(3);
                if let Ok(ty) = ty.try_into() {
                    let _r = obj.insert("type", ty);
                }
                if let Ok(val) = sym.d_val(e).into().try_into() {
                    let _r = obj.insert("val", val);
                }
                res.push(Value::Object(obj));

                if ty == u64::from(elf::DT_NULL) {
                    break;
                }
            }
            Some(res)
        }

        let data = Data::new(ctx.mem)?;
        apply!(data, f => fun(&f, ctx.mem))
    }

    fn symtab_entries(ctx: &ScanContext) -> Option<Value> {
        let data = Data::new(ctx.mem)?;
        apply!(data, f => get_symbols_len(&f, ctx.mem, elf::SHT_SYMTAB))
    }

    fn symtab(ctx: &ScanContext) -> Option<Vec<Value>> {
        let data = Data::new(ctx.mem)?;
        apply!(data, f => get_symbols(&f, ctx.mem, elf::SHT_SYMTAB))
    }

    fn dynsym_entries(ctx: &ScanContext) -> Option<Value> {
        let data = Data::new(ctx.mem)?;
        apply!(data, f => get_symbols_len(&f, ctx.mem, elf::SHT_DYNSYM))
    }

    fn dynsym(ctx: &ScanContext) -> Option<Vec<Value>> {
        let data = Data::new(ctx.mem)?;
        apply!(data, f => get_symbols(&f, ctx.mem, elf::SHT_DYNSYM))
    }
}

fn get_symbols_len<Elf: FileHeader>(
    f: &ElfFile<Elf>,
    mem: &[u8],
    symbol_type: u32,
) -> Option<Value> {
    let e = f.endian();
    let section_table = f.raw_header().sections(e, mem).ok()?;
    let symbol_table = section_table.symbols(e, mem, symbol_type).ok()?;

    symbol_table.len().try_into().ok()
}

fn get_symbols<Elf: FileHeader>(
    f: &ElfFile<Elf>,
    mem: &[u8],
    symbol_type: u32,
) -> Option<Vec<Value>> {
    let e = f.endian();
    let section_table = f.raw_header().sections(e, mem).ok()?;
    let symbol_table = section_table.symbols(e, mem, symbol_type).ok()?;
    let strings_table = symbol_table.strings();

    Some(
        symbol_table
            .iter()
            .map(|symbol| {
                let mut obj: HashMap<&'static str, Value> = HashMap::with_capacity(6);

                if let Some(v) = symbol
                    .name(e, strings_table)
                    .ok()
                    .and_then(|v| std::str::from_utf8(v).ok())
                {
                    let _r = obj.insert("name", v.to_string().into());
                }
                let _r = obj.insert("bind", symbol.st_bind().into());
                let _r = obj.insert("type", symbol.st_type().into());
                let _r = obj.insert("shndx", symbol.st_shndx(e).into());
                if let Ok(v) = symbol.st_value(e).into().try_into() {
                    let _r = obj.insert("value", v);
                }
                if let Ok(v) = symbol.st_size(e).into().try_into() {
                    let _r = obj.insert("size", v);
                }

                Value::Object(obj)
            })
            .collect(),
    )
}
