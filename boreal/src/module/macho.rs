use std::collections::HashMap;

// TODO: add tests on all methods, not relying on libyara compat tests

use object::{
    macho::{
        self, FatHeader, MachHeader32, MachHeader64, SegmentCommand32, SegmentCommand64,
        ThreadCommand,
    },
    read::macho::{FatArch, LoadCommandData, MachHeader, Section, Segment},
    BigEndian, Endian, Endianness, FileKind, U32, U64,
};

use super::{Module, ScanContext, StaticValue, Type, Value};

/// `macho` module. Allows inspecting Mach-O inputs
#[derive(Debug)]
pub struct MachO;

impl Module for MachO {
    fn get_name(&self) -> String {
        "macho".to_owned()
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
            // Magic constants
            ("MH_MAGIC", StaticValue::Integer(macho::MH_MAGIC.into())),
            ("MH_CIGAM", StaticValue::Integer(macho::MH_CIGAM.into())),
            (
                "MH_MAGIC_64",
                StaticValue::Integer(macho::MH_MAGIC_64.into()),
            ),
            (
                "MH_CIGAM_64",
                StaticValue::Integer(macho::MH_CIGAM_64.into()),
            ),
            // Fat magic constants
            ("FAT_MAGIC", StaticValue::Integer(macho::FAT_MAGIC.into())),
            ("FAT_CIGAM", StaticValue::Integer(macho::FAT_CIGAM.into())),
            (
                "FAT_MAGIC_64",
                StaticValue::Integer(macho::FAT_MAGIC_64.into()),
            ),
            (
                "FAT_CIGAM_64",
                StaticValue::Integer(macho::FAT_CIGAM_64.into()),
            ),
            // 64-bit masks
            (
                "CPU_ARCH_ABI64",
                StaticValue::Integer(macho::CPU_ARCH_ABI64.into()),
            ),
            (
                "CPU_SUBTYPE_LIB64",
                StaticValue::Integer(macho::CPU_SUBTYPE_LIB64.into()),
            ),
            // CPU types
            (
                "CPU_TYPE_MC680X0",
                StaticValue::Integer(macho::CPU_TYPE_MC680X0.into()),
            ),
            (
                "CPU_TYPE_X86",
                StaticValue::Integer(macho::CPU_TYPE_X86.into()),
            ),
            (
                "CPU_TYPE_I386",
                StaticValue::Integer(macho::CPU_TYPE_X86.into()),
            ),
            (
                "CPU_TYPE_X86_64",
                StaticValue::Integer(macho::CPU_TYPE_X86_64.into()),
            ),
            (
                "CPU_TYPE_MIPS",
                StaticValue::Integer(macho::CPU_TYPE_MIPS.into()),
            ),
            (
                "CPU_TYPE_MC98000",
                StaticValue::Integer(macho::CPU_TYPE_MC98000.into()),
            ),
            (
                "CPU_TYPE_ARM",
                StaticValue::Integer(macho::CPU_TYPE_ARM.into()),
            ),
            (
                "CPU_TYPE_ARM64",
                StaticValue::Integer(macho::CPU_TYPE_ARM64.into()),
            ),
            (
                "CPU_TYPE_MC88000",
                StaticValue::Integer(macho::CPU_TYPE_MC88000.into()),
            ),
            (
                "CPU_TYPE_SPARC",
                StaticValue::Integer(macho::CPU_TYPE_SPARC.into()),
            ),
            (
                "CPU_TYPE_POWERPC",
                StaticValue::Integer(macho::CPU_TYPE_POWERPC.into()),
            ),
            (
                "CPU_TYPE_POWERPC64",
                StaticValue::Integer(macho::CPU_TYPE_POWERPC64.into()),
            ),
            // CPU sub-types
            (
                "CPU_SUBTYPE_INTEL_MODEL_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_INTEL_MODEL_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_386",
                StaticValue::Integer(macho::CPU_SUBTYPE_386.into()),
            ),
            (
                "CPU_SUBTYPE_I386_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_I386_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_X86_64_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_X86_64_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_486",
                StaticValue::Integer(macho::CPU_SUBTYPE_486.into()),
            ),
            (
                "CPU_SUBTYPE_486SX",
                StaticValue::Integer(macho::CPU_SUBTYPE_486SX.into()),
            ),
            (
                "CPU_SUBTYPE_586",
                StaticValue::Integer(macho::CPU_SUBTYPE_586.into()),
            ),
            (
                "CPU_SUBTYPE_PENT",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENT.into()),
            ),
            (
                "CPU_SUBTYPE_PENTPRO",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTPRO.into()),
            ),
            (
                "CPU_SUBTYPE_PENTII_M3",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTII_M3.into()),
            ),
            (
                "CPU_SUBTYPE_PENTII_M5",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTII_M5.into()),
            ),
            (
                "CPU_SUBTYPE_CELERON",
                StaticValue::Integer(macho::CPU_SUBTYPE_CELERON.into()),
            ),
            (
                "CPU_SUBTYPE_CELERON_MOBILE",
                StaticValue::Integer(macho::CPU_SUBTYPE_CELERON_MOBILE.into()),
            ),
            (
                "CPU_SUBTYPE_PENTIUM_3",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTIUM_3.into()),
            ),
            (
                "CPU_SUBTYPE_PENTIUM_3_M",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTIUM_3_M.into()),
            ),
            (
                "CPU_SUBTYPE_PENTIUM_3_XEON",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTIUM_3_XEON.into()),
            ),
            (
                "CPU_SUBTYPE_PENTIUM_M",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTIUM_M.into()),
            ),
            (
                "CPU_SUBTYPE_PENTIUM_4",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTIUM_4.into()),
            ),
            (
                "CPU_SUBTYPE_PENTIUM_4_M",
                StaticValue::Integer(macho::CPU_SUBTYPE_PENTIUM_4_M.into()),
            ),
            (
                "CPU_SUBTYPE_ITANIUM",
                StaticValue::Integer(macho::CPU_SUBTYPE_ITANIUM.into()),
            ),
            (
                "CPU_SUBTYPE_ITANIUM_2",
                StaticValue::Integer(macho::CPU_SUBTYPE_ITANIUM_2.into()),
            ),
            (
                "CPU_SUBTYPE_XEON",
                StaticValue::Integer(macho::CPU_SUBTYPE_XEON.into()),
            ),
            (
                "CPU_SUBTYPE_XEON_MP",
                StaticValue::Integer(macho::CPU_SUBTYPE_XEON_MP.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V4T",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V4T.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V6",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V6.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V5",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V5TEJ.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V5TEJ",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V5TEJ.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_XSCALE",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_XSCALE.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V7",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V7.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V7F",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V7F.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V7S",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V7S.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V7K",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V7K.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V6M",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V6M.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V7M",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V7M.into()),
            ),
            (
                "CPU_SUBTYPE_ARM_V7EM",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM_V7EM.into()),
            ),
            (
                "CPU_SUBTYPE_ARM64_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_ARM64_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_SPARC_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_SPARC_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_MC980000_ALL",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_ALL.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_601",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_601.into()),
            ),
            (
                "CPU_SUBTYPE_MC98601",
                StaticValue::Integer(macho::CPU_SUBTYPE_MC98601.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_602",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_602.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_603",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_603.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_603e",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_603E.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_603ev",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_603EV.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_604",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_604.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_604e",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_604E.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_620",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_620.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_750",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_750.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_7400",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_7400.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_7450",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_7450.into()),
            ),
            (
                "CPU_SUBTYPE_POWERPC_970",
                StaticValue::Integer(macho::CPU_SUBTYPE_POWERPC_970.into()),
            ),
            // File types
            ("MH_OBJECT", StaticValue::Integer(macho::MH_OBJECT.into())),
            ("MH_EXECUTE", StaticValue::Integer(macho::MH_EXECUTE.into())),
            ("MH_FVMLIB", StaticValue::Integer(macho::MH_FVMLIB.into())),
            ("MH_CORE", StaticValue::Integer(macho::MH_CORE.into())),
            ("MH_PRELOAD", StaticValue::Integer(macho::MH_PRELOAD.into())),
            ("MH_DYLIB", StaticValue::Integer(macho::MH_DYLIB.into())),
            (
                "MH_DYLINKER",
                StaticValue::Integer(macho::MH_DYLINKER.into()),
            ),
            ("MH_BUNDLE", StaticValue::Integer(macho::MH_BUNDLE.into())),
            (
                "MH_DYLIB_STUB",
                StaticValue::Integer(macho::MH_DYLIB_STUB.into()),
            ),
            ("MH_DSYM", StaticValue::Integer(macho::MH_DSYM.into())),
            (
                "MH_KEXT_BUNDLE",
                StaticValue::Integer(macho::MH_KEXT_BUNDLE.into()),
            ),
            // Header flags
            (
                "MH_NOUNDEFS",
                StaticValue::Integer(macho::MH_NOUNDEFS.into()),
            ),
            (
                "MH_INCRLINK",
                StaticValue::Integer(macho::MH_INCRLINK.into()),
            ),
            (
                "MH_DYLDLINK",
                StaticValue::Integer(macho::MH_DYLDLINK.into()),
            ),
            (
                "MH_BINDATLOAD",
                StaticValue::Integer(macho::MH_BINDATLOAD.into()),
            ),
            (
                "MH_PREBOUND",
                StaticValue::Integer(macho::MH_PREBOUND.into()),
            ),
            (
                "MH_SPLIT_SEGS",
                StaticValue::Integer(macho::MH_SPLIT_SEGS.into()),
            ),
            (
                "MH_LAZY_INIT",
                StaticValue::Integer(macho::MH_LAZY_INIT.into()),
            ),
            (
                "MH_TWOLEVEL",
                StaticValue::Integer(macho::MH_TWOLEVEL.into()),
            ),
            (
                "MH_FORCE_FLAT",
                StaticValue::Integer(macho::MH_FORCE_FLAT.into()),
            ),
            (
                "MH_NOMULTIDEFS",
                StaticValue::Integer(macho::MH_NOMULTIDEFS.into()),
            ),
            (
                "MH_NOFIXPREBINDING",
                StaticValue::Integer(macho::MH_NOFIXPREBINDING.into()),
            ),
            (
                "MH_PREBINDABLE",
                StaticValue::Integer(macho::MH_PREBINDABLE.into()),
            ),
            (
                "MH_ALLMODSBOUND",
                StaticValue::Integer(macho::MH_ALLMODSBOUND.into()),
            ),
            (
                "MH_SUBSECTIONS_VIA_SYMBOLS",
                StaticValue::Integer(macho::MH_SUBSECTIONS_VIA_SYMBOLS.into()),
            ),
            (
                "MH_CANONICAL",
                StaticValue::Integer(macho::MH_CANONICAL.into()),
            ),
            (
                "MH_WEAK_DEFINES",
                StaticValue::Integer(macho::MH_WEAK_DEFINES.into()),
            ),
            (
                "MH_BINDS_TO_WEAK",
                StaticValue::Integer(macho::MH_BINDS_TO_WEAK.into()),
            ),
            (
                "MH_ALLOW_STACK_EXECUTION",
                StaticValue::Integer(macho::MH_ALLOW_STACK_EXECUTION.into()),
            ),
            (
                "MH_ROOT_SAFE",
                StaticValue::Integer(macho::MH_ROOT_SAFE.into()),
            ),
            (
                "MH_SETUID_SAFE",
                StaticValue::Integer(macho::MH_SETUID_SAFE.into()),
            ),
            (
                "MH_NO_REEXPORTED_DYLIBS",
                StaticValue::Integer(macho::MH_NO_REEXPORTED_DYLIBS.into()),
            ),
            ("MH_PIE", StaticValue::Integer(macho::MH_PIE.into())),
            (
                "MH_DEAD_STRIPPABLE_DYLIB",
                StaticValue::Integer(macho::MH_DEAD_STRIPPABLE_DYLIB.into()),
            ),
            (
                "MH_HAS_TLV_DESCRIPTORS",
                StaticValue::Integer(macho::MH_HAS_TLV_DESCRIPTORS.into()),
            ),
            (
                "MH_NO_HEAP_EXECUTION",
                StaticValue::Integer(macho::MH_NO_HEAP_EXECUTION.into()),
            ),
            (
                "MH_APP_EXTENSION_SAFE",
                StaticValue::Integer(macho::MH_APP_EXTENSION_SAFE.into()),
            ),
            // Segment flags
            ("SG_HIGHVM", StaticValue::Integer(macho::SG_HIGHVM.into())),
            ("SG_FVMLIB", StaticValue::Integer(macho::SG_FVMLIB.into())),
            ("SG_NORELOC", StaticValue::Integer(macho::SG_NORELOC.into())),
            (
                "SG_PROTECTED_VERSION_1",
                StaticValue::Integer(macho::SG_PROTECTED_VERSION_1.into()),
            ),
            // Section masks
            (
                "SECTION_TYPE",
                StaticValue::Integer(macho::SECTION_TYPE.into()),
            ),
            (
                "SECTION_ATTRIBUTES",
                StaticValue::Integer(macho::SECTION_ATTRIBUTES.into()),
            ),
            // Section types
            ("S_REGULAR", StaticValue::Integer(macho::S_REGULAR.into())),
            ("S_ZEROFILL", StaticValue::Integer(macho::S_ZEROFILL.into())),
            (
                "S_CSTRING_LITERALS",
                StaticValue::Integer(macho::S_CSTRING_LITERALS.into()),
            ),
            (
                "S_4BYTE_LITERALS",
                StaticValue::Integer(macho::S_4BYTE_LITERALS.into()),
            ),
            (
                "S_8BYTE_LITERALS",
                StaticValue::Integer(macho::S_8BYTE_LITERALS.into()),
            ),
            (
                "S_LITERAL_POINTERS",
                StaticValue::Integer(macho::S_LITERAL_POINTERS.into()),
            ),
            (
                "S_NON_LAZY_SYMBOL_POINTERS",
                StaticValue::Integer(macho::S_NON_LAZY_SYMBOL_POINTERS.into()),
            ),
            (
                "S_LAZY_SYMBOL_POINTERS",
                StaticValue::Integer(macho::S_LAZY_SYMBOL_POINTERS.into()),
            ),
            (
                "S_SYMBOL_STUBS",
                StaticValue::Integer(macho::S_SYMBOL_STUBS.into()),
            ),
            (
                "S_MOD_INIT_FUNC_POINTERS",
                StaticValue::Integer(macho::S_MOD_INIT_FUNC_POINTERS.into()),
            ),
            (
                "S_MOD_TERM_FUNC_POINTERS",
                StaticValue::Integer(macho::S_MOD_TERM_FUNC_POINTERS.into()),
            ),
            (
                "S_COALESCED",
                StaticValue::Integer(macho::S_COALESCED.into()),
            ),
            (
                "S_GB_ZEROFILL",
                StaticValue::Integer(macho::S_GB_ZEROFILL.into()),
            ),
            (
                "S_INTERPOSING",
                StaticValue::Integer(macho::S_INTERPOSING.into()),
            ),
            (
                "S_16BYTE_LITERALS",
                StaticValue::Integer(macho::S_16BYTE_LITERALS.into()),
            ),
            (
                "S_DTRACE_DOF",
                StaticValue::Integer(macho::S_DTRACE_DOF.into()),
            ),
            (
                "S_LAZY_DYLIB_SYMBOL_POINTERS",
                StaticValue::Integer(macho::S_LAZY_DYLIB_SYMBOL_POINTERS.into()),
            ),
            (
                "S_THREAD_LOCAL_REGULAR",
                StaticValue::Integer(macho::S_THREAD_LOCAL_REGULAR.into()),
            ),
            (
                "S_THREAD_LOCAL_ZEROFILL",
                StaticValue::Integer(macho::S_THREAD_LOCAL_ZEROFILL.into()),
            ),
            (
                "S_THREAD_LOCAL_VARIABLES",
                StaticValue::Integer(macho::S_THREAD_LOCAL_VARIABLES.into()),
            ),
            (
                "S_THREAD_LOCAL_VARIABLE_POINTERS",
                StaticValue::Integer(macho::S_THREAD_LOCAL_VARIABLE_POINTERS.into()),
            ),
            (
                "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
                StaticValue::Integer(macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS.into()),
            ),
            // Section attributes
            (
                "S_ATTR_PURE_INSTRUCTIONS",
                StaticValue::Integer(macho::S_ATTR_PURE_INSTRUCTIONS.into()),
            ),
            (
                "S_ATTR_NO_TOC",
                StaticValue::Integer(macho::S_ATTR_NO_TOC.into()),
            ),
            (
                "S_ATTR_STRIP_STATIC_SYMS",
                StaticValue::Integer(macho::S_ATTR_STRIP_STATIC_SYMS.into()),
            ),
            (
                "S_ATTR_NO_DEAD_STRIP",
                StaticValue::Integer(macho::S_ATTR_NO_DEAD_STRIP.into()),
            ),
            (
                "S_ATTR_LIVE_SUPPORT",
                StaticValue::Integer(macho::S_ATTR_LIVE_SUPPORT.into()),
            ),
            (
                "S_ATTR_SELF_MODIFYING_CODE",
                StaticValue::Integer(macho::S_ATTR_SELF_MODIFYING_CODE.into()),
            ),
            (
                "S_ATTR_DEBUG",
                StaticValue::Integer(macho::S_ATTR_DEBUG.into()),
            ),
            (
                "S_ATTR_SOME_INSTRUCTIONS",
                StaticValue::Integer(macho::S_ATTR_SOME_INSTRUCTIONS.into()),
            ),
            (
                "S_ATTR_EXT_RELOC",
                StaticValue::Integer(macho::S_ATTR_EXT_RELOC.into()),
            ),
            (
                "S_ATTR_LOC_RELOC",
                StaticValue::Integer(macho::S_ATTR_LOC_RELOC.into()),
            ),
            // Mach-O fat binary helper functions
            (
                "file_index_for_arch",
                StaticValue::function(
                    Self::file_index_for_arch,
                    vec![vec![Type::Integer], vec![Type::Integer, Type::Integer]],
                    Type::Integer,
                ),
            ),
            (
                "entry_point_for_arch",
                StaticValue::function(
                    Self::entry_point_for_arch,
                    vec![vec![Type::Integer], vec![Type::Integer, Type::Integer]],
                    Type::Integer,
                ),
            ),
        ]
        .into()
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        let file_types = [
            // Integers depending on scan
            ("magic", Type::Integer),
            ("cputype", Type::Integer),
            ("cpusubtype", Type::Integer),
            ("filetype", Type::Integer),
            ("ncmds", Type::Integer),
            ("sizeofcmds", Type::Integer),
            ("flags", Type::Integer),
            ("reserved", Type::Integer),
            // Segments
            ("number_of_segments", Type::Integer),
            (
                "segments",
                Type::array(Type::object([
                    ("segname", Type::String),
                    ("vmaddr", Type::Integer),
                    ("vmsize", Type::Integer),
                    ("fileoff", Type::Integer),
                    ("fsize", Type::Integer),
                    ("maxprot", Type::Integer),
                    ("initprot", Type::Integer),
                    ("nsects", Type::Integer),
                    ("flags", Type::Integer),
                    (
                        "sections",
                        Type::array(Type::object([
                            ("sectname", Type::String),
                            ("segname", Type::String),
                            ("addr", Type::Integer),
                            ("size", Type::Integer),
                            ("offset", Type::Integer),
                            ("align", Type::Integer),
                            ("reloff", Type::Integer),
                            ("nreloc", Type::Integer),
                            ("flags", Type::Integer),
                            ("reserved1", Type::Integer),
                            ("reserved2", Type::Integer),
                            ("reserved3", Type::Integer),
                        ])),
                    ),
                ])),
            ),
            // Entry point and stack size
            ("entry_point", Type::Integer),
            ("stack_size", Type::Integer),
        ];

        // Declare types only used for FAT files
        let mut out: HashMap<_, _> = [
            // Fat header
            ("fat_magic", Type::Integer),
            ("nfat_arch", Type::Integer),
            (
                "fat_arch",
                Type::array(Type::object([
                    ("cputype", Type::Integer),
                    ("cpusubtype", Type::Integer),
                    ("offset", Type::Integer),
                    ("size", Type::Integer),
                    ("align", Type::Integer),
                ])),
            ),
        ]
        .into();

        // for FAT files, "file" is an array for every arch.
        let _r = out.insert("file", Type::array(Type::object(file_types.clone())));

        // For non fat file, this is the only output.
        out.extend(file_types);

        out
    }

    fn get_dynamic_values(&self, ctx: &ScanContext) -> HashMap<&'static str, Value> {
        parse_file(ctx.mem).unwrap_or_default()
    }
}

impl MachO {
    fn file_index_for_arch(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v1: i64 = args.next()?.try_into().ok()?;
        let v2 = args.next().and_then(|v| i64::try_from(v).ok());

        // FIXME: get computed value for the module
        let mut value = parse_file(ctx.mem)?;
        let nfat: i64 = value.remove("nfat_arch")?.try_into().ok()?;
        let nfat: usize = nfat.try_into().ok()?;
        let files = match value.remove("file")? {
            Value::Array(files) => files,
            _ => return None,
        };

        for i in 0..nfat {
            if let Some(Value::Object(file)) = files.get(i) {
                if let Some(Value::Integer(cputype)) = file.get("cputype") {
                    if *cputype != v1 {
                        continue;
                    }
                }
                if let Some(v2) = v2 {
                    if let Some(Value::Integer(cpusubtype)) = file.get("cpusubtype") {
                        if *cpusubtype != v2 {
                            continue;
                        }
                    }
                }
                return Some(Value::Integer(i as i64));
            }
        }
        None
    }

    fn entry_point_for_arch(ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let v1: i64 = args.next()?.try_into().ok()?;
        let v2 = args.next().and_then(|v| i64::try_from(v).ok());

        // FIXME: get computed value for the module
        let mut value = parse_file(ctx.mem)?;
        let nfat: i64 = value.remove("nfat_arch")?.try_into().ok()?;
        let nfat: usize = nfat.try_into().ok()?;
        let archs = match value.remove("fat_arch")? {
            Value::Array(archs) => archs,
            _ => return None,
        };
        let files = match value.remove("file")? {
            Value::Array(files) => files,
            _ => return None,
        };

        for i in 0..nfat {
            if let Some(Value::Object(file)) = files.get(i) {
                if let Some(Value::Integer(cputype)) = file.get("cputype") {
                    if *cputype != v1 {
                        continue;
                    }
                }
                if let Some(v2) = v2 {
                    if let Some(Value::Integer(cpusubtype)) = file.get("cpusubtype") {
                        if *cpusubtype != v2 {
                            continue;
                        }
                    }
                }

                let offset = archs
                    .get(i)
                    .and_then(|v| match v {
                        Value::Object(dict) => Some(dict),
                        _ => None,
                    })
                    .and_then(|arch| match arch.get("offset") {
                        Some(Value::Integer(v)) => Some(*v),
                        _ => None,
                    })?;
                let entry_point = match file.get("entry_point") {
                    Some(Value::Integer(v)) => Some(*v),
                    _ => None,
                }?;

                return Some(Value::Integer(offset.saturating_add(entry_point)));
            }
        }
        None
    }
}

fn parse_file(mem: &[u8]) -> Option<HashMap<&'static str, Value>> {
    match FileKind::parse(mem).ok()? {
        FileKind::MachO32 => {
            let header = MachHeader32::parse(mem, 0).ok()?;
            let e = header.endian().ok()?;
            Some(parse_header(header, e, mem, None))
        }
        FileKind::MachO64 => {
            let header = MachHeader64::parse(mem, 0).ok()?;
            let e = header.endian().ok()?;
            Some(parse_header(header, e, mem, Some(header.reserved.get(e))))
        }
        FileKind::MachOFat32 => parse_fat(mem, false),
        FileKind::MachOFat64 => parse_fat(mem, true),
        _ => None,
    }
}

fn parse_header<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    e: Endianness,
    mem: &[u8],
    reserved: Option<u32>,
) -> HashMap<&'static str, Value> {
    let magic = header.magic().into();
    let cputype = header.cputype(e);
    let cpusubtype = header.cpusubtype(e).into();
    let filetype = header.filetype(e).into();
    let ncmds = header.ncmds(e).into();
    let sizeofcmds = header.sizeofcmds(e).into();
    let flags = header.flags(e).into();

    let segments = segments(header, e, mem);
    let nb_segments = segments.as_ref().and_then(|v| v.len().try_into().ok());

    // TODO: handle the UnixThread load command
    let (entry_point, stack_size) = entry_point_data(header, e, mem, cputype);

    [
        ("magic", Some(magic)),
        ("cputype", Some(cputype.into())),
        ("cpusubtype", Some(cpusubtype)),
        ("filetype", Some(filetype)),
        ("ncmds", Some(ncmds)),
        ("sizeofcmds", Some(sizeofcmds)),
        ("flags", Some(flags)),
        ("reserved", reserved.map(Into::into)),
        ("segments", segments.map(Value::Array)),
        ("number_of_segments", nb_segments),
        ("entry_point", entry_point),
        ("stack_size", stack_size),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.map(|v| (k, v)))
    .collect()
}

fn segments<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    e: Endianness,
    mem: &[u8],
) -> Option<Vec<Value>> {
    let mut segments = Vec::new();
    let mut cmds = header.load_commands(e, mem, 0).ok()?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((segment32, section_data))) = cmd.segment_32() {
            let mut map = segment_to_map(segment32, e);
            if let Some(sections) = sections32(segment32, e, section_data) {
                let _r = map.insert("sections", Value::Array(sections));
            }
            segments.push(Value::Object(map));
        } else if let Ok(Some((segment64, section_data))) = cmd.segment_64() {
            let mut map = segment_to_map(segment64, e);
            if let Some(sections) = sections64(segment64, e, section_data) {
                let _r = map.insert("sections", Value::Array(sections));
            }
            segments.push(Value::Object(map));
        }
    }

    Some(segments)
}

fn entry_point_data<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    e: Endianness,
    mem: &[u8],
    cputype: u32,
) -> (Option<Value>, Option<Value>) {
    if let Ok(mut cmds) = header.load_commands(e, mem, 0) {
        while let Ok(Some(cmd)) = cmds.next() {
            if let Ok(Some(entry)) = cmd.entry_point() {
                return (
                    entry.entryoff.get(e).try_into().ok(),
                    entry.stacksize.get(e).try_into().ok(),
                );
            } else if cmd.cmd() == macho::LC_UNIXTHREAD {
                match handle_unix_thread(cmd, e, cputype) {
                    Some(ep) => {
                        // Entry-point retrieved is a VA, it must be converted into a file offset.
                        return (va_to_file_offset(header, e, mem, ep), None);
                    }
                    None => return (None, None),
                }
            }
        }
    }
    (None, None)
}

fn va_to_file_offset<Mach: MachHeader<Endian = Endianness>>(
    header: &Mach,
    e: Endianness,
    mem: &[u8],
    ep: u64,
) -> Option<Value> {
    let mut cmds = header.load_commands(e, mem, 0).ok()?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((segment, _))) = Mach::Segment::from_command(cmd) {
            let vmaddr: u64 = segment.vmaddr(e).into();
            let vmsize: u64 = segment.vmsize(e).into();

            if ep >= vmaddr && ep < vmaddr.saturating_add(vmsize) {
                let fileoff: u64 = segment.fileoff(e).into();
                return fileoff.saturating_add(ep - vmaddr).try_into().ok();
            }
        }
    }

    None
}

fn handle_unix_thread(
    cmd: LoadCommandData<Endianness>,
    e: Endianness,
    cputype: u32,
) -> Option<u64> {
    let thread_cmd: &ThreadCommand<Endianness> = cmd.data().ok()?;
    let cmdsize = thread_cmd.cmdsize.get(e) as usize;

    // The command is:
    // - cmd: u32
    // - cmdsize: u32,
    // - flavor: u32
    // - count: u32
    // - <extra_state>
    // with:
    // - <extra_state> being additional fields depending on the cputype
    // - cmdsize being the size of the whole command (so the 4 u32 + the extra state).
    //
    // We want to retrieve the entry point from the right field in the extra state.

    // Get entry_point from an offset into the xtra state
    let get_at = |mut offset: usize, is64: bool| {
        // Add the 4 u32 at the start of the cmd.
        offset += 16;
        // 4 is the size of the entry point we are getting (u32).
        if (is64 && offset + 8 > cmdsize) || (!is64 && offset + 4 > cmdsize) {
            return None;
        }

        // TODO: ask object to expose the data buffer directly, this would avoid
        // this very scary unsafe block.
        //
        // Safety:
        //
        // - underlying data buffer (address of thread_cmd) is of size "cmdsize". This is
        //   guaranteed by object, but getting the underlying buffer would help ensure this
        //   never changes.
        // - offset is ensured to be in [0; cmdsize - N]
        // Hence the N bytes pointed to after the add is in bound of the same allocated object.
        let ptr: *const ThreadCommand<Endianness> = thread_cmd;
        unsafe {
            let ptr = ptr.cast::<u8>().add(offset);
            if is64 {
                let ptr = ptr.cast::<U64<Endianness>>();
                Some((*ptr).get(e))
            } else {
                let ptr = ptr.cast::<U32<Endianness>>();
                Some((*ptr).get(e).into())
            }
        }
    };

    // TODO: would be nice to test all this...
    match cputype {
        macho::CPU_TYPE_MC680X0 => {
            // pc is after 16 u32 and 2 u16
            get_at(16 * 4 + 2 * 2, false)
        }
        macho::CPU_TYPE_MC88000 => {
            // entry point is after 31 u32s
            get_at(31 * 4, false)
        }
        macho::CPU_TYPE_SPARC => {
            // entry point is fater a single u32
            get_at(4, false)
        }
        macho::CPU_TYPE_POWERPC => {
            // srr0 is the first u32
            get_at(0, false)
        }
        macho::CPU_TYPE_X86 => {
            // eip is after 10 u32s
            get_at(10 * 4, false)
        }
        macho::CPU_TYPE_ARM => {
            // pc is after 15 u32s
            get_at(15 * 4, false)
        }
        macho::CPU_TYPE_X86_64 => {
            // rip is after 16 u64s
            get_at(16 * 8, true)
        }
        macho::CPU_TYPE_ARM64 => {
            // pc is after 32 u64s
            get_at(32 * 8, true)
        }
        macho::CPU_TYPE_POWERPC64 => {
            // srr0 is the first u64
            get_at(0, true)
        }
        _ => None,
    }
}

fn segment_to_map<S: Segment<Endian = E>, E: Copy>(
    segment: &S,
    e: E,
) -> HashMap<&'static str, Value> {
    let vmaddr: u64 = segment.vmaddr(e).into();
    let vmsize: u64 = segment.vmsize(e).into();
    let fileoff: u64 = segment.fileoff(e).into();
    let fsize: u64 = segment.filesize(e).into();
    let segname = std::str::from_utf8(segment.name()).ok();

    [
        ("segname", segname.map(|v| v.to_string().into())),
        ("vmaddr", vmaddr.try_into().ok()),
        ("vmsize", vmsize.try_into().ok()),
        ("fileoff", fileoff.try_into().ok()),
        ("fsize", fsize.try_into().ok()),
        ("maxprot", Some(segment.maxprot(e).into())),
        ("iniprot", Some(segment.initprot(e).into())),
        ("nsects", Some(segment.nsects(e).into())),
        ("flags", Some(segment.flags(e).into())),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.map(|v| (k, v)))
    .collect()
}

// TODO: ask object to expose reserved1/2/3 through the trait?
fn sections32<E: Endian>(
    segment: &SegmentCommand32<E>,
    e: E,
    section_data: &[u8],
) -> Option<Vec<Value>> {
    Some(
        segment
            .sections(e, section_data)
            .ok()?
            .iter()
            .map(|section| {
                let addr: u64 = section.addr(e).into();
                let size: u64 = section.size(e).into();
                let segname = std::str::from_utf8(section.segment_name()).ok();
                let sectname = std::str::from_utf8(section.name()).ok();

                Value::Object(
                    [
                        ("segname", segname.map(|v| v.to_string().into())),
                        ("sectname", sectname.map(|v| v.to_string().into())),
                        ("addr", addr.try_into().ok()),
                        ("size", size.try_into().ok()),
                        ("offset", Some(section.offset(e).into())),
                        ("align", Some(section.align(e).into())),
                        ("reloff", Some(section.reloff(e).into())),
                        ("nreloc", Some(section.nreloc(e).into())),
                        ("flags", Some(section.flags(e).into())),
                        ("reserved1", Some(section.reserved1.get(e).into())),
                        ("reserved2", Some(section.reserved2.get(e).into())),
                    ]
                    .into_iter()
                    .filter_map(|(k, v)| v.map(|v| (k, v)))
                    .collect(),
                )
            })
            .collect(),
    )
}

fn sections64<E: Endian>(
    segment: &SegmentCommand64<E>,
    e: E,
    section_data: &[u8],
) -> Option<Vec<Value>> {
    Some(
        segment
            .sections(e, section_data)
            .ok()?
            .iter()
            .map(|section| {
                let addr: u64 = section.addr(e);
                let size: u64 = section.size(e);
                let segname = std::str::from_utf8(section.segment_name()).ok();
                let sectname = std::str::from_utf8(section.name()).ok();

                Value::Object(
                    [
                        ("segname", segname.map(|v| v.to_string().into())),
                        ("sectname", sectname.map(|v| v.to_string().into())),
                        ("addr", addr.try_into().ok()),
                        ("size", size.try_into().ok()),
                        ("offset", Some(section.offset(e).into())),
                        ("align", Some(section.align(e).into())),
                        ("reloff", Some(section.reloff(e).into())),
                        ("nreloc", Some(section.nreloc(e).into())),
                        ("flags", Some(section.flags(e).into())),
                        ("reserved1", Some(section.reserved1.get(e).into())),
                        ("reserved2", Some(section.reserved2.get(e).into())),
                        ("reserved3", Some(section.reserved3.get(e).into())),
                    ]
                    .into_iter()
                    .filter_map(|(k, v)| v.map(|v| (k, v)))
                    .collect(),
                )
            })
            .collect(),
    )
}

fn parse_fat(mem: &[u8], is64: bool) -> Option<HashMap<&'static str, Value>> {
    let (magic, nfat_arch) = match FatHeader::parse(mem) {
        Ok(header) => (
            Some(header.magic.get(BigEndian).into()),
            Some(header.nfat_arch.get(BigEndian).into()),
        ),
        Err(_) => (None, None),
    };

    let mut archs = Vec::new();
    let mut files = Vec::new();

    if is64 {
        for arch in FatHeader::parse_arch64(mem).ok()? {
            archs.push(fat_arch_to_value(arch, Some(arch.reserved.get(BigEndian))));
            files.push(fat_arch_to_file_value(arch, mem));
        }
    } else {
        for arch in FatHeader::parse_arch32(mem).ok()? {
            archs.push(fat_arch_to_value(arch, None));
            files.push(fat_arch_to_file_value(arch, mem));
        }
    }

    Some(
        [
            ("fat_magic", magic),
            ("nfat_arch", nfat_arch),
            ("fat_arch", Some(Value::Array(archs))),
            ("file", Some(Value::Array(files))),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect(),
    )
}

fn fat_arch_to_file_value<A: FatArch>(arch: &A, mem: &[u8]) -> Value {
    Value::Object(arch.data(mem).ok().and_then(parse_file).unwrap_or_default())
}

fn fat_arch_to_value<A: FatArch>(arch: &A, reserved: Option<u32>) -> Value {
    let cputype = arch.cputype().into();
    let cpusubtype = arch.cpusubtype().into();
    let offset = arch.offset().into();
    let size = arch.size().into();
    let align = arch.align().into();

    Value::Object(
        [
            ("cputype", Some(cputype)),
            ("cpusubtype", Some(cpusubtype)),
            ("offset", offset.try_into().ok()),
            ("size", size.try_into().ok()),
            ("align", Some(align)),
            ("reserved", reserved.map(Into::into)),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect(),
    )
}
