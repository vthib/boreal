use std::collections::HashMap;

use crate::memory::Region;
use crate::regex::Regex;
use object::{
    coff::{CoffHeader, SymbolTable},
    pe::{self, ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64},
    read::pe::{
        DataDirectories, DelayLoadImportTable, ExportTable, ImageNtHeaders, ImageOptionalHeader,
        ImageThunkData, ImportTable, ImportThunkList, ResourceDirectory,
        ResourceDirectoryEntryData, ResourceNameOrId, RichHeaderInfo,
    },
    FileKind, LittleEndian as LE, StringTable,
};

use super::{
    EvalContext, Module, ModuleData, ModuleDataMap, ScanContext, StaticValue, Type, Value,
};

mod debug;
mod ord;
#[cfg(feature = "authenticode")]
mod signatures;
pub mod utils;
mod version_info;

const MAX_PE_SECTIONS: usize = 96;
const MAX_PE_IMPORTS: usize = 16384;
const MAX_PE_EXPORTS: usize = 16384;
const MAX_EXPORT_NAME_LENGTH: usize = 512;
const MAX_IMPORT_DLL_NAME_LENGTH: usize = 256;
const MAX_RESOURCES: usize = 65536;
const MAX_NB_DATA_DIRECTORIES: usize = 32768;
const MAX_NB_VERSION_INFOS: usize = 32768;

/// `pe` module. Allows inspecting PE inputs.
#[derive(Debug)]
pub struct Pe;

#[repr(u8)]
enum ImportType {
    Standard = 0b0001,
    Delayed = 0b0010,
}

impl Module for Pe {
    fn get_name(&self) -> &'static str {
        "pe"
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        #[allow(clippy::cast_possible_wrap)]
        #[allow(clippy::large_stack_arrays)]
        HashMap::from([
            (
                "MACHINE_UNKNOWN",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_UNKNOWN.into()),
            ),
            (
                "MACHINE_AM33",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_AM33.into()),
            ),
            (
                "MACHINE_AMD64",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_AMD64.into()),
            ),
            (
                "MACHINE_ARM",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_ARM.into()),
            ),
            (
                "MACHINE_ARMNT",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_ARMNT.into()),
            ),
            (
                "MACHINE_ARM64",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_ARM64.into()),
            ),
            (
                "MACHINE_EBC",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_EBC.into()),
            ),
            (
                "MACHINE_I386",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_I386.into()),
            ),
            (
                "MACHINE_IA64",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_IA64.into()),
            ),
            (
                "MACHINE_M32R",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_M32R.into()),
            ),
            (
                "MACHINE_MIPS16",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_MIPS16.into()),
            ),
            (
                "MACHINE_MIPSFPU",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_MIPSFPU.into()),
            ),
            (
                "MACHINE_MIPSFPU16",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_MIPSFPU16.into()),
            ),
            (
                "MACHINE_POWERPC",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_POWERPC.into()),
            ),
            (
                "MACHINE_POWERPCFP",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_POWERPCFP.into()),
            ),
            (
                "MACHINE_R4000",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_R4000.into()),
            ),
            (
                "MACHINE_SH3",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_SH3.into()),
            ),
            (
                "MACHINE_SH3DSP",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_SH3DSP.into()),
            ),
            (
                "MACHINE_SH4",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_SH4.into()),
            ),
            (
                "MACHINE_SH5",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_SH5.into()),
            ),
            (
                "MACHINE_THUMB",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_THUMB.into()),
            ),
            (
                "MACHINE_WCEMIPSV2",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_WCEMIPSV2.into()),
            ),
            (
                "MACHINE_TARGET_HOST",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_TARGET_HOST.into()),
            ),
            (
                "MACHINE_R3000",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_R3000.into()),
            ),
            (
                "MACHINE_R10000",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_R10000.into()),
            ),
            (
                "MACHINE_ALPHA",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_ALPHA.into()),
            ),
            (
                "MACHINE_SH3E",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_SH3E.into()),
            ),
            (
                "MACHINE_ALPHA64",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_ALPHA64.into()),
            ),
            (
                "MACHINE_AXP64",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_AXP64.into()),
            ),
            (
                "MACHINE_TRICORE",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_TRICORE.into()),
            ),
            (
                "MACHINE_CEF",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_CEF.into()),
            ),
            (
                "MACHINE_CEE",
                StaticValue::Integer(pe::IMAGE_FILE_MACHINE_CEE.into()),
            ),
            (
                "SUBSYSTEM_UNKNOWN",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_UNKNOWN.into()),
            ),
            (
                "SUBSYSTEM_NATIVE",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_NATIVE.into()),
            ),
            (
                "SUBSYSTEM_WINDOWS_GUI",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_WINDOWS_GUI.into()),
            ),
            (
                "SUBSYSTEM_WINDOWS_CUI",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_WINDOWS_CUI.into()),
            ),
            (
                "SUBSYSTEM_OS2_CUI",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_OS2_CUI.into()),
            ),
            (
                "SUBSYSTEM_POSIX_CUI",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_POSIX_CUI.into()),
            ),
            (
                "SUBSYSTEM_NATIVE_WINDOWS",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_NATIVE_WINDOWS.into()),
            ),
            (
                "SUBSYSTEM_WINDOWS_CE_GUI",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_WINDOWS_CE_GUI.into()),
            ),
            (
                "SUBSYSTEM_EFI_APPLICATION",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_EFI_APPLICATION.into()),
            ),
            (
                "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER.into()),
            ),
            (
                "SUBSYSTEM_EFI_RUNTIME_DRIVER",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER.into()),
            ),
            (
                "SUBSYSTEM_EFI_ROM_IMAGE",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_EFI_ROM.into()),
            ),
            (
                "SUBSYSTEM_XBOX",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_XBOX.into()),
            ),
            (
                "SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
                StaticValue::Integer(pe::IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION.into()),
            ),
            (
                "HIGH_ENTROPY_VA",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA.into()),
            ),
            (
                "DYNAMIC_BASE",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE.into()),
            ),
            (
                "FORCE_INTEGRITY",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.into()),
            ),
            (
                "NX_COMPAT",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT.into()),
            ),
            (
                "NO_ISOLATION",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION.into()),
            ),
            (
                "NO_SEH",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_NO_SEH.into()),
            ),
            (
                "NO_BIND",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_NO_BIND.into()),
            ),
            (
                "APPCONTAINER",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_APPCONTAINER.into()),
            ),
            (
                "WDM_DRIVER",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_WDM_DRIVER.into()),
            ),
            (
                "GUARD_CF",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF.into()),
            ),
            (
                "TERMINAL_SERVER_AWARE",
                StaticValue::Integer(pe::IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE.into()),
            ),
            (
                "RELOCS_STRIPPED",
                StaticValue::Integer(pe::IMAGE_FILE_RELOCS_STRIPPED.into()),
            ),
            (
                "EXECUTABLE_IMAGE",
                StaticValue::Integer(pe::IMAGE_FILE_EXECUTABLE_IMAGE.into()),
            ),
            (
                "LINE_NUMS_STRIPPED",
                StaticValue::Integer(pe::IMAGE_FILE_LINE_NUMS_STRIPPED.into()),
            ),
            (
                "LOCAL_SYMS_STRIPPED",
                StaticValue::Integer(pe::IMAGE_FILE_LOCAL_SYMS_STRIPPED.into()),
            ),
            (
                "AGGRESIVE_WS_TRIM",
                StaticValue::Integer(pe::IMAGE_FILE_AGGRESIVE_WS_TRIM.into()),
            ),
            (
                "LARGE_ADDRESS_AWARE",
                StaticValue::Integer(pe::IMAGE_FILE_LARGE_ADDRESS_AWARE.into()),
            ),
            (
                "BYTES_REVERSED_LO",
                StaticValue::Integer(pe::IMAGE_FILE_BYTES_REVERSED_LO.into()),
            ),
            (
                "MACHINE_32BIT",
                StaticValue::Integer(pe::IMAGE_FILE_32BIT_MACHINE.into()),
            ),
            (
                "DEBUG_STRIPPED",
                StaticValue::Integer(pe::IMAGE_FILE_DEBUG_STRIPPED.into()),
            ),
            (
                "REMOVABLE_RUN_FROM_SWAP",
                StaticValue::Integer(pe::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP.into()),
            ),
            (
                "NET_RUN_FROM_SWAP",
                StaticValue::Integer(pe::IMAGE_FILE_NET_RUN_FROM_SWAP.into()),
            ),
            ("SYSTEM", StaticValue::Integer(pe::IMAGE_FILE_SYSTEM.into())),
            ("DLL", StaticValue::Integer(pe::IMAGE_FILE_DLL.into())),
            (
                "UP_SYSTEM_ONLY",
                StaticValue::Integer(pe::IMAGE_FILE_UP_SYSTEM_ONLY.into()),
            ),
            (
                "BYTES_REVERSED_HI",
                StaticValue::Integer(pe::IMAGE_FILE_BYTES_REVERSED_HI.into()),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_EXPORT",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_EXPORT as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_IMPORT",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_IMPORT as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_RESOURCE",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_RESOURCE as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_SECURITY",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_SECURITY as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_BASERELOC",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_DEBUG",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_DEBUG as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_ARCHITECTURE as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_ARCHITECTURE as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_GLOBALPTR as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_TLS",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_TLS as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_IAT",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_IAT as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT as i64),
            ),
            (
                "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
                StaticValue::Integer(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR as i64),
            ),
            (
                "IMAGE_NT_OPTIONAL_HDR32_MAGIC",
                StaticValue::Integer(pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC.into()),
            ),
            (
                "IMAGE_NT_OPTIONAL_HDR64_MAGIC",
                StaticValue::Integer(pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC.into()),
            ),
            (
                "IMAGE_ROM_OPTIONAL_HDR_MAGIC",
                StaticValue::Integer(pe::IMAGE_ROM_OPTIONAL_HDR_MAGIC.into()),
            ),
            (
                "SECTION_NO_PAD",
                StaticValue::Integer(pe::IMAGE_SCN_TYPE_NO_PAD.into()),
            ),
            (
                "SECTION_CNT_CODE",
                StaticValue::Integer(pe::IMAGE_SCN_CNT_CODE.into()),
            ),
            (
                "SECTION_CNT_INITIALIZED_DATA",
                StaticValue::Integer(pe::IMAGE_SCN_CNT_INITIALIZED_DATA.into()),
            ),
            (
                "SECTION_CNT_UNINITIALIZED_DATA",
                StaticValue::Integer(pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.into()),
            ),
            (
                "SECTION_LNK_OTHER",
                StaticValue::Integer(pe::IMAGE_SCN_LNK_OTHER.into()),
            ),
            (
                "SECTION_LNK_INFO",
                StaticValue::Integer(pe::IMAGE_SCN_LNK_INFO.into()),
            ),
            (
                "SECTION_LNK_REMOVE",
                StaticValue::Integer(pe::IMAGE_SCN_LNK_REMOVE.into()),
            ),
            (
                "SECTION_LNK_COMDAT",
                StaticValue::Integer(pe::IMAGE_SCN_LNK_COMDAT.into()),
            ),
            (
                "SECTION_NO_DEFER_SPEC_EXC",
                StaticValue::Integer(pe::IMAGE_SCN_NO_DEFER_SPEC_EXC.into()),
            ),
            (
                "SECTION_GPREL",
                StaticValue::Integer(pe::IMAGE_SCN_GPREL.into()),
            ),
            (
                "SECTION_MEM_FARDATA",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_FARDATA.into()),
            ),
            (
                "SECTION_MEM_PURGEABLE",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_PURGEABLE.into()),
            ),
            (
                "SECTION_MEM_16BIT",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_16BIT.into()),
            ),
            (
                "SECTION_MEM_LOCKED",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_LOCKED.into()),
            ),
            (
                "SECTION_MEM_PRELOAD",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_PRELOAD.into()),
            ),
            (
                "SECTION_ALIGN_1BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_1BYTES.into()),
            ),
            (
                "SECTION_ALIGN_2BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_2BYTES.into()),
            ),
            (
                "SECTION_ALIGN_4BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_4BYTES.into()),
            ),
            (
                "SECTION_ALIGN_8BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_8BYTES.into()),
            ),
            (
                "SECTION_ALIGN_16BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_16BYTES.into()),
            ),
            (
                "SECTION_ALIGN_32BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_32BYTES.into()),
            ),
            (
                "SECTION_ALIGN_64BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_64BYTES.into()),
            ),
            (
                "SECTION_ALIGN_128BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_128BYTES.into()),
            ),
            (
                "SECTION_ALIGN_256BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_256BYTES.into()),
            ),
            (
                "SECTION_ALIGN_512BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_512BYTES.into()),
            ),
            (
                "SECTION_ALIGN_1024BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_1024BYTES.into()),
            ),
            (
                "SECTION_ALIGN_2048BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_2048BYTES.into()),
            ),
            (
                "SECTION_ALIGN_4096BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_4096BYTES.into()),
            ),
            (
                "SECTION_ALIGN_8192BYTES",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_8192BYTES.into()),
            ),
            (
                "SECTION_ALIGN_MASK",
                StaticValue::Integer(pe::IMAGE_SCN_ALIGN_MASK.into()),
            ),
            (
                "SECTION_LNK_NRELOC_OVFL",
                StaticValue::Integer(pe::IMAGE_SCN_LNK_NRELOC_OVFL.into()),
            ),
            (
                "SECTION_MEM_DISCARDABLE",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_DISCARDABLE.into()),
            ),
            (
                "SECTION_MEM_NOT_CACHED",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_NOT_CACHED.into()),
            ),
            (
                "SECTION_MEM_NOT_PAGED",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_NOT_PAGED.into()),
            ),
            (
                "SECTION_MEM_SHARED",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_SHARED.into()),
            ),
            (
                "SECTION_MEM_EXECUTE",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_EXECUTE.into()),
            ),
            (
                "SECTION_MEM_READ",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_READ.into()),
            ),
            (
                "SECTION_MEM_WRITE",
                StaticValue::Integer(pe::IMAGE_SCN_MEM_WRITE.into()),
            ),
            (
                "SECTION_SCALE_INDEX",
                StaticValue::Integer(pe::IMAGE_SCN_SCALE_INDEX.into()),
            ),
            (
                "RESOURCE_TYPE_CURSOR",
                StaticValue::Integer(pe::RT_CURSOR.into()),
            ),
            (
                "RESOURCE_TYPE_BITMAP",
                StaticValue::Integer(pe::RT_BITMAP.into()),
            ),
            (
                "RESOURCE_TYPE_ICON",
                StaticValue::Integer(pe::RT_ICON.into()),
            ),
            (
                "RESOURCE_TYPE_MENU",
                StaticValue::Integer(pe::RT_MENU.into()),
            ),
            (
                "RESOURCE_TYPE_DIALOG",
                StaticValue::Integer(pe::RT_DIALOG.into()),
            ),
            (
                "RESOURCE_TYPE_STRING",
                StaticValue::Integer(pe::RT_STRING.into()),
            ),
            (
                "RESOURCE_TYPE_FONTDIR",
                StaticValue::Integer(pe::RT_FONTDIR.into()),
            ),
            (
                "RESOURCE_TYPE_FONT",
                StaticValue::Integer(pe::RT_FONT.into()),
            ),
            (
                "RESOURCE_TYPE_ACCELERATOR",
                StaticValue::Integer(pe::RT_ACCELERATOR.into()),
            ),
            (
                "RESOURCE_TYPE_RCDATA",
                StaticValue::Integer(pe::RT_RCDATA.into()),
            ),
            (
                "RESOURCE_TYPE_MESSAGETABLE",
                StaticValue::Integer(pe::RT_MESSAGETABLE.into()),
            ),
            (
                "RESOURCE_TYPE_GROUP_CURSOR",
                StaticValue::Integer(pe::RT_GROUP_CURSOR.into()),
            ),
            (
                "RESOURCE_TYPE_GROUP_ICON",
                StaticValue::Integer(pe::RT_GROUP_ICON.into()),
            ),
            (
                "RESOURCE_TYPE_VERSION",
                StaticValue::Integer(pe::RT_VERSION.into()),
            ),
            (
                "RESOURCE_TYPE_DLGINCLUDE",
                StaticValue::Integer(pe::RT_DLGINCLUDE.into()),
            ),
            (
                "RESOURCE_TYPE_PLUGPLAY",
                StaticValue::Integer(pe::RT_PLUGPLAY.into()),
            ),
            ("RESOURCE_TYPE_VXD", StaticValue::Integer(pe::RT_VXD.into())),
            (
                "RESOURCE_TYPE_ANICURSOR",
                StaticValue::Integer(pe::RT_ANICURSOR.into()),
            ),
            (
                "RESOURCE_TYPE_ANIICON",
                StaticValue::Integer(pe::RT_ANIICON.into()),
            ),
            (
                "RESOURCE_TYPE_HTML",
                StaticValue::Integer(pe::RT_HTML.into()),
            ),
            (
                "RESOURCE_TYPE_MANIFEST",
                StaticValue::Integer(pe::RT_MANIFEST.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_UNKNOWN",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_UNKNOWN.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_COFF",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_COFF.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_CODEVIEW",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_CODEVIEW.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_FPO",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_FPO.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_MISC",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_MISC.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_EXCEPTION",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_EXCEPTION.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_FIXUP",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_FIXUP.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_OMAP_TO_SRC.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_OMAP_FROM_SRC.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_BORLAND",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_BORLAND.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_RESERVED10",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_RESERVED10.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_CLSID",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_CLSID.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_VC_FEATURE",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_VC_FEATURE.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_POGO",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_POGO.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_ILTCG",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_ILTCG.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_MPX",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_MPX.into()),
            ),
            (
                "IMAGE_DEBUG_TYPE_REPRO",
                StaticValue::Integer(pe::IMAGE_DEBUG_TYPE_REPRO.into()),
            ),
            (
                "IMPORT_DELAYED",
                StaticValue::Integer((ImportType::Delayed as u8).into()),
            ),
            (
                "IMPORT_STANDARD",
                StaticValue::Integer((ImportType::Standard as u8).into()),
            ),
            ("IMPORT_ANY", StaticValue::Integer(!0)),
            (
                "section_index",
                StaticValue::function(
                    Self::section_index,
                    vec![vec![Type::Bytes], vec![Type::Integer]],
                    Type::Integer,
                ),
            ),
            (
                "exports",
                StaticValue::function(
                    Self::exports,
                    vec![vec![Type::Bytes], vec![Type::Integer], vec![Type::Regex]],
                    Type::Integer,
                ),
            ),
            (
                "exports_index",
                StaticValue::function(
                    Self::exports_index,
                    vec![vec![Type::Bytes], vec![Type::Integer], vec![Type::Regex]],
                    Type::Integer,
                ),
            ),
            (
                "imports",
                StaticValue::function(
                    Self::imports,
                    vec![
                        vec![Type::Bytes, Type::Bytes],
                        vec![Type::Bytes, Type::Integer],
                        vec![Type::Bytes],
                        vec![Type::Regex, Type::Regex],
                        vec![Type::Integer, Type::Bytes, Type::Bytes],
                        vec![Type::Integer, Type::Bytes, Type::Integer],
                        vec![Type::Integer, Type::Bytes],
                        vec![Type::Integer, Type::Regex, Type::Regex],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "import_rva",
                StaticValue::function(
                    Self::import_rva,
                    vec![
                        vec![Type::Bytes, Type::Bytes],
                        vec![Type::Bytes, Type::Integer],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "delayed_import_rva",
                StaticValue::function(
                    Self::delayed_import_rva,
                    vec![
                        vec![Type::Bytes, Type::Bytes],
                        vec![Type::Bytes, Type::Integer],
                    ],
                    Type::Integer,
                ),
            ),
            (
                "locale",
                StaticValue::function(Self::locale, vec![vec![Type::Integer]], Type::Integer),
            ),
            (
                "language",
                StaticValue::function(Self::language, vec![vec![Type::Integer]], Type::Integer),
            ),
            (
                "is_dll",
                StaticValue::function(Self::is_dll, vec![], Type::Integer),
            ),
            (
                "is_32bit",
                StaticValue::function(Self::is_32bit, vec![], Type::Integer),
            ),
            (
                "is_64bit",
                StaticValue::function(Self::is_64bit, vec![], Type::Integer),
            ),
            (
                "calculate_checksum",
                StaticValue::function(Self::calculate_checksum, vec![], Type::Integer),
            ),
            #[cfg(feature = "hash")]
            (
                "imphash",
                StaticValue::function(Self::imphash, vec![], Type::Bytes),
            ),
            (
                "rva_to_offset",
                StaticValue::function(
                    Self::rva_to_offset,
                    vec![vec![Type::Integer]],
                    Type::Integer,
                ),
            ),
        ])
    }

    fn get_dynamic_types(&self) -> HashMap<&'static str, Type> {
        [
            ("is_pe", Type::Integer),
            // File header
            ("machine", Type::Integer),
            ("number_of_sections", Type::Integer),
            ("timestamp", Type::Integer),
            ("pointer_to_symbol_table", Type::Integer),
            ("number_of_symbols", Type::Integer),
            ("size_of_optional_header", Type::Integer),
            ("characteristics", Type::Integer),
            //
            ("entry_point", Type::Integer),
            ("entry_point_raw", Type::Integer),
            ("image_base", Type::Integer),
            ("number_of_rva_and_sizes", Type::Integer),
            ("number_of_version_infos", Type::Integer),
            // version info
            ("version_info", Type::dict(Type::Bytes)),
            (
                "version_info_list",
                Type::array(Type::object([("key", Type::Bytes), ("value", Type::Bytes)])),
            ),
            // Optional header part 1
            ("opthdr_magic", Type::Integer),
            ("size_of_code", Type::Integer),
            ("size_of_initialized_data", Type::Integer),
            ("size_of_uninitialized_data", Type::Integer),
            ("base_of_code", Type::Integer),
            ("base_of_data", Type::Integer),
            ("section_alignment", Type::Integer),
            ("file_alignment", Type::Integer),
            (
                "linker_version",
                Type::object([("major", Type::Integer), ("minor", Type::Integer)]),
            ),
            (
                "os_version",
                Type::object([("major", Type::Integer), ("minor", Type::Integer)]),
            ),
            (
                "image_version",
                Type::object([("major", Type::Integer), ("minor", Type::Integer)]),
            ),
            (
                "subsystem_version",
                Type::object([("major", Type::Integer), ("minor", Type::Integer)]),
            ),
            ("win32_version_value", Type::Integer),
            ("size_of_image", Type::Integer),
            ("size_of_headers", Type::Integer),
            ("checksum", Type::Integer),
            ("subsystem", Type::Integer),
            ("dll_characteristics", Type::Integer),
            ("size_of_stack_reserve", Type::Integer),
            ("size_of_stack_commit", Type::Integer),
            ("size_of_heap_reserve", Type::Integer),
            ("size_of_heap_commit", Type::Integer),
            ("loader_flags", Type::Integer),
            //
            (
                "data_directories",
                Type::array(Type::object([
                    ("virtual_address", Type::Integer),
                    ("size", Type::Integer),
                ])),
            ),
            (
                "sections",
                Type::array(Type::object([
                    ("name", Type::Bytes),
                    ("full_name", Type::Bytes),
                    ("characteristics", Type::Integer),
                    ("virtual_address", Type::Integer),
                    ("virtual_size", Type::Integer),
                    ("raw_data_offset", Type::Integer),
                    ("raw_data_size", Type::Integer),
                    ("pointer_to_relocations", Type::Integer),
                    ("pointer_to_line_numbers", Type::Integer),
                    ("number_of_relocations", Type::Integer),
                    ("number_of_line_numbers", Type::Integer),
                ])),
            ),
            (
                "overlay",
                Type::object([("offset", Type::Integer), ("size", Type::Integer)]),
            ),
            (
                "rich_signature",
                Type::object([
                    ("offset", Type::Integer),
                    ("length", Type::Integer),
                    ("key", Type::Integer),
                    ("raw_data", Type::Bytes),
                    ("clear_data", Type::Bytes),
                    ("version_data", Type::Bytes),
                    (
                        "version",
                        Type::function(
                            vec![vec![Type::Integer], vec![Type::Integer, Type::Integer]],
                            Type::Integer,
                        ),
                    ),
                    (
                        "toolid",
                        Type::function(
                            vec![vec![Type::Integer], vec![Type::Integer, Type::Integer]],
                            Type::Integer,
                        ),
                    ),
                ]),
            ),
            ("number_of_imports", Type::Integer),
            ("number_of_imported_functions", Type::Integer),
            ("number_of_delayed_imports", Type::Integer),
            ("number_of_delayed_imported_functions", Type::Integer),
            ("number_of_exports", Type::Integer),
            //
            ("dll_name", Type::Bytes),
            ("export_timestamp", Type::Integer),
            (
                "export_details",
                Type::array(Type::object([
                    ("offset", Type::Integer),
                    ("name", Type::Bytes),
                    ("forward_name", Type::Bytes),
                    ("ordinal", Type::Integer),
                    ("rva", Type::Integer),
                ])),
            ),
            (
                "import_details",
                Type::array(Type::object([
                    ("library_name", Type::Bytes),
                    ("number_of_functions", Type::Integer),
                    (
                        "functions",
                        Type::array(Type::object([
                            ("name", Type::Bytes),
                            ("ordinal", Type::Integer),
                            ("rva", Type::Integer),
                        ])),
                    ),
                ])),
            ),
            (
                "delayed_import_details",
                Type::array(Type::object([
                    ("library_name", Type::Bytes),
                    ("number_of_functions", Type::Integer),
                    (
                        "functions",
                        Type::array(Type::object([
                            ("name", Type::Bytes),
                            ("ordinal", Type::Integer),
                            ("rva", Type::Integer),
                        ])),
                    ),
                ])),
            ),
            ("resource_timestamp", Type::Integer),
            (
                "resource_version",
                Type::object([("major", Type::Integer), ("minor", Type::Integer)]),
            ),
            (
                "resources",
                Type::array(Type::object([
                    ("rva", Type::Integer),
                    ("offset", Type::Integer),
                    ("length", Type::Integer),
                    ("type", Type::Integer),
                    ("id", Type::Integer),
                    ("language", Type::Integer),
                    ("type_string", Type::Bytes),
                    ("name_string", Type::Bytes),
                    ("language_string", Type::Bytes),
                ])),
            ),
            ("number_of_resources", Type::Integer),
            ("pdb_path", Type::Bytes),
            #[cfg(feature = "authenticode")]
            ("number_of_signatures", Type::Integer),
            #[cfg(feature = "authenticode")]
            ("is_signed", Type::Integer),
            #[cfg(feature = "authenticode")]
            (
                "signatures",
                Type::array(Type::object([
                    ("thumbprint", Type::Bytes),
                    ("issuer", Type::Bytes),
                    ("subject", Type::Bytes),
                    ("version", Type::Integer),
                    ("algorithm", Type::Bytes),
                    ("algorithm_oid", Type::Bytes),
                    ("serial", Type::Bytes),
                    ("not_before", Type::Integer),
                    ("not_after", Type::Integer),
                    ("verified", Type::Integer),
                    ("digest_alg", Type::Bytes),
                    ("digest", Type::Bytes),
                    ("file_digest", Type::Bytes),
                    ("number_of_certificates", Type::Integer),
                    (
                        "certificates",
                        Type::array(Type::object([
                            ("thumbprint", Type::Bytes),
                            ("issuer", Type::Bytes),
                            ("subject", Type::Bytes),
                            ("version", Type::Integer),
                            ("algorithm", Type::Bytes),
                            ("algorithm_oid", Type::Bytes),
                            ("serial", Type::Bytes),
                            ("not_before", Type::Integer),
                            ("not_after", Type::Integer),
                        ])),
                    ),
                    (
                        "signer_info",
                        Type::object([
                            ("program_name", Type::Bytes),
                            ("digest", Type::Bytes),
                            ("digest_alg", Type::Bytes),
                            ("length_of_chain", Type::Integer),
                            (
                                "chain",
                                Type::array(Type::object([
                                    ("thumbprint", Type::Bytes),
                                    ("issuer", Type::Bytes),
                                    ("subject", Type::Bytes),
                                    ("version", Type::Integer),
                                    ("algorithm", Type::Bytes),
                                    ("algorithm_oid", Type::Bytes),
                                    ("serial", Type::Bytes),
                                    ("not_before", Type::Integer),
                                    ("not_after", Type::Integer),
                                ])),
                            ),
                        ]),
                    ),
                    ("number_of_countersignatures", Type::Integer),
                    (
                        "countersignatures",
                        Type::array(Type::object([
                            ("verified", Type::Integer),
                            ("sign_time", Type::Integer),
                            ("digest", Type::Bytes),
                            ("digest_alg", Type::Bytes),
                            ("length_of_chain", Type::Integer),
                            (
                                "chain",
                                Type::array(Type::object([
                                    ("thumbprint", Type::Bytes),
                                    ("issuer", Type::Bytes),
                                    ("subject", Type::Bytes),
                                    ("version", Type::Integer),
                                    ("algorithm", Type::Bytes),
                                    ("algorithm_oid", Type::Bytes),
                                    ("serial", Type::Bytes),
                                    ("not_before", Type::Integer),
                                    ("not_after", Type::Integer),
                                ])),
                            ),
                        ])),
                    ),
                    (
                        "valid_on",
                        Type::function(vec![vec![Type::Integer]], Type::Integer),
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

        if data.found_pe {
            // We already found a PE in a region, so ignore the others
            return;
        }

        let res = match FileKind::parse(ctx.region.mem) {
            Ok(FileKind::Pe32) => {
                data.is_32bit = true;
                parse_file::<ImageNtHeaders32>(ctx.region, ctx.process_memory, data)
            }
            Ok(FileKind::Pe64) => {
                data.is_32bit = false;
                parse_file::<ImageNtHeaders64>(ctx.region, ctx.process_memory, data)
            }
            _ => None,
        };

        match res {
            Some(values) => {
                *out = values;
                data.found_pe = true;
            }
            None => *out = [("is_pe", 0.into())].into(),
        }
    }
}

impl ModuleData for Pe {
    type PrivateData = Data;
    type UserData = ();
}

fn parse_file<HEADERS: ImageNtHeaders>(
    region: &Region,
    process_memory: bool,
    data: &mut Data,
) -> Option<HashMap<&'static str, Value>> {
    let dos_header = ImageDosHeader::parse(region.mem).ok()?;
    let mut offset = dos_header.nt_headers_offset().into();
    let (nt_headers, data_dirs) = HEADERS::parse(region.mem, &mut offset).ok()?;

    let sections = utils::SectionTable::new(nt_headers, region.mem, offset);

    let hdr = nt_headers.file_header();
    let characteristics = hdr.characteristics.get(LE);

    if process_memory && (characteristics & pe::IMAGE_FILE_DLL) != 0 {
        return None;
    }

    let symbols = hdr.symbols(region.mem).ok();

    let opt_hdr = nt_headers.optional_header();
    let ep = opt_hdr.address_of_entry_point();

    // libyara does not return a bool, but the result of the bitwise and...
    data.is_dll = characteristics & pe::IMAGE_FILE_DLL;

    let entrypoint: Value = if process_memory {
        let ep: Option<usize> = ep.try_into().ok();
        ep.and_then(|ep| ep.checked_add(region.start)).into()
    } else {
        sections
            .as_ref()
            .and_then(|sections| utils::va_to_file_offset(region.mem, sections, ep))
            .map_or(-1, i64::from)
            .into()
    };

    let mut map: HashMap<_, _> = [
        ("is_pe", Value::Integer(1)),
        // File header
        ("machine", hdr.machine.get(LE).into()),
        ("number_of_sections", hdr.number_of_sections.get(LE).into()),
        ("timestamp", hdr.time_date_stamp.get(LE).into()),
        (
            "pointer_to_symbol_table",
            hdr.pointer_to_symbol_table.get(LE).into(),
        ),
        ("number_of_symbols", hdr.number_of_symbols.get(LE).into()),
        (
            "size_of_optional_header",
            hdr.size_of_optional_header.get(LE).into(),
        ),
        ("characteristics", characteristics.into()),
        //
        ("entry_point", entrypoint),
        ("entry_point_raw", ep.into()),
        ("image_base", opt_hdr.image_base().into()),
        (
            "number_of_rva_and_sizes",
            opt_hdr.number_of_rva_and_sizes().into(),
        ),
        // Optional header
        ("opthdr_magic", opt_hdr.magic().into()),
        ("size_of_code", opt_hdr.size_of_code().into()),
        (
            "size_of_initialized_data",
            opt_hdr.size_of_initialized_data().into(),
        ),
        (
            "size_of_uninitialized_data",
            opt_hdr.size_of_uninitialized_data().into(),
        ),
        ("base_of_code", opt_hdr.base_of_code().into()),
        ("base_of_data", opt_hdr.base_of_data().into()),
        ("section_alignment", opt_hdr.section_alignment().into()),
        ("file_alignment", opt_hdr.file_alignment().into()),
        (
            "linker_version",
            Value::object([
                ("major", opt_hdr.major_linker_version().into()),
                ("minor", opt_hdr.minor_linker_version().into()),
            ]),
        ),
        (
            "os_version",
            Value::object([
                ("major", opt_hdr.major_operating_system_version().into()),
                ("minor", opt_hdr.minor_operating_system_version().into()),
            ]),
        ),
        (
            "image_version",
            Value::object([
                ("major", opt_hdr.major_image_version().into()),
                ("minor", opt_hdr.minor_image_version().into()),
            ]),
        ),
        (
            "subsystem_version",
            Value::object([
                ("major", opt_hdr.major_subsystem_version().into()),
                ("minor", opt_hdr.minor_subsystem_version().into()),
            ]),
        ),
        ("win32_version_value", opt_hdr.win32_version_value().into()),
        ("size_of_image", opt_hdr.size_of_image().into()),
        ("size_of_headers", opt_hdr.size_of_headers().into()),
        ("checksum", opt_hdr.check_sum().into()),
        ("subsystem", opt_hdr.subsystem().into()),
        ("dll_characteristics", opt_hdr.dll_characteristics().into()),
        (
            "size_of_stack_reserve",
            opt_hdr.size_of_stack_reserve().into(),
        ),
        (
            "size_of_stack_commit",
            opt_hdr.size_of_stack_commit().into(),
        ),
        (
            "size_of_heap_reserve",
            opt_hdr.size_of_heap_reserve().into(),
        ),
        ("size_of_heap_commit", opt_hdr.size_of_heap_commit().into()),
        ("loader_flags", opt_hdr.loader_flags().into()),
        //
        ("data_directories", data_directories(data_dirs)),
        (
            "sections",
            sections.as_ref().map_or(Value::Undefined, |sections| {
                sections_to_value(sections, symbols.as_ref().map(SymbolTable::strings), data)
            }),
        ),
        (
            "overlay",
            sections
                .as_ref()
                .map_or(Value::Undefined, |sections| overlay(sections, region.mem)),
        ),
        (
            "pdb_path",
            sections
                .as_ref()
                .and_then(|sections| debug::pdb_path(&data_dirs, region.mem, sections))
                .unwrap_or(Value::Undefined),
        ),
        (
            "rich_signature",
            RichHeaderInfo::parse(region.mem, dos_header.nt_headers_offset().into()).map_or_else(
                || {
                    // Setting this is a bit useless, but it mirrors what yara does
                    // and helps comparing module values.
                    Value::object([
                        ("version", Value::function(Pe::rich_signature_version)),
                        ("toolid", Value::function(Pe::rich_signature_toolid)),
                    ])
                },
                |info| rich_signature(info, region, data),
            ),
        ),
        ("number_of_version_infos", 0.into()),
    ]
    .into();

    if let Some(sections) = sections.as_ref() {
        add_imports::<HEADERS>(&data_dirs, region.mem, sections, data, &mut map);
        add_delay_load_imports::<HEADERS>(&data_dirs, region.mem, sections, data, &mut map);
        add_exports(&data_dirs, region.mem, sections, data, &mut map);
        add_resources(&data_dirs, region.mem, sections, data, &mut map);
    }

    #[cfg(feature = "authenticode")]
    if let Some((signatures, is_signed)) = signatures::get_signatures(&data_dirs, region.mem) {
        let _r = map.insert("number_of_signatures", signatures.len().into());
        let _r = map.insert("is_signed", is_signed);
        let _r = map.insert("signatures", Value::Array(signatures));
    } else {
        let _r = map.insert("number_of_signatures", Value::Integer(0));
        let _r = map.insert("is_signed", Value::Integer(0));
    }

    Some(map)
}

fn rich_signature(info: RichHeaderInfo, region: &Region, data: &mut Data) -> Value {
    data.rich_entries = info
        .unmasked_entries()
        .map(|entry| DataRichEntry {
            version: (entry.comp_id & 0xFFFF) as u16,
            toolid: (entry.comp_id >> 16) as u16,
            times: entry.count,
        })
        .collect();

    let length = info.length.saturating_sub(8);

    let raw = if info.offset + length <= region.mem.len() {
        Some(region.mem[info.offset..(info.offset + length)].to_vec())
    } else {
        None
    };
    let xor_key_bytes = info.xor_key.to_le_bytes();
    // Xor raw with the xor_key, but 4 bytes by 4 bytes
    let clear = raw.clone().map(|mut clear| {
        for (b, k) in clear.iter_mut().zip(xor_key_bytes.iter().cycle()) {
            *b ^= k;
        }
        clear
    });

    let mut version = Vec::new();
    for entry in info.unmasked_entries() {
        version.extend(entry.comp_id.to_le_bytes().as_slice());
    }

    Value::object([
        ("offset", (region.start + info.offset).into()),
        ("length", length.into()),
        ("key", info.xor_key.into()),
        ("raw_data", raw.into()),
        ("clear_data", clear.into()),
        ("version_data", version.into()),
        ("version", Value::function(Pe::rich_signature_version)),
        ("toolid", Value::function(Pe::rich_signature_toolid)),
    ])
}

fn add_imports<Pe: ImageNtHeaders>(
    data_dirs: &DataDirectories,
    mem: &[u8],
    sections: &utils::SectionTable,
    data: &mut Data,
    out: &mut HashMap<&'static str, Value>,
) {
    let mut imports = Vec::new();
    let mut nb_functions_total = 0;

    let table = data_dirs
        .get(pe::IMAGE_DIRECTORY_ENTRY_IMPORT)
        .and_then(|dir| {
            let import_va = dir.virtual_address.get(LE);
            let (section_data, section_va) = sections.get_section_containing(mem, import_va)?;
            Some(ImportTable::new(section_data, section_va, import_va))
        });
    let descriptors = table.as_ref().and_then(|table| table.descriptors().ok());
    if let (Some(table), Some(mut descriptors)) = (table, descriptors) {
        while let Ok(Some(import_desc)) = descriptors.next() {
            let library = match table.name(import_desc.name.get(LE)) {
                Ok(name) => name.to_vec(),
                Err(_) => continue,
            };
            if library.len() >= MAX_IMPORT_DLL_NAME_LENGTH || !dll_name_is_valid(&library) {
                continue;
            }

            let mut data_functions = Vec::new();
            let import_thunk_list = table
                .thunks(import_desc.original_first_thunk.get(LE))
                .or_else(|_| table.thunks(import_desc.first_thunk.get(LE)));
            let functions = import_thunk_list.ok().map(|mut thunks| {
                import_functions::<Pe, _>(
                    &mut thunks,
                    &library,
                    |hint| table.hint_name(hint).map(|(_, name)| name.to_vec()),
                    import_desc.first_thunk.get(LE),
                    data.is_32bit,
                    &mut data_functions,
                    &mut nb_functions_total,
                )
            });
            if functions.as_ref().map_or(true, Vec::is_empty) {
                continue;
            }

            data.imports.push(DataImport {
                dll_name: library.clone(),
                functions: data_functions,
            });

            imports.push(Value::object([
                ("library_name", library.into()),
                (
                    "number_of_functions",
                    functions.as_ref().map(Vec::len).into(),
                ),
                (
                    "functions",
                    functions.map_or(Value::Undefined, Value::Array),
                ),
            ]));
            if imports.len() >= MAX_PE_IMPORTS {
                break;
            }
        }
    }

    out.extend([
        ("number_of_imported_functions", nb_functions_total.into()),
        ("number_of_imports", imports.len().into()),
        ("import_details", Value::Array(imports)),
    ]);
}

fn import_functions<Pe: ImageNtHeaders, F>(
    thunks: &mut ImportThunkList,
    dll_name: &[u8],
    hint_name: F,
    mut rva: u32,
    is_32: bool,
    data_functions: &mut Vec<DataFunction>,
    nb_functions_total: &mut usize,
) -> Vec<Value>
where
    F: Fn(u32) -> object::Result<Vec<u8>>,
{
    // FIXME: yara does rva adjusments, do we need to do it too?
    let mut functions = Vec::new();
    while let Ok(Some(thunk)) = thunks.next::<Pe>() {
        if *nb_functions_total >= MAX_PE_IMPORTS {
            break;
        }

        if add_thunk::<Pe, _>(
            thunk,
            dll_name,
            rva,
            is_32,
            &hint_name,
            &mut functions,
            data_functions,
        ) {
            *nb_functions_total += 1;
        }
        rva += if is_32 { 4 } else { 8 };
    }
    functions
}

fn add_thunk<Pe: ImageNtHeaders, F>(
    thunk: Pe::ImageThunkData,
    dll_name: &[u8],
    rva: u32,
    is_32: bool,
    hint_name: F,
    functions: &mut Vec<Value>,
    data_functions: &mut Vec<DataFunction>,
) -> bool
where
    F: Fn(u32) -> object::Result<Vec<u8>>,
{
    if thunk.is_ordinal() {
        let raw = if is_32 {
            thunk.raw() & 0x7FFF_FFFF
        } else {
            thunk.raw() & 0x7FFF_FFFF_FFFF_FFFF
        };

        let Ok(ordinal) = u16::try_from(raw) else {
            // Corrupted ordinal value, ignore
            return false;
        };
        let name = ord::ord_lookup(dll_name, ordinal);

        data_functions.push(DataFunction {
            name: name.clone(),
            ordinal: Some(ordinal),
            rva,
        });

        functions.push(Value::object([
            ("name", name.into()),
            ("ordinal", ordinal.into()),
            ("rva", rva.into()),
        ]));
        true
    } else {
        let Ok(name) = hint_name(thunk.address()) else {
            return false;
        };

        if !is_import_name_valid(&name) {
            return false;
        }

        data_functions.push(DataFunction {
            name: name.clone(),
            ordinal: None,
            rva,
        });
        functions.push(Value::object([("name", name.into()), ("rva", rva.into())]));
        true
    }
}

// This mirrors what pefile does.
// See https://github.com/erocarrera/pefile/blob/593d094e35198dad92aaf040bef17eb800c8a373/pefile.py#L2326-L2348
fn is_import_name_valid(name: &[u8]) -> bool {
    if name.is_empty() {
        false
    } else {
        name.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || [b'.', b'_', b'?', b'@', b'$', b'(', b')', b'<', b'>'].contains(b)
        })
    }
}

fn add_delay_load_imports<Pe: ImageNtHeaders>(
    data_dirs: &DataDirectories,
    mem: &[u8],
    sections: &utils::SectionTable,
    data: &mut Data,
    out: &mut HashMap<&'static str, Value>,
) {
    let mut imports = Vec::new();
    let mut nb_functions_total = 0;

    let table = data_dirs
        .get(pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
        .and_then(|dir| {
            let import_va = dir.virtual_address.get(LE);
            let (section_data, section_va) = sections.get_section_containing(mem, import_va)?;
            Some(DelayLoadImportTable::new(
                section_data,
                section_va,
                import_va,
            ))
        });
    let descriptors = table.as_ref().and_then(|table| table.descriptors().ok());
    if let (Some(table), Some(mut descriptors)) = (table, descriptors) {
        while let Ok(Some(import_desc)) = descriptors.next() {
            let library = match table.name(import_desc.dll_name_rva.get(LE)) {
                Ok(name) => name.to_vec(),
                Err(_) => continue,
            };
            if !dll_name_is_valid(&library) {
                continue;
            }

            let mut data_functions = Vec::new();
            let functions = table
                .thunks(import_desc.import_name_table_rva.get(LE))
                .ok()
                .map(|mut thunks| {
                    import_functions::<Pe, _>(
                        &mut thunks,
                        &library,
                        |hint| table.hint_name(hint).map(|(_, name)| name.to_vec()),
                        import_desc.import_address_table_rva.get(LE),
                        data.is_32bit,
                        &mut data_functions,
                        &mut nb_functions_total,
                    )
                });

            data.delayed_imports.push(DataImport {
                dll_name: library.clone(),
                functions: data_functions,
            });

            imports.push(Value::object([
                ("library_name", library.into()),
                (
                    "number_of_functions",
                    functions.as_ref().map(Vec::len).into(),
                ),
                (
                    "functions",
                    functions.map_or(Value::Undefined, Value::Array),
                ),
            ]));
            if imports.len() >= MAX_PE_IMPORTS {
                break;
            }
        }
    }

    out.extend([
        (
            "number_of_delayed_imported_functions",
            nb_functions_total.into(),
        ),
        ("number_of_delayed_imports", imports.len().into()),
        ("delayed_import_details", Value::Array(imports)),
    ]);
}

fn dll_name_is_valid(dll_name: &[u8]) -> bool {
    dll_name.iter().all(|c| {
        *c >= b' '
            && *c <= 0x7e
            && *c != b'\"'
            && *c != b'*'
            && *c != b'<'
            && *c != b'>'
            && *c != b'?'
            && *c != b'|'
    })
}

fn add_exports(
    data_dirs: &DataDirectories,
    mem: &[u8],
    sections: &utils::SectionTable,
    data: &mut Data,
    out: &mut HashMap<&'static str, Value>,
) {
    let export_table = data_dirs
        .get(pe::IMAGE_DIRECTORY_ENTRY_EXPORT)
        .and_then(|dir| {
            let export_va = dir.virtual_address.get(LE);
            let export_data = sections.get_dir_data(mem, *dir)?;
            ExportTable::parse(export_data, export_va).ok()
        });

    if let Some(table) = export_table {
        let ordinal_base = table.ordinal_base() as usize;
        let addresses = table.addresses();
        let mut details: Vec<_> = addresses
            .iter()
            .take(MAX_PE_EXPORTS)
            .enumerate()
            .map(|(i, address)| {
                let address = address.get(LE);
                let forward_name = table.forward_string(address).ok().flatten().map(|forward| {
                    if forward.len() > MAX_EXPORT_NAME_LENGTH {
                        forward[..MAX_EXPORT_NAME_LENGTH].to_vec()
                    } else {
                        forward.to_vec()
                    }
                });

                data.exports.push(DataExport {
                    name: None,
                    ordinal: ordinal_base + i,
                });

                Value::object([
                    ("ordinal", (ordinal_base + i).into()),
                    (
                        "offset",
                        match forward_name {
                            Some(_) => Value::Undefined,
                            // -1 is set by libyara to indicate an invalid offset.
                            None => match utils::va_to_file_offset(mem, sections, address) {
                                Some(v) => v.into(),
                                None => Value::Undefined,
                            },
                        },
                    ),
                    ("forward_name", forward_name.into()),
                    ("rva", address.into()),
                ])
            })
            .collect();

        // Now, add names
        for (name_pointer, ordinal_index) in table.name_iter() {
            let Ok(mut name) = table.name_from_pointer(name_pointer) else {
                continue;
            };
            if name.len() > MAX_EXPORT_NAME_LENGTH {
                name = &name[..MAX_EXPORT_NAME_LENGTH];
            }
            let ordinal_index = usize::from(ordinal_index);

            if let Some(Value::Object(map)) = details.get_mut(ordinal_index) {
                let _r = map.insert("name", Value::bytes(name));
            }
            if let Some(export) = data.exports.get_mut(ordinal_index) {
                export.name = Some(name.to_vec());
            }
        }

        let dir = table.directory();
        out.extend([
            ("export_timestamp", dir.time_date_stamp.get(LE).into()),
            (
                "dll_name",
                table
                    .name_from_pointer(dir.name.get(LE))
                    .ok()
                    .map(<[u8]>::to_vec)
                    .into(),
            ),
            ("number_of_exports", details.len().into()),
            ("export_details", Value::Array(details)),
        ]);
    } else {
        let _r = out.insert("number_of_exports", Value::Integer(0));
    }
}

fn data_directories(dirs: DataDirectories) -> Value {
    Value::Array(
        dirs.iter()
            .take(MAX_NB_DATA_DIRECTORIES)
            .map(|dir| {
                Value::object([
                    ("virtual_address", dir.virtual_address.get(LE).into()),
                    ("size", dir.size.get(LE).into()),
                ])
            })
            .collect(),
    )
}

fn sections_to_value(
    sections: &utils::SectionTable,
    strings: Option<StringTable>,
    data: &mut Data,
) -> Value {
    Value::Array(
        sections
            .iter()
            .take(MAX_PE_SECTIONS)
            .map(|section| {
                let mut name = section.name.as_slice();
                if let Some(last_non_zero_pos) = name
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(i, v)| (*v != 0).then_some(i))
                {
                    name = &name[..=last_non_zero_pos];
                }
                let full_name = match (strings, section.name_offset()) {
                    // Get full name from the strings table
                    // TODO: yara rejects a full name that contains non isprint bytes. But why?
                    (Some(strings), Ok(Some(offset))) => strings.get(offset).ok(),
                    // No offset into string table, full name is the same as the name
                    (_, Ok(None)) => Some(name),
                    (_, _) => None,
                };
                let raw_data_offset = i64::from(section.pointer_to_raw_data.get(LE));
                let raw_data_size = i64::from(section.size_of_raw_data.get(LE));
                let virtual_address = i64::from(section.virtual_address.get(LE));
                let virtual_size = i64::from(section.virtual_size.get(LE));

                data.sections.push(DataSection {
                    name: name.to_vec(),
                    raw_data_offset,
                    raw_data_size,
                    virtual_address,
                    virtual_size,
                });

                Value::object([
                    ("name", name.to_vec().into()),
                    ("full_name", full_name.map(<[u8]>::to_vec).into()),
                    ("characteristics", section.characteristics.get(LE).into()),
                    ("virtual_address", virtual_address.into()),
                    ("virtual_size", virtual_size.into()),
                    ("raw_data_size", raw_data_size.into()),
                    ("raw_data_offset", raw_data_offset.into()),
                    (
                        "pointer_to_relocations",
                        section.pointer_to_relocations.get(LE).into(),
                    ),
                    (
                        "pointer_to_line_numbers",
                        section.pointer_to_linenumbers.get(LE).into(),
                    ),
                    (
                        "number_of_relocations",
                        section.number_of_relocations.get(LE).into(),
                    ),
                    (
                        "number_of_line_numbers",
                        section.number_of_linenumbers.get(LE).into(),
                    ),
                ])
            })
            .collect(),
    )
}

fn overlay(sections: &utils::SectionTable, mem: &[u8]) -> Value {
    let offset = sections.max_section_file_offset();

    if offset < mem.len() as u64 {
        Value::object([
            ("offset", offset.into()),
            ("size", (mem.len() as u64 - offset).into()),
        ])
    } else {
        Value::object([("offset", 0.into()), ("size", 0.into())])
    }
}

fn add_resources(
    data_dirs: &DataDirectories,
    mem: &[u8],
    sections: &utils::SectionTable,
    data: &mut Data,
    out: &mut HashMap<&'static str, Value>,
) {
    let mut infos = Vec::new();

    let resource_dir = data_dirs
        .get(pe::IMAGE_DIRECTORY_ENTRY_RESOURCE)
        .and_then(|dir| {
            let rsrc_data = sections.get_dir_data(mem, *dir)?;
            Some(ResourceDirectory::new(rsrc_data))
        });

    let root = resource_dir.as_ref().and_then(|dir| dir.root().ok());
    if let (Some(dir), Some(root)) = (resource_dir, root) {
        let mut resources = Vec::new();

        'outer: for entry in root.entries {
            // Copied from 1242223b04f2 in libyara
            if entry.offset_to_data_or_directory.get(LE) == 0 {
                continue;
            }

            // First level is type
            let ty = entry.name_or_id.get(LE);
            let ty_name = match entry.name_or_id() {
                ResourceNameOrId::Name(name) => name.raw_data(dir).ok(),
                ResourceNameOrId::Id(_) => None,
            };

            let Ok(ResourceDirectoryEntryData::Table(table)) = entry.data(dir) else {
                continue;
            };
            for entry in table.entries {
                // Second level is id
                let id = entry.name_or_id.get(LE);
                let id_name = resource_entry_name(*entry, dir);

                let Ok(ResourceDirectoryEntryData::Table(table)) = entry.data(dir) else {
                    continue;
                };
                for entry in table.entries {
                    // Third level is language
                    let lang = entry.name_or_id.get(LE);
                    let lang_name = match entry.name_or_id() {
                        ResourceNameOrId::Name(name) => name.raw_data(dir).ok(),
                        ResourceNameOrId::Id(_) => None,
                    };

                    if let Ok(ResourceDirectoryEntryData::Data(entry_data)) = entry.data(dir) {
                        // Copied from 620963092c4 and 44fd0945446665 in libyara
                        // The goal is to reject corrupted/random values while accepting
                        // truncated files (where the size/offset may get out of bound compared
                        // to the scanned memory.
                        let size = entry_data.size.get(LE);
                        if size == 0 || size > 0x3FFF_FFFF {
                            continue;
                        }

                        let rva = entry_data.offset_to_data.get(LE);
                        let offset = utils::va_to_file_offset(mem, sections, rva);
                        if ty == u32::from(pe::RT_VERSION) {
                            if let Some(offset) = offset {
                                version_info::read_version_info(mem, offset as usize, &mut infos);
                            }
                        }

                        data.resource_languages.push(lang);

                        resources.push(Value::object([
                            ("rva", rva.into()),
                            ("length", entry_data.size.get(LE).into()),
                            ("offset", offset.into()),
                            ("type_string", ty_name.map(<[u8]>::to_vec).into()),
                            (
                                "type",
                                match ty_name {
                                    Some(_) => Value::Undefined,
                                    None => ty.into(),
                                },
                            ),
                            ("name_string", id_name.map(<[u8]>::to_vec).into()),
                            (
                                "id",
                                match id_name {
                                    Some(_) => Value::Undefined,
                                    None => id.into(),
                                },
                            ),
                            ("language_string", lang_name.map(<[u8]>::to_vec).into()),
                            (
                                "language",
                                match lang_name {
                                    Some(_) => Value::Undefined,
                                    None => lang.into(),
                                },
                            ),
                        ]));
                        if resources.len() >= MAX_RESOURCES {
                            break 'outer;
                        }
                    }
                }
            }
        }

        out.extend([
            ("number_of_resources", resources.len().into()),
            (
                "resource_timestamp",
                root.header.time_date_stamp.get(LE).into(),
            ),
            (
                "resource_version",
                Value::object([
                    ("major", root.header.major_version.get(LE).into()),
                    ("minor", root.header.minor_version.get(LE).into()),
                ]),
            ),
            ("resources", Value::Array(resources)),
        ]);
    } else {
        let _r = out.insert("number_of_resources", Value::Integer(0));
    }

    out.extend([
        ("number_of_version_infos", infos.len().into()),
        (
            "version_info",
            Value::Dictionary(
                infos
                    .iter()
                    .map(|info| (info.key.clone(), info.value.clone().into()))
                    .collect(),
            ),
        ),
        (
            "version_info_list",
            Value::Array(
                infos
                    .into_iter()
                    .map(|info| {
                        Value::object([("key", info.key.into()), ("value", info.value.into())])
                    })
                    .collect(),
            ),
        ),
    ]);
}

fn resource_entry_name(
    entry: pe::ImageResourceDirectoryEntry,
    dir: ResourceDirectory,
) -> Option<&[u8]> {
    match entry.name_or_id() {
        ResourceNameOrId::Name(resource_name) => match resource_name.raw_data(dir) {
            Ok(name) if name.len() <= 1000 => Some(name),
            _ => None,
        },
        ResourceNameOrId::Id(_) => None,
    }
}

fn bool_to_int_value(b: bool) -> Value {
    Value::Integer(b.into())
}

impl Pe {
    fn calculate_checksum(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        let mem = ctx.mem.get_direct()?;

        // Compute offset of checksum in the file: this is replaced by 0 when computing the
        // checksum
        let dos_header = ImageDosHeader::parse(mem).ok()?;
        // 64 is the offset of the checksum in the optional header, and 24 is the offset of the
        // optional header in the nt headers: See
        // <https://docs.microsoft.com/en-us/windows/win32/debug/pe-format>
        let csum_offset = dos_header.nt_headers_offset() + 64 + 24;

        // Add data as LE u32 with overflow
        let mut csum: u64 = 0;
        let mut idx = 0;
        let mut cursor = mem;
        while cursor.len() >= 4 {
            if idx != csum_offset {
                let dword = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);

                csum += u64::from(dword);
                if csum > 0xFFFF_FFFF {
                    csum = (csum & 0xFFFF_FFFF) + (csum >> 32);
                }
            }

            cursor = &cursor[4..];
            idx += 4;
        }

        // pad with 0 for the last chunk
        let dword = match cursor {
            [a] => u32::from_le_bytes([*a, 0, 0, 0]),
            [a, b] => u32::from_le_bytes([*a, *b, 0, 0]),
            [a, b, c] => u32::from_le_bytes([*a, *b, *c, 0]),
            _ => 0,
        };
        csum += u64::from(dword);
        if csum > 0xFFFF_FFFF {
            csum = (csum & 0xFFFF_FFFF) + (csum >> 32);
        }

        // Fold the checksum to a u16
        let mut csum = (csum & 0xFFFF) + (csum >> 16);
        csum += csum >> 16;
        csum &= 0xFFFF;

        // Finally, add the filesize
        #[allow(clippy::cast_possible_truncation)]
        Some((csum as usize).wrapping_add(mem.len()).into())
    }

    fn section_index(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let arg = args.next()?;

        let data = ctx.module_data.get::<Self>()?;

        match arg {
            Value::Bytes(section_name) => data
                .sections
                .iter()
                .position(|sec| sec.name == section_name)
                .map(Into::into),
            Value::Integer(addr) => {
                let index = if ctx.process_memory {
                    data.sections.iter().position(|sec| {
                        addr >= sec.virtual_address && addr - sec.virtual_address < sec.virtual_size
                    })?
                } else {
                    data.sections.iter().position(|sec| {
                        addr >= sec.raw_data_offset
                            && addr - sec.raw_data_offset < sec.raw_data_size
                    })?
                };

                Some(index.into())
            }
            _ => None,
        }
    }

    fn exports(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let arg = args.next()?;

        let data = ctx.module_data.get::<Self>()?;

        let res = match arg {
            Value::Bytes(function_name) => data.exports.iter().any(|export| {
                export
                    .name
                    .as_ref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&function_name))
            }),
            Value::Integer(ordinal) => match usize::try_from(ordinal) {
                Ok(ord) => data.exports.iter().any(|export| export.ordinal == ord),
                Err(_) => false,
            },
            Value::Regex(function_name_regex) => data.exports.iter().any(|export| {
                export
                    .name
                    .as_ref()
                    .is_some_and(|name| function_name_regex.is_match(name))
            }),
            _ => return None,
        };

        Some(bool_to_int_value(res))
    }

    fn exports_index(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let arg = args.next()?;

        let data = ctx.module_data.get::<Self>()?;
        // XXX: yara does this, for some reason
        if data.exports.is_empty() {
            return None;
        }

        let res = match arg {
            Value::Bytes(function_name) => data.exports.iter().position(|export| {
                export
                    .name
                    .as_ref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&function_name))
            })?,
            Value::Integer(ordinal) => {
                let ordinal = usize::try_from(ordinal).ok()?;
                if ordinal == 0 || ordinal > data.exports.len() {
                    return None;
                }

                data.exports
                    .iter()
                    .position(|export| export.ordinal == ordinal)?
            }
            Value::Regex(function_name_regex) => data.exports.iter().position(|export| {
                export
                    .name
                    .as_ref()
                    .is_some_and(|name| function_name_regex.is_match(name))
            })?,
            _ => return None,
        };

        Some(res.into())
    }

    fn imports(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let first = args.next()?;
        let second = args.next();
        let third = args.next();

        let data = ctx.module_data.get::<Self>()?;

        match (first, second, third) {
            (Value::Bytes(dll_name), Some(Value::Bytes(function_name)), None) => {
                Some(bool_to_int_value(
                    data.find_function(&dll_name, &function_name, false)
                        .is_some(),
                ))
            }
            (Value::Bytes(dll_name), Some(Value::Integer(ordinal)), None) => {
                Some(bool_to_int_value(
                    data.find_function_ordinal(&dll_name, ordinal, false)
                        .is_some(),
                ))
            }
            (Value::Bytes(dll_name), None, None) => {
                Some(data.nb_functions(&dll_name, false).into())
            }
            (Value::Regex(dll_name), Some(Value::Regex(function_name)), None) => Some(
                data.nb_functions_regex(&dll_name, &function_name, false)
                    .into(),
            ),
            (
                Value::Integer(flags),
                Some(Value::Bytes(dll_name)),
                Some(Value::Bytes(function_name)),
            ) => {
                if flags & (ImportType::Standard as i64) != 0
                    && data
                        .find_function(&dll_name, &function_name, false)
                        .is_some()
                {
                    return Some(Value::Integer(1));
                }
                if flags & (ImportType::Delayed as i64) != 0
                    && data
                        .find_function(&dll_name, &function_name, true)
                        .is_some()
                {
                    return Some(Value::Integer(1));
                }

                Some(Value::Integer(0))
            }
            (
                Value::Integer(flags),
                Some(Value::Bytes(dll_name)),
                Some(Value::Integer(ordinal)),
            ) => {
                if flags & (ImportType::Standard as i64) != 0
                    && data
                        .find_function_ordinal(&dll_name, ordinal, false)
                        .is_some()
                {
                    return Some(Value::Integer(1));
                }
                if flags & (ImportType::Delayed as i64) != 0
                    && data
                        .find_function_ordinal(&dll_name, ordinal, true)
                        .is_some()
                {
                    return Some(Value::Integer(1));
                }

                Some(Value::Integer(0))
            }
            (Value::Integer(flags), Some(Value::Bytes(dll_name)), None) => {
                let mut res = 0;
                if flags & (ImportType::Standard as i64) != 0 {
                    res += data.nb_functions(&dll_name, false);
                }
                if flags & (ImportType::Delayed as i64) != 0 {
                    res += data.nb_functions(&dll_name, true);
                }
                Some(res.into())
            }
            (
                Value::Integer(flags),
                Some(Value::Regex(dll_name)),
                Some(Value::Regex(function_name)),
            ) => {
                let mut res = 0;
                if flags & (ImportType::Standard as i64) != 0 {
                    res += data.nb_functions_regex(&dll_name, &function_name, false);
                }
                if flags & (ImportType::Delayed as i64) != 0 {
                    res += data.nb_functions_regex(&dll_name, &function_name, true);
                }
                Some(res.into())
            }
            _ => None,
        }
    }

    fn import_rva(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let first = args.next()?;
        let second = args.next()?;

        let data = ctx.module_data.get::<Self>()?;

        match (first, second) {
            (Value::Bytes(dll_name), Value::Bytes(function_name)) => data
                .find_function(&dll_name, &function_name, false)
                .map(|v| v.rva.into()),
            (Value::Bytes(dll_name), Value::Integer(ordinal)) => data
                .find_function_ordinal(&dll_name, ordinal, false)
                .map(|v| v.rva.into()),
            _ => None,
        }
    }

    fn delayed_import_rva(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let first = args.next()?;
        let second = args.next()?;

        let data = ctx.module_data.get::<Self>()?;

        match (first, second) {
            (Value::Bytes(dll_name), Value::Bytes(function_name)) => data
                .find_function(&dll_name, &function_name, true)
                .map(|v| v.rva.into()),
            (Value::Bytes(dll_name), Value::Integer(ordinal)) => data
                .find_function_ordinal(&dll_name, ordinal, true)
                .map(|v| v.rva.into()),
            _ => None,
        }
    }

    fn locale(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let locale: i64 = args.next()?.try_into().ok()?;

        let data = ctx.module_data.get::<Self>()?;
        Some(bool_to_int_value(
            data.resource_languages
                .iter()
                .any(|language| i64::from(language & 0xFFFF) == locale),
        ))
    }

    fn language(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let lang: i64 = args.next()?.try_into().ok()?;

        let data = ctx.module_data.get::<Self>()?;
        Some(bool_to_int_value(
            data.resource_languages
                .iter()
                .any(|language| i64::from(language & 0xFF) == lang),
        ))
    }

    fn is_dll(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Self>()?;
        Some(data.is_dll.into())
    }

    fn is_32bit(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Self>()?;
        Some(bool_to_int_value(data.is_32bit))
    }

    fn is_64bit(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        let data = ctx.module_data.get::<Self>()?;
        Some(bool_to_int_value(!data.is_32bit))
    }

    fn rich_signature_version(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let first = args.next()?;
        let second = args.next();

        let data = ctx.module_data.get::<Self>()?;

        let res = match (first, second) {
            (Value::Integer(version), Some(Value::Integer(toolid))) => {
                data.count_rich_entries(Some(version), Some(toolid))
            }
            (Value::Integer(version), None) => data.count_rich_entries(Some(version), None),
            _ => return None,
        };

        Some(res.into())
    }

    fn rich_signature_toolid(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let first = args.next()?;
        let second = args.next();

        let data = ctx.module_data.get::<Self>()?;

        let res = match (first, second) {
            (Value::Integer(toolid), Some(Value::Integer(version))) => {
                data.count_rich_entries(Some(version), Some(toolid))
            }
            (Value::Integer(toolid), None) => data.count_rich_entries(None, Some(toolid)),
            _ => return None,
        };

        Some(res.into())
    }

    #[cfg(feature = "hash")]
    fn imphash(ctx: &mut EvalContext, _: Vec<Value>) -> Option<Value> {
        use md5::{Digest, Md5};

        let data = ctx.module_data.get::<Self>()?;

        let mut hasher = Md5::new();
        let mut first = true;
        for dll in &data.imports {
            let mut dll_name = dll.dll_name.to_ascii_lowercase();
            if dll_name.ends_with(b".ocx")
                || dll_name.ends_with(b".sys")
                || dll_name.ends_with(b".dll")
            {
                dll_name.truncate(dll_name.len() - 4);
            }

            for fun in &dll.functions {
                let fun_name = fun.name.to_ascii_lowercase();

                if !first {
                    hasher.update([b',']);
                }
                hasher.update(&dll_name);
                hasher.update([b'.']);
                hasher.update(fun_name);
                first = false;
            }
        }

        Some(Value::Bytes(super::hex_encode(hasher.finalize())))
    }

    fn rva_to_offset(ctx: &mut EvalContext, args: Vec<Value>) -> Option<Value> {
        let rva: i64 = args.into_iter().next()?.try_into().ok()?;
        let rva: u32 = rva.try_into().ok()?;

        // TODO: handle fragmented memory for this
        let mem = ctx.mem.get_direct()?;

        // We cannot save the SectionTable in the data, because it is a no-copy struct borrowing on
        // the scanned mem. Instead, we will reparse the mem and rebuild the SectionTable.
        // This isn't that costly, and this function shouldn't be used that much anyway.
        let dos_header = ImageDosHeader::parse(mem).ok()?;
        let mut offset = dos_header.nt_headers_offset().into();
        let section_table = match FileKind::parse(mem) {
            Ok(FileKind::Pe32) => {
                let (nt_headers, _) = ImageNtHeaders32::parse(mem, &mut offset).ok()?;
                utils::SectionTable::new(nt_headers, mem, offset)?
            }
            Ok(FileKind::Pe64) => {
                let (nt_headers, _) = ImageNtHeaders64::parse(mem, &mut offset).ok()?;
                utils::SectionTable::new(nt_headers, mem, offset)?
            }
            _ => return None,
        };

        utils::va_to_file_offset(mem, &section_table, rva).map(Into::into)
    }
}

#[derive(Default)]
pub struct Data {
    imports: Vec<DataImport>,
    delayed_imports: Vec<DataImport>,
    exports: Vec<DataExport>,
    sections: Vec<DataSection>,
    rich_entries: Vec<DataRichEntry>,
    resource_languages: Vec<u32>,
    is_32bit: bool,
    is_dll: u16,
    found_pe: bool,
}

struct DataImport {
    dll_name: Vec<u8>,
    functions: Vec<DataFunction>,
}

struct DataExport {
    name: Option<Vec<u8>>,
    ordinal: usize,
}

struct DataFunction {
    name: Vec<u8>,
    ordinal: Option<u16>,
    rva: u32,
}

struct DataSection {
    name: Vec<u8>,
    raw_data_offset: i64,
    raw_data_size: i64,
    virtual_address: i64,
    virtual_size: i64,
}

struct DataRichEntry {
    version: u16,
    toolid: u16,
    times: u32,
}

impl Data {
    fn get_imports(&self, delayed: bool) -> &[DataImport] {
        if delayed {
            &self.delayed_imports
        } else {
            &self.imports
        }
    }

    fn find_function(
        &self,
        dll_name: &[u8],
        fun_name: &[u8],
        delayed: bool,
    ) -> Option<&DataFunction> {
        self.get_imports(delayed)
            .iter()
            .find(|imp| imp.dll_name.eq_ignore_ascii_case(dll_name))
            .and_then(|imp| {
                imp.functions
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(fun_name))
            })
    }

    fn find_function_ordinal(
        &self,
        dll_name: &[u8],
        ordinal: i64,
        delayed: bool,
    ) -> Option<&DataFunction> {
        self.get_imports(delayed)
            .iter()
            .find(|imp| imp.dll_name.eq_ignore_ascii_case(dll_name))
            .and_then(|imp| {
                imp.functions.iter().find(|f| match f.ordinal {
                    Some(v) => i64::from(v) == ordinal,
                    None => false,
                })
            })
    }

    fn nb_functions(&self, dll_name: &[u8], delayed: bool) -> usize {
        self.get_imports(delayed)
            .iter()
            .find(|imp| imp.dll_name.eq_ignore_ascii_case(dll_name))
            .map_or(0, |imp| imp.functions.len())
    }

    fn nb_functions_regex(&self, dll_regex: &Regex, fun_regex: &Regex, delayed: bool) -> u32 {
        let mut nb_matches = 0;

        for imp in self.get_imports(delayed) {
            if !dll_regex.is_match(&imp.dll_name) {
                continue;
            }
            for fun in &imp.functions {
                if fun_regex.is_match(&fun.name) {
                    nb_matches += 1;
                }
            }
        }
        nb_matches
    }

    fn count_rich_entries(&self, version: Option<i64>, toolid: Option<i64>) -> u64 {
        let version = match version {
            Some(v) => match u16::try_from(v) {
                Ok(v) => Some(v),
                Err(_) => return 0,
            },
            None => None,
        };
        let toolid = match toolid {
            Some(v) => match u16::try_from(v) {
                Ok(v) => Some(v),
                Err(_) => return 0,
            },
            None => None,
        };

        self.rich_entries
            .iter()
            .map(|entry| {
                let mut matched = true;
                if let Some(v) = version {
                    matched = matched && v == entry.version;
                }
                if let Some(t) = toolid {
                    matched = matched && t == entry.toolid;
                }

                if matched {
                    u64::from(entry.times)
                } else {
                    0
                }
            })
            .sum()
    }
}
