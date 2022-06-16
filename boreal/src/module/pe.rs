use std::collections::HashMap;

use object::{
    coff::{SectionTable, SymbolTable},
    pe::{self, ImageImportDescriptor, ImageNtHeaders32, ImageNtHeaders64},
    read::pe::{
        DataDirectories, ExportTable, ImageNtHeaders, ImageOptionalHeader, ImageThunkData,
        ImportTable, PeFile, RichHeaderInfo,
    },
    FileKind, LittleEndian as LE, StringTable,
};

use super::{Module, ScanContext, StaticValue, Type, Value};

/// `pe` module. Allows inspecting PE inputs.
#[derive(Debug)]
pub struct Pe;

impl Module for Pe {
    fn get_name(&self) -> String {
        "pe".to_owned()
    }

    fn get_static_values(&self) -> HashMap<&'static str, StaticValue> {
        [
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
            ("IMPORT_DELAYED", StaticValue::Integer(1)),
            ("IMPORT_STANDARD", StaticValue::Integer(2)),
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
                    Self::exports,
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
        ]
        .into()
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
            // TODO: imphash
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
                        ])),
                    ),
                ])),
            ),
            (
                "delay_import_details",
                Type::array(Type::object([
                    ("library_name", Type::Bytes),
                    ("number_of_functions", Type::Integer),
                    (
                        "functions",
                        Type::array(Type::object([
                            ("name", Type::Bytes),
                            ("ordinal", Type::Integer),
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
            ("pdb_path", Type::Integer),
            // TODO: signatures
            ("number_of_signatures", Type::Integer),
            //
            (
                "rva_to_offset",
                Type::function(vec![vec![Type::Integer]], Type::Integer),
            ),
        ]
        .into()
    }

    fn get_dynamic_values(&self, ctx: &ScanContext) -> HashMap<&'static str, Value> {
        match FileKind::parse(ctx.mem) {
            Ok(FileKind::Pe32) => {
                if let Some(dict) = parse_file::<ImageNtHeaders32>(ctx.mem) {
                    return dict;
                }
            }
            Ok(FileKind::Pe64) => {
                if let Some(dict) = parse_file::<ImageNtHeaders64>(ctx.mem) {
                    return dict;
                }
            }
            _ => (),
        }

        [("is_pe", 0.into())].into()
    }
}

fn parse_file<Pe: ImageNtHeaders>(data: &[u8]) -> Option<HashMap<&'static str, Value>> {
    let file = PeFile::<Pe>::parse(data).ok()?;
    let nt_headers = file.nt_headers();
    let data_dirs = file.data_directories();

    let hdr = nt_headers.file_header();
    let opt_hdr = nt_headers.optional_header();

    let sections = file.section_table();
    let symbols = hdr.symbols(data).ok();

    let ep = opt_hdr.address_of_entry_point();

    let mut map: HashMap<_, _> = [
        ("is_pe", Some(Value::Integer(1))),
        // File header
        ("machine", Some(hdr.machine.get(LE).into())),
        (
            "number_of_sections",
            Some(hdr.number_of_sections.get(LE).into()),
        ),
        ("timestamp", Some(hdr.time_date_stamp.get(LE).into())),
        (
            "pointer_to_symbol_table",
            Some(hdr.pointer_to_symbol_table.get(LE).into()),
        ),
        (
            "number_of_symbols",
            Some(hdr.number_of_symbols.get(LE).into()),
        ),
        (
            "size_of_optional_header",
            Some(hdr.size_of_optional_header.get(LE).into()),
        ),
        ("characteristics", Some(hdr.characteristics.get(LE).into())),
        //
        ("entry_point", rva_to_offset(ep)),
        ("entry_point_raw", Some(ep.into())),
        ("image_base", opt_hdr.image_base().try_into().ok()),
        (
            "number_of_rva_and_sizes",
            Some(opt_hdr.number_of_rva_and_sizes().into()),
        ),
        // Optional header
        ("opthdr_magic", Some(opt_hdr.magic().into())),
        ("size_of_code", Some(opt_hdr.size_of_code().into())),
        (
            "size_of_initialized_data",
            Some(opt_hdr.size_of_initialized_data().into()),
        ),
        (
            "size_of_uninitialized_data",
            Some(opt_hdr.size_of_uninitialized_data().into()),
        ),
        ("base_of_code", Some(opt_hdr.base_of_code().into())),
        ("base_of_data", opt_hdr.base_of_data().map(Into::into)),
        (
            "section_alignment",
            Some(opt_hdr.section_alignment().into()),
        ),
        ("file_alignment", Some(opt_hdr.file_alignment().into())),
        (
            "linker_version",
            Some(Value::object([
                ("major", opt_hdr.major_linker_version().into()),
                ("minor", opt_hdr.minor_linker_version().into()),
            ])),
        ),
        (
            "os_version",
            Some(Value::object([
                ("major", opt_hdr.major_operating_system_version().into()),
                ("minor", opt_hdr.minor_operating_system_version().into()),
            ])),
        ),
        (
            "image_version",
            Some(Value::object([
                ("major", opt_hdr.major_image_version().into()),
                ("minor", opt_hdr.minor_image_version().into()),
            ])),
        ),
        (
            "subsystem_version",
            Some(Value::object([
                ("major", opt_hdr.major_subsystem_version().into()),
                ("minor", opt_hdr.minor_subsystem_version().into()),
            ])),
        ),
        (
            "win32_version_value",
            Some(opt_hdr.win32_version_value().into()),
        ),
        ("size_of_image", Some(opt_hdr.size_of_image().into())),
        ("size_of_headers", Some(opt_hdr.size_of_headers().into())),
        ("checksum", Some(opt_hdr.check_sum().into())),
        ("subsystem", Some(opt_hdr.subsystem().into())),
        (
            "dll_characteristics",
            Some(opt_hdr.dll_characteristics().into()),
        ),
        (
            "size_of_stack_reserve",
            opt_hdr.size_of_stack_reserve().try_into().ok(),
        ),
        (
            "size_of_stack_commit",
            opt_hdr.size_of_stack_commit().try_into().ok(),
        ),
        (
            "size_of_heap_reserve",
            opt_hdr.size_of_heap_reserve().try_into().ok(),
        ),
        (
            "size_of_heap_commit",
            opt_hdr.size_of_heap_commit().try_into().ok(),
        ),
        ("loader_flags", Some(opt_hdr.loader_flags().into())),
        //
        ("data_directories", Some(data_directories(data_dirs))),
        (
            "sections",
            Some(sections_to_value(
                &sections,
                symbols.as_ref().map(SymbolTable::strings),
            )),
        ),
        ("overlay", overlay(&sections, data)),
        (
            "rich_signature",
            file.rich_header_info().map(rich_signature),
        ),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.map(|v| (k, v)))
    .collect();

    add_imports::<Pe>(&data_dirs, data, &sections, &mut map);
    add_exports(&data_dirs, data, &sections, &mut map);

    // TODO: rich signature
    // TODO: delay import details
    //
    Some(map)
}

fn rich_signature(info: RichHeaderInfo) -> Value {
    Value::Object(
        [
            ("offset", info.offset.try_into().ok()),
            ("length", info.length.try_into().ok()),
            ("key", Some(info.xor_key.into())),
            // TODO: get raw & unmask data from object
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect(),
    )
}

fn add_imports<Pe: ImageNtHeaders>(
    data_dirs: &DataDirectories,
    data: &[u8],
    sections: &SectionTable,
    out: &mut HashMap<&'static str, Value>,
) {
    let table = match data_dirs.import_table(data, sections) {
        Ok(Some(table)) => table,
        _ => return,
    };
    let mut descriptors = match table.descriptors() {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut imports = Vec::new();
    let mut nb_functions_total = 0;

    // TODO: implement limits on nb imports & functions
    while let Ok(Some(import_desc)) = descriptors.next() {
        let library = match table.name(import_desc.name.get(LE)).ok() {
            Some(name) => name.to_vec(),
            None => continue,
        };
        let functions = import_functions::<Pe>(&table, import_desc);
        let nb_functions = functions.as_ref().map(Vec::len);
        if let Some(n) = nb_functions {
            nb_functions_total += n;
        }

        imports.push(Value::Object(
            [
                ("library_name", Some(library.into())),
                (
                    "number_of_functions",
                    nb_functions.and_then(|v| v.try_into().ok()),
                ),
                ("functions", functions.map(Value::Array)),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect(),
        ));
    }

    if let Ok(v) = nb_functions_total.try_into() {
        let _r = out.insert("number_of_imported_functions", v);
    }
    if let Ok(v) = imports.len().try_into() {
        let _r = out.insert("number_of_imports", v);
    }
    let _r = out.insert("import_details", Value::Array(imports));
}

fn import_functions<Pe: ImageNtHeaders>(
    import_table: &ImportTable,
    desc: &ImageImportDescriptor,
) -> Option<Vec<Value>> {
    let mut first_thunk = desc.original_first_thunk.get(LE);
    if first_thunk == 0 {
        first_thunk = desc.first_thunk.get(LE);
    }
    let mut thunks = import_table.thunks(first_thunk).ok()?;

    let mut functions = Vec::new();
    while let Ok(Some(thunk)) = thunks.next::<Pe>() {
        if let Some(v) = thunk_to_value::<Pe>(thunk, import_table) {
            functions.push(v);
        }
    }
    Some(functions)
}

fn thunk_to_value<Pe: ImageNtHeaders>(
    thunk: Pe::ImageThunkData,
    import_table: &ImportTable,
) -> Option<Value> {
    if thunk.is_ordinal() {
        // TODO: get name from ordinal
        Some(Value::object([("ordinal", thunk.ordinal().into())]))
    } else {
        let (_hint, name) = import_table.hint_name(thunk.address()).ok()?;
        Some(Value::object([("name", name.to_vec().into())]))
    }
}

fn add_exports(
    data_dirs: &DataDirectories,
    data: &[u8],
    sections: &SectionTable,
    out: &mut HashMap<&'static str, Value>,
) {
    // TODO: could call data_dirs.export_table, but need to retrieve export_va because it is not
    // exposed.
    let entry = match data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Some(entry) => entry,
        None => return,
    };
    let export_va = entry.virtual_address.get(LE);
    let export_data = match entry.data(data, sections) {
        Ok(d) => d,
        Err(_) => return,
    };
    let table = match ExportTable::parse(export_data, export_va) {
        Ok(table) => table,
        Err(_) => return,
    };

    let ordinal_base = table.ordinal_base() as usize;
    let addresses = table.addresses();
    let mut details: Vec<_> = addresses
        .iter()
        .enumerate()
        .map(|(i, address)| {
            let mut map = HashMap::with_capacity(4);

            if let Ok(v) = i64::try_from(ordinal_base + i) {
                let _r = map.insert("ordinal", v.into());
            }

            let address = address.get(LE);
            if let Ok(Some(forward)) = table.forward_string(address) {
                let _r = map.insert("forward_name", Value::bytes(forward));
            } else {
                let _r = map.insert("offset", address.saturating_sub(export_va).into());
            }

            Value::Object(map)
        })
        .collect();

    // Now, add names
    for (name_pointer, ordinal_index) in table.name_iter() {
        let name = match table.name_from_pointer(name_pointer) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(Value::Object(map)) = details.get_mut(ordinal_index as usize) {
            let _r = map.insert("name", Value::bytes(name));
        }
    }

    let dir = table.directory();
    let _r = out.insert("export_timestamp", dir.time_date_stamp.get(LE).into());
    let name_pointer = dir.name.get(LE);
    if let Ok(dll_name) = table.name_from_pointer(name_pointer) {
        let _r = out.insert("dll_name", dll_name.to_vec().into());
    }

    if let Ok(v) = details.len().try_into() {
        let _r = out.insert("number_of_exports", v);
    }
    let _r = out.insert("export_details", Value::Array(details));
}

fn data_directories(dirs: DataDirectories) -> Value {
    Value::Array(
        dirs.iter()
            .map(|dir| {
                Value::object([
                    ("virtual_address", dir.virtual_address.get(LE).into()),
                    ("size", dir.size.get(LE).into()),
                ])
            })
            .collect(),
    )
}

fn sections_to_value(sections: &SectionTable, strings: Option<StringTable>) -> Value {
    Value::Array(
        sections
            .iter()
            .map(|section| {
                let full_name = strings.and_then(|strings| section.name(strings).ok());
                // TODO: libyara does some rtrim of nul bytes here
                let name = section.raw_name().to_vec();

                Value::Object(
                    [
                        ("name", Some(name.into())),
                        ("full_name", full_name.map(|v| v.to_vec().into())),
                        (
                            "characteristics",
                            Some(section.characteristics.get(LE).into()),
                        ),
                        (
                            "virtual_address",
                            Some(section.virtual_address.get(LE).into()),
                        ),
                        ("virtual_size", Some(section.virtual_size.get(LE).into())),
                        (
                            "raw_data_size",
                            Some(section.size_of_raw_data.get(LE).into()),
                        ),
                        (
                            "raw_data_offset",
                            Some(section.pointer_to_raw_data.get(LE).into()),
                        ),
                        (
                            "pointer_to_relocations",
                            Some(section.pointer_to_relocations.get(LE).into()),
                        ),
                        (
                            "pointer_to_linenumbers",
                            Some(section.pointer_to_linenumbers.get(LE).into()),
                        ),
                        (
                            "number_of_relocations",
                            Some(section.number_of_relocations.get(LE).into()),
                        ),
                        (
                            "number_of_linenumbers",
                            Some(section.number_of_linenumbers.get(LE).into()),
                        ),
                    ]
                    .into_iter()
                    .filter_map(|(k, v)| v.map(|v| (k, v)))
                    .collect(),
                )
            })
            .collect(),
    )
}

fn overlay(sections: &SectionTable, data: &[u8]) -> Option<Value> {
    let offset = sections.max_section_file_offset();

    if offset < data.len() as u64 {
        Some(Value::Object(
            [
                ("offset", offset.try_into().ok()),
                ("size", (data.len() as u64 - offset).try_into().ok()),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect(),
        ))
    } else {
        None
    }
}

fn rva_to_offset(_ep: u32) -> Option<Value> {
    todo!()
}

impl Pe {
    fn calculate_checksum(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }

    fn section_index(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn exports(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn exports_index(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn imports(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let mut args = args.into_iter();
        let first = args.next()?;
        let second = args.next();
        let third = args.next();
        match (first, second, third) {
            (Value::Bytes(dll_name), Some(Value::Bytes(function_name)), None) => None,
            (Value::Bytes(dll_name), Some(Value::Integer(ordinal)), None) => None,
            (Value::Bytes(dll_name), None, None) => None,
            (Value::Regex(dll_name), Some(Value::Regex(function_name)), None) => None,
            (
                Value::Integer(flags),
                Some(Value::Bytes(dll_name)),
                Some(Value::Bytes(function_name)),
            ) => None,
            (
                Value::Integer(flags),
                Some(Value::Bytes(dll_name)),
                Some(Value::Integer(ordinal)),
            ) => None,
            (Value::Integer(flags), Some(Value::Bytes(dll_name)), None) => None,
            (
                Value::Integer(flags),
                Some(Value::Regex(dll_name)),
                Some(Value::Regex(function_name)),
            ) => None,
            _ => None,
        }
    }
    fn locale(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn language(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn is_dll(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn is_32bit(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
    fn is_64bit(_ctx: &ScanContext, args: Vec<Value>) -> Option<Value> {
        let _args = args.into_iter();
        todo!()
    }
}
