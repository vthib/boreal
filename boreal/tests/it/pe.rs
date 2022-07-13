use crate::utils::check_file;

// These are mostly coverage tests, ensuring all the fields are correctly set and have the same
// values as in libyara

#[test]
fn test_coverage_pe_tiny() {
    check_file(
        r#"import "pe"
rule test {
    condition:
pe.base_of_code == 4096 and
pe.base_of_data == 12288 and
pe.characteristics == 783 and
pe.checksum == 43228 and
(
    pe.data_directories[0].size == 0 and
    pe.data_directories[0].virtual_address == 0 and
    pe.data_directories[1].size == 1424 and
    pe.data_directories[1].virtual_address == 24576 and
    pe.data_directories[2].size == 0 and
    pe.data_directories[2].virtual_address == 0 and
    pe.data_directories[3].size == 0 and
    pe.data_directories[3].virtual_address == 0 and
    pe.data_directories[4].size == 0 and
    pe.data_directories[4].virtual_address == 0 and
    pe.data_directories[5].size == 0 and
    pe.data_directories[5].virtual_address == 0 and
    pe.data_directories[6].size == 0 and
    pe.data_directories[6].virtual_address == 0 and
    pe.data_directories[7].size == 0 and
    pe.data_directories[7].virtual_address == 0 and
    pe.data_directories[8].size == 0 and
    pe.data_directories[8].virtual_address == 0 and
    pe.data_directories[9].size == 24 and
    pe.data_directories[9].virtual_address == 32772 and
    pe.data_directories[10].size == 0 and
    pe.data_directories[10].virtual_address == 0 and
    pe.data_directories[11].size == 0 and
    pe.data_directories[11].virtual_address == 0 and
    pe.data_directories[12].size == 200 and
    pe.data_directories[12].virtual_address == 24836 and
    pe.data_directories[13].size == 0 and
    pe.data_directories[13].virtual_address == 0 and
    pe.data_directories[14].size == 0 and
    pe.data_directories[14].virtual_address == 0 and
    pe.data_directories[15].size == 0 and
    pe.data_directories[15].virtual_address == 0)
 and
pe.dll_characteristics == 0 and
pe.entry_point == 5344 and
pe.entry_point_raw == 5344 and
pe.file_alignment == 4096 and
pe.image_base == 4194304 and
pe.image_version.major == 1 and
pe.image_version.minor == 0 and
(
    (
        pe.import_details[0].functions[0].name == "DeleteCriticalSection" and
        pe.import_details[0].functions[1].name == "EnterCriticalSection" and
        pe.import_details[0].functions[2].name == "GetCurrentProcess" and
        pe.import_details[0].functions[3].name == "GetCurrentProcessId" and
        pe.import_details[0].functions[4].name == "GetCurrentThreadId" and
        pe.import_details[0].functions[5].name == "GetLastError" and
        pe.import_details[0].functions[6].name == "GetModuleHandleA" and
        pe.import_details[0].functions[7].name == "GetProcAddress" and
        pe.import_details[0].functions[8].name == "GetStartupInfoA" and
        pe.import_details[0].functions[9].name == "GetSystemTimeAsFileTime" and
        pe.import_details[0].functions[10].name == "GetTickCount" and
        pe.import_details[0].functions[11].name == "InitializeCriticalSection" and
        pe.import_details[0].functions[12].name == "LeaveCriticalSection" and
        pe.import_details[0].functions[13].name == "QueryPerformanceCounter" and
        pe.import_details[0].functions[14].name == "SetUnhandledExceptionFilter" and
        pe.import_details[0].functions[15].name == "Sleep" and
        pe.import_details[0].functions[16].name == "TerminateProcess" and
        pe.import_details[0].functions[17].name == "TlsGetValue" and
        pe.import_details[0].functions[18].name == "UnhandledExceptionFilter" and
        pe.import_details[0].functions[19].name == "VirtualProtect" and
        pe.import_details[0].functions[20].name == "VirtualQuery"    )
 and
    pe.import_details[0].library_name == "KERNEL32.dll" and
    pe.import_details[0].number_of_functions == 21 and
 // FIXME: see https://github.com/VirusTotal/yara/pull/1747
 //   (
 //       pe.import_details[1].functions[0].name == "__dllonexit" and
 //       pe.import_details[1].functions[1].name == "__getmainargs" and
 //       pe.import_details[1].functions[2].name == "__initenv" and
 //       pe.import_details[1].functions[3].name == "__lconv_init" and
 //       pe.import_details[1].functions[4].name == "__set_app_type" and
 //       pe.import_details[1].functions[5].name == "__setusermatherr" and
 //       pe.import_details[1].functions[6].name == "_acmdln" and
 //       pe.import_details[1].functions[7].name == "_amsg_exit" and
 //       pe.import_details[1].functions[8].name == "_cexit" and
 //       pe.import_details[1].functions[9].name == "_fmode" and
 //       pe.import_details[1].functions[10].name == "_initterm" and
 //       pe.import_details[1].functions[11].name == "_iob" and
 //       pe.import_details[1].functions[12].name == "_lock" and
 //       pe.import_details[1].functions[13].name == "_onexit" and
 //       pe.import_details[1].functions[14].name == "calloc" and
 //       pe.import_details[1].functions[15].name == "exit" and
 //       pe.import_details[1].functions[16].name == "fprintf" and
 //       pe.import_details[1].functions[17].name == "free" and
 //       pe.import_details[1].functions[18].name == "fwrite" and
 //       pe.import_details[1].functions[19].name == "malloc" and
 //       pe.import_details[1].functions[20].name == "memcpy" and
 //       pe.import_details[1].functions[21].name == "signal" and
 //       pe.import_details[1].functions[22].name == "strlen" and
 //       pe.import_details[1].functions[23].name == "strncmp" and
 //       pe.import_details[1].functions[24].name == "_unlock" and
 //       pe.import_details[1].functions[25].name == "abort" and
 //       pe.import_details[1].functions[26].name == "vfprintf"    )
 //and
 //   pe.import_details[1].library_name == "msvcrt.dll" and
 //   pe.import_details[1].number_of_functions == 27)
 true)
 and
pe.is_pe == 1 and
pe.linker_version.major == 2 and
pe.linker_version.minor == 26 and
pe.loader_flags == 0 and
pe.machine == 332 and
pe.number_of_imported_functions == 48 and
pe.number_of_imports == 2 and
pe.number_of_rva_and_sizes == 16 and
pe.number_of_sections == 7 and
pe.number_of_symbols == 0 and
pe.opthdr_magic == 267 and
pe.os_version.major == 4 and
pe.os_version.minor == 0 and
pe.overlay.offset == 0 and
pe.overlay.size == 0 and
pe.pointer_to_symbol_table == 0 and
pe.section_alignment == 4096 and
(
    pe.sections[0].characteristics == 1615855712 and
    pe.sections[0].full_name == ".text" and
    pe.sections[0].name == ".text" and
    pe.sections[0].number_of_line_numbers == 0 and
    pe.sections[0].number_of_relocations == 0 and
    pe.sections[0].pointer_to_line_numbers == 0 and
    pe.sections[0].pointer_to_relocations == 0 and
    pe.sections[0].raw_data_offset == 4096 and
    pe.sections[0].raw_data_size == 8192 and
    pe.sections[0].virtual_address == 4096 and
    pe.sections[0].virtual_size == 6004 and
    pe.sections[1].characteristics == 3224371264 and
    pe.sections[1].full_name == ".data" and
    pe.sections[1].name == ".data" and
    pe.sections[1].number_of_line_numbers == 0 and
    pe.sections[1].number_of_relocations == 0 and
    pe.sections[1].pointer_to_line_numbers == 0 and
    pe.sections[1].pointer_to_relocations == 0 and
    pe.sections[1].raw_data_offset == 12288 and
    pe.sections[1].raw_data_size == 4096 and
    pe.sections[1].virtual_address == 12288 and
    pe.sections[1].virtual_size == 48 and
    pe.sections[2].characteristics == 1076887616 and
    pe.sections[2].full_name == ".rdata" and
    pe.sections[2].name == ".rdata" and
    pe.sections[2].number_of_line_numbers == 0 and
    pe.sections[2].number_of_relocations == 0 and
    pe.sections[2].pointer_to_line_numbers == 0 and
    pe.sections[2].pointer_to_relocations == 0 and
    pe.sections[2].raw_data_offset == 16384 and
    pe.sections[2].raw_data_size == 4096 and
    pe.sections[2].virtual_address == 16384 and
    pe.sections[2].virtual_size == 1360 and
    pe.sections[3].characteristics == 3227517056 and
    pe.sections[3].full_name == ".bss" and
    pe.sections[3].name == ".bss" and
    pe.sections[3].number_of_line_numbers == 0 and
    pe.sections[3].number_of_relocations == 0 and
    pe.sections[3].pointer_to_line_numbers == 0 and
    pe.sections[3].pointer_to_relocations == 0 and
    pe.sections[3].raw_data_offset == 0 and
    pe.sections[3].raw_data_size == 0 and
    pe.sections[3].virtual_address == 20480 and
    pe.sections[3].virtual_size == 1024 and
    pe.sections[4].characteristics == 3224371264 and
    pe.sections[4].full_name == ".idata" and
    pe.sections[4].name == ".idata" and
    pe.sections[4].number_of_line_numbers == 0 and
    pe.sections[4].number_of_relocations == 0 and
    pe.sections[4].pointer_to_line_numbers == 0 and
    pe.sections[4].pointer_to_relocations == 0 and
    pe.sections[4].raw_data_offset == 20480 and
    pe.sections[4].raw_data_size == 4096 and
    pe.sections[4].virtual_address == 24576 and
    pe.sections[4].virtual_size == 1424 and
    pe.sections[5].characteristics == 3224371264 and
    pe.sections[5].full_name == ".CRT" and
    pe.sections[5].name == ".CRT" and
    pe.sections[5].number_of_line_numbers == 0 and
    pe.sections[5].number_of_relocations == 0 and
    pe.sections[5].pointer_to_line_numbers == 0 and
    pe.sections[5].pointer_to_relocations == 0 and
    pe.sections[5].raw_data_offset == 24576 and
    pe.sections[5].raw_data_size == 4096 and
    pe.sections[5].virtual_address == 28672 and
    pe.sections[5].virtual_size == 52 and
    pe.sections[6].characteristics == 3224371264 and
    pe.sections[6].full_name == ".tls" and
    pe.sections[6].name == ".tls" and
    pe.sections[6].number_of_line_numbers == 0 and
    pe.sections[6].number_of_relocations == 0 and
    pe.sections[6].pointer_to_line_numbers == 0 and
    pe.sections[6].pointer_to_relocations == 0 and
    pe.sections[6].raw_data_offset == 28672 and
    pe.sections[6].raw_data_size == 4096 and
    pe.sections[6].virtual_address == 32768 and
    pe.sections[6].virtual_size == 32)
 and
pe.size_of_code == 8192 and
pe.size_of_headers == 4096 and
pe.size_of_heap_commit == 4096 and
pe.size_of_heap_reserve == 1048576 and
pe.size_of_image == 36864 and
pe.size_of_initialized_data == 28672 and
pe.size_of_optional_header == 224 and
pe.size_of_stack_commit == 4096 and
pe.size_of_stack_reserve == 2097152 and
pe.size_of_uninitialized_data == 4096 and
pe.subsystem == 3 and
pe.subsystem_version.major == 4 and
pe.subsystem_version.minor == 0 and
pe.timestamp == 1459377848 and
pe.win32_version_value == 0
}"#,
        "assets/libyara/data/tiny",
        true,
    );
}

#[test]
fn test_coverage_pe_ord_and_delay() {
    check_file(
        r#"import "pe"
rule test {
    condition:
pe.base_of_code == 4096 and
pe.base_of_data == 53248 and
pe.characteristics == 258 and
pe.checksum == 0 and
(
    pe.data_directories[0].size == 0 and
    pe.data_directories[0].virtual_address == 0 and
    pe.data_directories[1].size == 60 and
    pe.data_directories[1].virtual_address == 74940 and
    pe.data_directories[2].size == 0 and
    pe.data_directories[2].virtual_address == 0 and
    pe.data_directories[3].size == 0 and
    pe.data_directories[3].virtual_address == 0 and
    pe.data_directories[4].size == 0 and
    pe.data_directories[4].virtual_address == 0 and
    pe.data_directories[5].size == 3708 and
    pe.data_directories[5].virtual_address == 86016 and
    pe.data_directories[6].size == 28 and
    pe.data_directories[6].virtual_address == 73036 and
    pe.data_directories[7].size == 0 and
    pe.data_directories[7].virtual_address == 0 and
    pe.data_directories[8].size == 0 and
    pe.data_directories[8].virtual_address == 0 and
    pe.data_directories[9].size == 0 and
    pe.data_directories[9].virtual_address == 0 and
    pe.data_directories[10].size == 64 and
    pe.data_directories[10].virtual_address == 53736 and
    pe.data_directories[11].size == 0 and
    pe.data_directories[11].virtual_address == 0 and
    pe.data_directories[12].size == 292 and
    pe.data_directories[12].virtual_address == 53248 and
    pe.data_directories[13].size == 64 and
    pe.data_directories[13].virtual_address == 74852 and
    pe.data_directories[14].size == 0 and
    pe.data_directories[14].virtual_address == 0 and
    pe.data_directories[15].size == 0 and
    pe.data_directories[15].virtual_address == 0)
 and
// TODO: yara used wrong namings for those, fix not released yet:
// <https://github.com/VirusTotal/yara/commit/3bb53558367f689d31975aea5f8b563439548d17>
// (
//     (
//         pe.delayed_import_details[0].functions[0].name == "VariantInit" and
//         pe.delayed_import_details[0].functions[0].ordinal == 8 and
//         pe.delayed_import_details[0].functions[1].name == "SafeArrayCreateVector" and
//         pe.delayed_import_details[0].functions[1].ordinal == 411    )
//  and
//     pe.delayed_import_details[0].library_name == "OLEAUT32.dll" and
//     pe.delayed_import_details[0].number_of_functions == 2)
//  and
pe.dll_characteristics == 33088 and
pe.entry_point == 3086 and
pe.entry_point_raw == 6158 and
pe.file_alignment == 512 and
pe.image_base == 4194304 and
pe.image_version.major == 0 and
pe.image_version.minor == 0 and
(
    (
        pe.import_details[0].functions[0].name == "WSAStartup" and
        pe.import_details[0].functions[0].ordinal == 115 and
        pe.import_details[0].functions[1].name == "gethostbyname" and
        pe.import_details[0].functions[1].ordinal == 52    )
 and
    pe.import_details[0].library_name == "WS2_32.dll" and
    pe.import_details[0].number_of_functions == 2 and
 // FIXME: see https://github.com/VirusTotal/yara/pull/1747
 //   (
 //       pe.import_details[1].functions[0].name == "GetCommandLineA" and
 //       pe.import_details[1].functions[1].name == "WriteConsoleW" and
 //       pe.import_details[1].functions[2].name == "CloseHandle" and
 //       pe.import_details[1].functions[3].name == "RaiseException" and
 //       pe.import_details[1].functions[4].name == "GetLastError" and
 //       pe.import_details[1].functions[5].name == "GetSystemInfo" and
 //       pe.import_details[1].functions[6].name == "VirtualProtect" and
 //       pe.import_details[1].functions[7].name == "VirtualQuery" and
 //       pe.import_details[1].functions[8].name == "FreeLibrary" and
 //       pe.import_details[1].functions[9].name == "GetModuleHandleW" and
 //       pe.import_details[1].functions[10].name == "GetProcAddress" and
 //       pe.import_details[1].functions[11].name == "LoadLibraryExA" and
 //       pe.import_details[1].functions[12].name == "UnhandledExceptionFilter" and
 //       pe.import_details[1].functions[13].name == "SetUnhandledExceptionFilter" and
 //       pe.import_details[1].functions[14].name == "GetCurrentProcess" and
 //       pe.import_details[1].functions[15].name == "TerminateProcess" and
 //       pe.import_details[1].functions[16].name == "IsProcessorFeaturePresent" and
 //       pe.import_details[1].functions[17].name == "QueryPerformanceCounter" and
 //       pe.import_details[1].functions[18].name == "GetCurrentProcessId" and
 //       pe.import_details[1].functions[19].name == "GetCurrentThreadId" and
 //       pe.import_details[1].functions[20].name == "GetSystemTimeAsFileTime" and
 //       pe.import_details[1].functions[21].name == "InitializeSListHead" and
 //       pe.import_details[1].functions[22].name == "IsDebuggerPresent" and
 //       pe.import_details[1].functions[23].name == "GetStartupInfoW" and
 //       pe.import_details[1].functions[24].name == "CreateFileW" and
 //       pe.import_details[1].functions[25].name == "RtlUnwind" and
 //       pe.import_details[1].functions[26].name == "SetLastError" and
 //       pe.import_details[1].functions[27].name == "EnterCriticalSection" and
 //       pe.import_details[1].functions[28].name == "LeaveCriticalSection" and
 //       pe.import_details[1].functions[29].name == "DeleteCriticalSection" and
 //       pe.import_details[1].functions[30].name == "InitializeCriticalSectionAndSpinCount" and
 //       pe.import_details[1].functions[31].name == "TlsAlloc" and
 //       pe.import_details[1].functions[32].name == "TlsGetValue" and
 //       pe.import_details[1].functions[33].name == "TlsSetValue" and
 //       pe.import_details[1].functions[34].name == "TlsFree" and
 //       pe.import_details[1].functions[35].name == "LoadLibraryExW" and
 //       pe.import_details[1].functions[36].name == "GetStdHandle" and
 //       pe.import_details[1].functions[37].name == "WriteFile" and
 //       pe.import_details[1].functions[38].name == "GetModuleFileNameW" and
 //       pe.import_details[1].functions[39].name == "ExitProcess" and
 //       pe.import_details[1].functions[40].name == "GetModuleHandleExW" and
 //       pe.import_details[1].functions[41].name == "DecodePointer" and
 //       pe.import_details[1].functions[42].name == "GetCommandLineW" and
 //       pe.import_details[1].functions[43].name == "HeapAlloc" and
 //       pe.import_details[1].functions[44].name == "HeapFree" and
 //       pe.import_details[1].functions[45].name == "FindClose" and
 //       pe.import_details[1].functions[46].name == "FindFirstFileExW" and
 //       pe.import_details[1].functions[47].name == "FindNextFileW" and
 //       pe.import_details[1].functions[48].name == "IsValidCodePage" and
 //       pe.import_details[1].functions[49].name == "GetACP" and
 //       pe.import_details[1].functions[50].name == "GetOEMCP" and
 //       pe.import_details[1].functions[51].name == "GetCPInfo" and
 //       pe.import_details[1].functions[52].name == "MultiByteToWideChar" and
 //       pe.import_details[1].functions[53].name == "WideCharToMultiByte" and
 //       pe.import_details[1].functions[54].name == "GetEnvironmentStringsW" and
 //       pe.import_details[1].functions[55].name == "FreeEnvironmentStringsW" and
 //       pe.import_details[1].functions[56].name == "SetEnvironmentVariableW" and
 //       pe.import_details[1].functions[57].name == "SetStdHandle" and
 //       pe.import_details[1].functions[58].name == "GetFileType" and
 //       pe.import_details[1].functions[59].name == "GetStringTypeW" and
 //       pe.import_details[1].functions[60].name == "CompareStringW" and
 //       pe.import_details[1].functions[61].name == "LCMapStringW" and
 //       pe.import_details[1].functions[62].name == "GetProcessHeap" and
 //       pe.import_details[1].functions[63].name == "HeapSize" and
 //       pe.import_details[1].functions[64].name == "HeapReAlloc" and
 //       pe.import_details[1].functions[65].name == "FlushFileBuffers" and
 //       pe.import_details[1].functions[66].name == "GetConsoleOutputCP" and
 //       pe.import_details[1].functions[67].name == "GetConsoleMode" and
 //       pe.import_details[1].functions[68].name == "SetFilePointerEx"    )
 //and
 //   pe.import_details[1].library_name == "KERNEL32.dll" and
 //   pe.import_details[1].number_of_functions == 69)
 true)
 and
pe.is_pe == 1 and
pe.linker_version.major == 14 and
pe.linker_version.minor == 29 and
pe.loader_flags == 0 and
pe.machine == 332 and
pe.number_of_delayed_imported_functions == 2 and
pe.number_of_delayed_imports == 1 and
pe.number_of_imported_functions == 71 and
pe.number_of_imports == 2 and
pe.number_of_rva_and_sizes == 16 and
pe.number_of_sections == 4 and
pe.number_of_symbols == 0 and
pe.opthdr_magic == 267 and
pe.os_version.major == 6 and
pe.os_version.minor == 0 and
pe.overlay.offset == 0 and
pe.overlay.size == 0 and
pe.pointer_to_symbol_table == 0 and
pe.rich_signature.clear_data == "\x44\x61\x6e\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x6b\x03\x01\x0a\x00\x00\x00\x14\x6b\x05\x01\x8c\x00\x00\x00\x14\x6b\x04\x01\x12\x00\x00\x00\x52\x75\x04\x01\x11\x00\x00\x00\x52\x75\x03\x01\x11\x00\x00\x00\x52\x75\x05\x01\x28\x00\x00\x00\x14\x6b\x01\x01\x05\x00\x00\x00\x00\x00\x01\x00\x58\x00\x00\x00\xc1\x75\x05\x01\x01\x00\x00\x00\xc1\x75\x02\x01\x01\x00\x00\x00" and
pe.rich_signature.key == 2549569753 and
pe.rich_signature.length == 96 and
pe.rich_signature.offset == 128 and
pe.rich_signature.raw_data == "\x9d\x39\x99\xc4\xd9\x58\xf7\x97\xd9\x58\xf7\x97\xd9\x58\xf7\x97\xcd\x33\xf4\x96\xd3\x58\xf7\x97\xcd\x33\xf2\x96\x55\x58\xf7\x97\xcd\x33\xf3\x96\xcb\x58\xf7\x97\x8b\x2d\xf3\x96\xc8\x58\xf7\x97\x8b\x2d\xf4\x96\xc8\x58\xf7\x97\x8b\x2d\xf2\x96\xf1\x58\xf7\x97\xcd\x33\xf6\x96\xdc\x58\xf7\x97\xd9\x58\xf6\x97\x81\x58\xf7\x97\x18\x2d\xf2\x96\xd8\x58\xf7\x97\x18\x2d\xf5\x96\xd8\x58\xf7\x97" and
true
 and
true
 and
pe.section_alignment == 4096 and
(
    pe.sections[0].characteristics == 1610612768 and
    pe.sections[0].full_name == ".text" and
    pe.sections[0].name == ".text" and
    pe.sections[0].number_of_line_numbers == 0 and
    pe.sections[0].number_of_relocations == 0 and
    pe.sections[0].pointer_to_line_numbers == 0 and
    pe.sections[0].pointer_to_relocations == 0 and
    pe.sections[0].raw_data_offset == 1024 and
    pe.sections[0].raw_data_size == 47104 and
    pe.sections[0].virtual_address == 4096 and
    pe.sections[0].virtual_size == 46888 and
    pe.sections[1].characteristics == 1073741888 and
    pe.sections[1].full_name == ".rdata" and
    pe.sections[1].name == ".rdata" and
    pe.sections[1].number_of_line_numbers == 0 and
    pe.sections[1].number_of_relocations == 0 and
    pe.sections[1].pointer_to_line_numbers == 0 and
    pe.sections[1].pointer_to_relocations == 0 and
    pe.sections[1].raw_data_offset == 48128 and
    pe.sections[1].raw_data_size == 23552 and
    pe.sections[1].virtual_address == 53248 and
    pe.sections[1].virtual_size == 23348 and
    pe.sections[2].characteristics == 3221225536 and
    pe.sections[2].full_name == ".data" and
    pe.sections[2].name == ".data" and
    pe.sections[2].number_of_line_numbers == 0 and
    pe.sections[2].number_of_relocations == 0 and
    pe.sections[2].pointer_to_line_numbers == 0 and
    pe.sections[2].pointer_to_relocations == 0 and
    pe.sections[2].raw_data_offset == 71680 and
    pe.sections[2].raw_data_size == 2560 and
    pe.sections[2].virtual_address == 77824 and
    pe.sections[2].virtual_size == 4828 and
    pe.sections[3].characteristics == 1107296320 and
    pe.sections[3].full_name == ".reloc" and
    pe.sections[3].name == ".reloc" and
    pe.sections[3].number_of_line_numbers == 0 and
    pe.sections[3].number_of_relocations == 0 and
    pe.sections[3].pointer_to_line_numbers == 0 and
    pe.sections[3].pointer_to_relocations == 0 and
    pe.sections[3].raw_data_offset == 74240 and
    pe.sections[3].raw_data_size == 4096 and
    pe.sections[3].virtual_address == 86016 and
    pe.sections[3].virtual_size == 3708)
 and
pe.size_of_code == 47104 and
pe.size_of_headers == 1024 and
pe.size_of_heap_commit == 4096 and
pe.size_of_heap_reserve == 1048576 and
pe.size_of_image == 90112 and
pe.size_of_initialized_data == 32768 and
pe.size_of_optional_header == 224 and
pe.size_of_stack_commit == 4096 and
pe.size_of_stack_reserve == 1048576 and
pe.size_of_uninitialized_data == 0 and
pe.subsystem == 3 and
pe.subsystem_version.major == 6 and
pe.subsystem_version.minor == 0 and
pe.timestamp == 1657579306 and
pe.win32_version_value == 0
}"#,
        "assets/pe/ord_and_delay.exe",
        true,
    );
}
