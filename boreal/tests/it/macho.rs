use crate::{
    libyara_compat::util::{MACHO_X86_64_DYLIB_FILE, MACHO_X86_FILE},
    utils::{check, check_file},
};

// These are mostly coverage tests, ensuring all the fields are correctly set and have the same
// values as in libyara

#[test]
fn test_coverage_macho_x86() {
    check(
        r#"import "macho"
rule test {
    condition:
        macho.magic == 0xfeedface and
        macho.cputype == 7 and
        macho.cpusubtype == 3 and
        macho.filetype == 2 and
        macho.ncmds == 16 and
        macho.sizeofcmds == 1060 and
        macho.flags == 0x1200085 and
        macho.entry_point == 0xe90 and
        macho.stack_size == 0 and
        macho.number_of_segments == 4 and
        (
            macho.segments[0].segname == "__PAGEZERO" and
            macho.segments[0].vmaddr == 0 and
            macho.segments[0].vmsize == 4096 and
            macho.segments[0].fileoff == 0 and
            macho.segments[0].fsize == 0 and
            macho.segments[0].maxprot == 0 and
            macho.segments[0].initprot == 0 and
            macho.segments[0].nsects == 0 and
            macho.segments[0].flags == 0 and
            not defined macho.segments[0].sections[0].size
        ) and
        (
            macho.segments[1].segname == "__TEXT" and
            macho.segments[1].vmaddr == 4096 and
            macho.segments[1].vmsize == 4096 and
            macho.segments[1].fileoff == 0 and
            macho.segments[1].fsize == 4096 and
            macho.segments[1].maxprot == 7 and
            macho.segments[1].initprot == 5 and
            macho.segments[1].nsects == 5 and
            macho.segments[1].flags == 0 and
            (
                macho.segments[1].sections[0].sectname == "__text" and
                macho.segments[1].sections[0].segname == "__TEXT" and
                macho.segments[1].sections[0].addr == 7824 and
                macho.segments[1].sections[0].size == 166 and
                macho.segments[1].sections[0].offset == 3728 and
                macho.segments[1].sections[0].align == 4 and
                macho.segments[1].sections[0].reloff == 0 and
                macho.segments[1].sections[0].nreloc == 0 and
                macho.segments[1].sections[0].flags == 0x80000400 and
                macho.segments[1].sections[0].reserved1 == 0 and
                macho.segments[1].sections[0].reserved2 == 0 and
                not defined macho.segments[1].sections[0].reserved3
            ) and
            (
                macho.segments[1].sections[1].sectname == "__symbol_stub" and
                macho.segments[1].sections[1].segname == "__TEXT" and
                macho.segments[1].sections[1].addr == 7990 and
                macho.segments[1].sections[1].size == 12 and
                macho.segments[1].sections[1].offset == 3894 and
                macho.segments[1].sections[1].align == 1 and
                macho.segments[1].sections[1].reloff == 0 and
                macho.segments[1].sections[1].nreloc == 0 and
                macho.segments[1].sections[1].flags == 0x80000508 and
                macho.segments[1].sections[1].reserved1 == 0 and
                macho.segments[1].sections[1].reserved2 == 6 and
                not defined macho.segments[1].sections[1].reserved3
            ) and
            (
                macho.segments[1].sections[2].sectname == "__stub_helper" and
                macho.segments[1].sections[2].segname == "__TEXT" and
                macho.segments[1].sections[2].addr == 8004 and
                macho.segments[1].sections[2].size == 32 and
                macho.segments[1].sections[2].offset == 3908 and
                macho.segments[1].sections[2].align == 2 and
                macho.segments[1].sections[2].reloff == 0 and
                macho.segments[1].sections[2].nreloc == 0 and
                macho.segments[1].sections[2].flags == 0x80000500 and
                macho.segments[1].sections[2].reserved1 == 0 and
                macho.segments[1].sections[2].reserved2 == 0 and
                not defined macho.segments[1].sections[2].reserved3
            ) and
            (
                macho.segments[1].sections[3].sectname == "__cstring" and
                macho.segments[1].sections[3].segname == "__TEXT" and
                macho.segments[1].sections[3].addr == 8036 and
                macho.segments[1].sections[3].size == 69 and
                macho.segments[1].sections[3].offset == 3940 and
                macho.segments[1].sections[3].align == 0 and
                macho.segments[1].sections[3].reloff == 0 and
                macho.segments[1].sections[3].nreloc == 0 and
                macho.segments[1].sections[3].flags == 2 and
                macho.segments[1].sections[3].reserved1 == 0 and
                macho.segments[1].sections[3].reserved2 == 0 and
                not defined macho.segments[1].sections[3].reserved3
            ) and
            (
                macho.segments[1].sections[4].sectname == "__unwind_info" and
                macho.segments[1].sections[4].segname == "__TEXT" and
                macho.segments[1].sections[4].addr == 8108 and
                macho.segments[1].sections[4].size == 72 and
                macho.segments[1].sections[4].offset == 4012 and
                macho.segments[1].sections[4].align == 2 and
                macho.segments[1].sections[4].reloff == 0 and
                macho.segments[1].sections[4].nreloc == 0 and
                macho.segments[1].sections[4].flags == 0 and
                macho.segments[1].sections[4].reserved1 == 0 and
                macho.segments[1].sections[4].reserved2 == 0 and
                not defined macho.segments[1].sections[4].reserved3
            ) and
            not defined macho.segments[1].sections[5].size
        ) and
        (
            macho.segments[2].segname == "__DATA" and
            macho.segments[2].vmaddr == 8192 and
            macho.segments[2].vmsize == 4096 and
            macho.segments[2].fileoff == 4096 and
            macho.segments[2].fsize == 4096 and
            macho.segments[2].maxprot == 7 and
            macho.segments[2].initprot == 3 and
            macho.segments[2].nsects == 2 and
            macho.segments[2].flags == 0 and
            (
                macho.segments[2].sections[0].sectname == "__nl_symbol_ptr" and
                macho.segments[2].sections[0].segname == "__DATA" and
                macho.segments[2].sections[0].addr == 8192 and
                macho.segments[2].sections[0].size == 8 and
                macho.segments[2].sections[0].offset == 4096 and
                macho.segments[2].sections[0].align == 2 and
                macho.segments[2].sections[0].reloff == 0 and
                macho.segments[2].sections[0].nreloc == 0 and
                macho.segments[2].sections[0].flags == 6 and
                macho.segments[2].sections[0].reserved1 == 2 and
                macho.segments[2].sections[0].reserved2 == 0 and
                not defined macho.segments[2].sections[0].reserved3
            ) and
            (
                macho.segments[2].sections[1].sectname == "__la_symbol_ptr" and
                macho.segments[2].sections[1].segname == "__DATA" and
                macho.segments[2].sections[1].addr == 8200 and
                macho.segments[2].sections[1].size == 8 and
                macho.segments[2].sections[1].offset == 4104 and
                macho.segments[2].sections[1].align == 2 and
                macho.segments[2].sections[1].reloff == 0 and
                macho.segments[2].sections[1].nreloc == 0 and
                macho.segments[2].sections[1].flags == 7 and
                macho.segments[2].sections[1].reserved1 == 4 and
                macho.segments[2].sections[1].reserved2 == 0 and
                not defined macho.segments[2].sections[1].reserved3
            ) and
            not defined macho.segments[2].sections[2].size
        ) and
        (
            macho.segments[3].segname == "__LINKEDIT" and
            macho.segments[3].vmaddr == 12288 and
            macho.segments[3].vmsize == 4096 and
            macho.segments[3].fileoff == 8192 and
            macho.segments[3].fsize == 280 and
            macho.segments[3].maxprot == 7 and
            macho.segments[3].initprot == 1 and
            macho.segments[3].nsects == 0 and
            macho.segments[3].flags == 0 and
            not defined macho.segments[3].sections[0].size
        ) and

        not defined macho.reserved and
        not defined macho.fat_magic and
        not defined macho.nfat_arch and
        not defined macho.fat_arch[0].cputype and
        not defined macho.file[0].magic
}"#,
        MACHO_X86_FILE,
        true,
    );
}

#[test]
fn test_coverage_macho_x64_dylib() {
    check(
        r#"import "macho"
rule test {
    condition:
        macho.magic == 0xfeedfacf and
        macho.cputype == 0x1000007 and
        macho.cpusubtype == 3 and
        macho.filetype == 6 and
        macho.ncmds == 13 and
        macho.sizeofcmds == 744 and
        macho.flags == 0x100085 and
        macho.number_of_segments == 2 and
        macho.reserved == 1 and
        not defined macho.entry_point and
        not defined macho.stack_size and
        (
            macho.segments[0].segname == "__TEXT" and
            macho.segments[0].vmaddr == 0 and
            macho.segments[0].vmsize == 4096 and
            macho.segments[0].fileoff == 0 and
            macho.segments[0].fsize == 4096 and
            macho.segments[0].maxprot == 7 and
            macho.segments[0].initprot == 5 and
            macho.segments[0].nsects == 3 and
            macho.segments[0].flags == 0 and
            (
                macho.segments[0].sections[0].sectname == "__text" and
                macho.segments[0].sections[0].segname == "__TEXT" and
                macho.segments[0].sections[0].addr == 3920 and
                macho.segments[0].sections[0].size == 72 and
                macho.segments[0].sections[0].offset == 3920 and
                macho.segments[0].sections[0].align == 4 and
                macho.segments[0].sections[0].reloff == 0 and
                macho.segments[0].sections[0].nreloc == 0 and
                macho.segments[0].sections[0].flags == 0x80000400 and
                macho.segments[0].sections[0].reserved1 == 0 and
                macho.segments[0].sections[0].reserved2 == 0 and
                macho.segments[0].sections[0].reserved3 == 0
            ) and
            (
                macho.segments[0].sections[1].sectname == "__unwind_info" and
                macho.segments[0].sections[1].segname == "__TEXT" and
                macho.segments[0].sections[1].addr == 3992 and
                macho.segments[0].sections[1].size == 72 and
                macho.segments[0].sections[1].offset == 3992 and
                macho.segments[0].sections[1].align == 2 and
                macho.segments[0].sections[1].reloff == 0 and
                macho.segments[0].sections[1].nreloc == 0 and
                macho.segments[0].sections[1].flags == 0 and
                macho.segments[0].sections[1].reserved1 == 0 and
                macho.segments[0].sections[1].reserved2 == 0 and
                macho.segments[0].sections[1].reserved3 == 0
            ) and
            (
                macho.segments[0].sections[2].sectname == "__eh_frame" and
                macho.segments[0].sections[2].segname == "__TEXT" and
                macho.segments[0].sections[2].addr == 4064 and
                macho.segments[0].sections[2].size == 24 and
                macho.segments[0].sections[2].offset == 4064 and
                macho.segments[0].sections[2].align == 3 and
                macho.segments[0].sections[2].reloff == 0 and
                macho.segments[0].sections[2].nreloc == 0 and
                macho.segments[0].sections[2].flags == 0 and
                macho.segments[0].sections[2].reserved1 == 0 and
                macho.segments[0].sections[2].reserved2 == 0 and
                macho.segments[0].sections[2].reserved3 == 0
            ) and
            not defined macho.segments[0].sections[3].size
        ) and
        (
            macho.segments[1].segname == "__LINKEDIT" and
            macho.segments[1].vmaddr == 4096 and
            macho.segments[1].vmsize == 4096 and
            macho.segments[1].fileoff == 4096 and
            macho.segments[1].fsize == 128 and
            macho.segments[1].maxprot == 7 and
            macho.segments[1].initprot == 1 and
            macho.segments[1].nsects == 0 and
            macho.segments[1].flags == 0 and
            not defined macho.segments[1].sections[0].align
        ) and

        not defined macho.fat_magic and
        not defined macho.nfat_arch and
        not defined macho.fat_arch[0].cputype and
        not defined macho.file[0].magic
}"#,
        MACHO_X86_64_DYLIB_FILE,
        true,
    );
}

#[test]
fn test_coverage_macho_fat32() {
    check_file(
        r#"import "macho"
rule test {
    condition:
        not defined macho.magic and
        not defined macho.cputype and
        not defined macho.cpusubtype and
        not defined macho.filetype and
        not defined macho.ncmds and
        not defined macho.sizeofcmds and
        not defined macho.flags and
        not defined macho.number_of_segments and
        not defined macho.reserved and
        not defined macho.entry_point and
        not defined macho.stack_size and
        macho.fat_magic == 0xcafebabe and
        macho.nfat_arch == 2 and
        (
            macho.fat_arch[0].cputype == 7 and
            macho.fat_arch[0].cpusubtype == 3 and
            macho.fat_arch[0].size == 8512 and
            macho.fat_arch[0].align == 12 and
            macho.fat_arch[0].offset == 4096
        ) and
        (
            macho.fat_arch[1].cputype == 0x1000007 and
            macho.fat_arch[1].cpusubtype == 0x80000003 and
            macho.fat_arch[1].size == 8544 and
            macho.fat_arch[1].align == 12 and
            macho.fat_arch[1].offset == 16384
        ) and
        (
            macho.file[0].magic == 0xfeedface and
            macho.file[0].cputype == 7 and
            macho.file[0].cpusubtype == 3 and
            macho.file[0].filetype == 2 and
            macho.file[0].ncmds == 16 and
            macho.file[0].sizeofcmds == 1060 and
            macho.file[0].flags == 0x1200085 and
            macho.file[0].number_of_segments == 4 and
            macho.file[0].entry_point == 0xee0 and
            macho.file[0].stack_size == 0 and
            not defined macho.file[0].reserved and
            (
                macho.file[0].segments[0].segname == "__PAGEZERO" and
                macho.file[0].segments[0].vmaddr == 0 and
                macho.file[0].segments[0].vmsize == 4096 and
                macho.file[0].segments[0].fileoff == 0 and
                macho.file[0].segments[0].fsize == 0 and
                macho.file[0].segments[0].maxprot == 0 and
                macho.file[0].segments[0].initprot == 0 and
                macho.file[0].segments[0].nsects == 0 and
                macho.file[0].segments[0].flags == 0 and
                not defined macho.file[0].segments[0].sections[0].size
            ) and
            (
                macho.file[0].segments[1].segname == "__TEXT" and
                macho.file[0].segments[1].vmaddr == 4096 and
                macho.file[0].segments[1].vmsize == 4096 and
                macho.file[0].segments[1].fileoff == 0 and
                macho.file[0].segments[1].fsize == 4096 and
                macho.file[0].segments[1].maxprot == 7 and
                macho.file[0].segments[1].initprot == 5 and
                macho.file[0].segments[1].nsects == 5 and
                macho.file[0].segments[1].flags == 0 and
                (
                    macho.file[0].segments[1].sections[0].sectname == "__text" and
                    macho.file[0].segments[1].sections[0].segname == "__TEXT" and
                    macho.file[0].segments[1].sections[0].addr == 7824 and
                    macho.file[0].segments[1].sections[0].size == 214 and
                    macho.file[0].segments[1].sections[0].offset == 3728 and
                    macho.file[0].segments[1].sections[0].align == 4 and
                    macho.file[0].segments[1].sections[0].reloff == 0 and
                    macho.file[0].segments[1].sections[0].nreloc == 0 and
                    macho.file[0].segments[1].sections[0].flags == 0x80000400 and
                    macho.file[0].segments[1].sections[0].reserved1 == 0 and
                    macho.file[0].segments[1].sections[0].reserved2 == 0 and
                    not defined macho.file[0].segments[1].sections[0].reserved3
                ) and
                (
                    macho.file[0].segments[1].sections[1].sectname == "__symbol_stub" and
                    macho.file[0].segments[1].sections[1].segname == "__TEXT" and
                    macho.file[0].segments[1].sections[1].addr == 8038 and
                    macho.file[0].segments[1].sections[1].size == 12 and
                    macho.file[0].segments[1].sections[1].offset == 3942 and
                    macho.file[0].segments[1].sections[1].align == 1 and
                    macho.file[0].segments[1].sections[1].reloff == 0 and
                    macho.file[0].segments[1].sections[1].nreloc == 0 and
                    macho.file[0].segments[1].sections[1].flags == 0x80000508 and
                    macho.file[0].segments[1].sections[1].reserved1 == 0 and
                    macho.file[0].segments[1].sections[1].reserved2 == 6 and
                    not defined macho.file[0].segments[1].sections[1].reserved3
                ) and
                (
                    macho.file[0].segments[1].sections[2].sectname == "__stub_helper" and
                    macho.file[0].segments[1].sections[2].segname == "__TEXT" and
                    macho.file[0].segments[1].sections[2].addr == 8052 and
                    macho.file[0].segments[1].sections[2].size == 32 and
                    macho.file[0].segments[1].sections[2].offset == 3956 and
                    macho.file[0].segments[1].sections[2].align == 2 and
                    macho.file[0].segments[1].sections[2].reloff == 0 and
                    macho.file[0].segments[1].sections[2].nreloc == 0 and
                    macho.file[0].segments[1].sections[2].flags == 0x80000500 and
                    macho.file[0].segments[1].sections[2].reserved1 == 0 and
                    macho.file[0].segments[1].sections[2].reserved2 == 0 and
                    not defined macho.file[0].segments[1].sections[2].reserved3
                ) and
                (
                    macho.file[0].segments[1].sections[3].sectname == "__cstring" and
                    macho.file[0].segments[1].sections[3].segname == "__TEXT" and
                    macho.file[0].segments[1].sections[3].addr == 8084 and
                    macho.file[0].segments[1].sections[3].size == 25 and
                    macho.file[0].segments[1].sections[3].offset == 3988 and
                    macho.file[0].segments[1].sections[3].align == 0 and
                    macho.file[0].segments[1].sections[3].reloff == 0 and
                    macho.file[0].segments[1].sections[3].nreloc == 0 and
                    macho.file[0].segments[1].sections[3].flags == 2 and
                    macho.file[0].segments[1].sections[3].reserved1 == 0 and
                    macho.file[0].segments[1].sections[3].reserved2 == 0 and
                    not defined macho.file[0].segments[1].sections[3].reserved3
                ) and
                (
                    macho.file[0].segments[1].sections[4].sectname == "__unwind_info" and
                    macho.file[0].segments[1].sections[4].segname == "__TEXT" and
                    macho.file[0].segments[1].sections[4].addr == 8112 and
                    macho.file[0].segments[1].sections[4].size == 72 and
                    macho.file[0].segments[1].sections[4].offset == 4016 and
                    macho.file[0].segments[1].sections[4].align == 2 and
                    macho.file[0].segments[1].sections[4].reloff == 0 and
                    macho.file[0].segments[1].sections[4].nreloc == 0 and
                    macho.file[0].segments[1].sections[4].flags == 0 and
                    macho.file[0].segments[1].sections[4].reserved1 == 0 and
                    macho.file[0].segments[1].sections[4].reserved2 == 0 and
                    not defined macho.file[0].segments[1].sections[4].reserved3
                ) and
                not defined macho.file[0].segments[1].sections[5].size
            ) and
            (
                macho.file[0].segments[2].segname == "__DATA" and
                macho.file[0].segments[2].vmaddr == 8192 and
                macho.file[0].segments[2].vmsize == 4096 and
                macho.file[0].segments[2].fileoff == 4096 and
                macho.file[0].segments[2].fsize == 4096 and
                macho.file[0].segments[2].maxprot == 7 and
                macho.file[0].segments[2].initprot == 3 and
                macho.file[0].segments[2].nsects == 2 and
                macho.file[0].segments[2].flags == 0 and
                (
                    macho.file[0].segments[2].sections[0].sectname == "__nl_symbol_ptr" and
                    macho.file[0].segments[2].sections[0].segname == "__DATA" and
                    macho.file[0].segments[2].sections[0].addr == 8192 and
                    macho.file[0].segments[2].sections[0].size == 8 and
                    macho.file[0].segments[2].sections[0].offset == 4096 and
                    macho.file[0].segments[2].sections[0].align == 2 and
                    macho.file[0].segments[2].sections[0].reloff == 0 and
                    macho.file[0].segments[2].sections[0].nreloc == 0 and
                    macho.file[0].segments[2].sections[0].flags == 6 and
                    macho.file[0].segments[2].sections[0].reserved1 == 2 and
                    macho.file[0].segments[2].sections[0].reserved2 == 0 and
                    not defined macho.file[0].segments[2].sections[0].reserved3
                ) and
                (
                    macho.file[0].segments[2].sections[1].sectname == "__la_symbol_ptr" and
                    macho.file[0].segments[2].sections[1].segname == "__DATA" and
                    macho.file[0].segments[2].sections[1].addr == 8200 and
                    macho.file[0].segments[2].sections[1].size == 8 and
                    macho.file[0].segments[2].sections[1].offset == 4104 and
                    macho.file[0].segments[2].sections[1].align == 2 and
                    macho.file[0].segments[2].sections[1].reloff == 0 and
                    macho.file[0].segments[2].sections[1].nreloc == 0 and
                    macho.file[0].segments[2].sections[1].flags == 7 and
                    macho.file[0].segments[2].sections[1].reserved1 == 4 and
                    macho.file[0].segments[2].sections[1].reserved2 == 0 and
                    not defined macho.file[0].segments[2].sections[1].reserved3
                ) and
                not defined macho.file[0].segments[2].sections[2].size
            ) and
            (
                macho.file[0].segments[3].segname == "__LINKEDIT" and
                macho.file[0].segments[3].vmaddr == 12288 and
                macho.file[0].segments[3].vmsize == 4096 and
                macho.file[0].segments[3].fileoff == 8192 and
                macho.file[0].segments[3].fsize == 320 and
                macho.file[0].segments[3].maxprot == 7 and
                macho.file[0].segments[3].initprot == 1 and
                macho.file[0].segments[3].nsects == 0 and
                macho.file[0].segments[3].flags == 0 and
                not defined macho.file[0].segments[3].sections[0].size
            )
        ) and
        (
            macho.file[1].magic == 0xfeedfacf and
            macho.file[1].cputype == 0x1000007 and
            macho.file[1].cpusubtype == 0x80000003 and
            macho.file[1].filetype == 2 and
            macho.file[1].ncmds == 16 and
            macho.file[1].sizeofcmds == 1296 and
            macho.file[1].flags == 0x200085 and
            macho.file[1].number_of_segments == 4 and
            macho.file[1].entry_point == 0xee0 and
            macho.file[1].stack_size == 0 and
            macho.file[1].reserved == 0 and
            (
                macho.file[1].segments[0].segname == "__PAGEZERO" and
                macho.file[1].segments[0].vmaddr == 0 and
                macho.file[1].segments[0].vmsize == 0x100000000 and
                macho.file[1].segments[0].fileoff == 0 and
                macho.file[1].segments[0].fsize == 0 and
                macho.file[1].segments[0].maxprot == 0 and
                macho.file[1].segments[0].initprot == 0 and
                macho.file[1].segments[0].nsects == 0 and
                macho.file[1].segments[0].flags == 0 and
                not defined macho.file[1].segments[0].sections[0].size
            ) and
            (
                macho.file[1].segments[1].segname == "__TEXT" and
                macho.file[1].segments[1].vmaddr == 0x100000000 and
                macho.file[1].segments[1].vmsize == 4096 and
                macho.file[1].segments[1].fileoff == 0 and
                macho.file[1].segments[1].fsize == 4096 and
                macho.file[1].segments[1].maxprot == 7 and
                macho.file[1].segments[1].initprot == 5 and
                macho.file[1].segments[1].nsects == 6 and
                macho.file[1].segments[1].flags == 0 and
                (
                    macho.file[1].segments[1].sections[0].sectname == "__text" and
                    macho.file[1].segments[1].sections[0].segname == "__TEXT" and
                    macho.file[1].segments[1].sections[0].addr == 0x100000e90 and
                    macho.file[1].segments[1].sections[0].size == 181 and
                    macho.file[1].segments[1].sections[0].offset == 3728 and
                    macho.file[1].segments[1].sections[0].align == 4 and
                    macho.file[1].segments[1].sections[0].reloff == 0 and
                    macho.file[1].segments[1].sections[0].nreloc == 0 and
                    macho.file[1].segments[1].sections[0].flags == 0x80000400 and
                    macho.file[1].segments[1].sections[0].reserved1 == 0 and
                    macho.file[1].segments[1].sections[0].reserved2 == 0 and
                    macho.file[1].segments[1].sections[0].reserved3 == 0
                ) and
                (
                    macho.file[1].segments[1].sections[1].sectname == "__stubs" and
                    macho.file[1].segments[1].sections[1].segname == "__TEXT" and
                    macho.file[1].segments[1].sections[1].addr == 0x100000f46 and
                    macho.file[1].segments[1].sections[1].size == 12 and
                    macho.file[1].segments[1].sections[1].offset == 3910 and
                    macho.file[1].segments[1].sections[1].align == 1 and
                    macho.file[1].segments[1].sections[1].reloff == 0 and
                    macho.file[1].segments[1].sections[1].nreloc == 0 and
                    macho.file[1].segments[1].sections[1].flags == 0x80000408 and
                    macho.file[1].segments[1].sections[1].reserved1 == 0 and
                    macho.file[1].segments[1].sections[1].reserved2 == 6 and
                    macho.file[1].segments[1].sections[1].reserved3 == 0
                ) and
                (
                    macho.file[1].segments[1].sections[2].sectname == "__stub_helper" and
                    macho.file[1].segments[1].sections[2].segname == "__TEXT" and
                    macho.file[1].segments[1].sections[2].addr == 0x100000f54 and
                    macho.file[1].segments[1].sections[2].size == 36 and
                    macho.file[1].segments[1].sections[2].offset == 3924 and
                    macho.file[1].segments[1].sections[2].align == 2 and
                    macho.file[1].segments[1].sections[2].reloff == 0 and
                    macho.file[1].segments[1].sections[2].nreloc == 0 and
                    macho.file[1].segments[1].sections[2].flags == 0x80000400 and
                    macho.file[1].segments[1].sections[2].reserved1 == 0 and
                    macho.file[1].segments[1].sections[2].reserved2 == 0 and
                    macho.file[1].segments[1].sections[2].reserved3 == 0
                ) and
                (
                    macho.file[1].segments[1].sections[3].sectname == "__cstring" and
                    macho.file[1].segments[1].sections[3].segname == "__TEXT" and
                    macho.file[1].segments[1].sections[3].addr == 0x100000f78 and
                    macho.file[1].segments[1].sections[3].size == 25 and
                    macho.file[1].segments[1].sections[3].offset == 3960 and
                    macho.file[1].segments[1].sections[3].align == 0 and
                    macho.file[1].segments[1].sections[3].reloff == 0 and
                    macho.file[1].segments[1].sections[3].nreloc == 0 and
                    macho.file[1].segments[1].sections[3].flags == 2 and
                    macho.file[1].segments[1].sections[3].reserved1 == 0 and
                    macho.file[1].segments[1].sections[3].reserved2 == 0 and
                    macho.file[1].segments[1].sections[3].reserved3 == 0
                ) and
                (
                    macho.file[1].segments[1].sections[4].sectname == "__unwind_info" and
                    macho.file[1].segments[1].sections[4].segname == "__TEXT" and
                    macho.file[1].segments[1].sections[4].addr == 0x100000f94 and
                    macho.file[1].segments[1].sections[4].size == 72 and
                    macho.file[1].segments[1].sections[4].offset == 3988 and
                    macho.file[1].segments[1].sections[4].align == 2 and
                    macho.file[1].segments[1].sections[4].reloff == 0 and
                    macho.file[1].segments[1].sections[4].nreloc == 0 and
                    macho.file[1].segments[1].sections[4].flags == 0 and
                    macho.file[1].segments[1].sections[4].reserved1 == 0 and
                    macho.file[1].segments[1].sections[4].reserved2 == 0 and
                    macho.file[1].segments[1].sections[4].reserved3 == 0
                ) and
                (
                    macho.file[1].segments[1].sections[5].sectname == "__eh_frame" and
                    macho.file[1].segments[1].sections[5].segname == "__TEXT" and
                    macho.file[1].segments[1].sections[5].addr == 0x100000fe0 and
                    macho.file[1].segments[1].sections[5].size == 24 and
                    macho.file[1].segments[1].sections[5].offset == 4064 and
                    macho.file[1].segments[1].sections[5].align == 3 and
                    macho.file[1].segments[1].sections[5].reloff == 0 and
                    macho.file[1].segments[1].sections[5].nreloc == 0 and
                    macho.file[1].segments[1].sections[5].flags == 0 and
                    macho.file[1].segments[1].sections[5].reserved1 == 0 and
                    macho.file[1].segments[1].sections[5].reserved2 == 0 and
                    macho.file[1].segments[1].sections[5].reserved3 == 0
                ) and
                not defined macho.file[1].segments[1].sections[6].size
            ) and
            (
                macho.file[1].segments[2].segname == "__DATA" and
                macho.file[1].segments[2].vmaddr == 0x100001000 and
                macho.file[1].segments[2].vmsize == 4096 and
                macho.file[1].segments[2].fileoff == 4096 and
                macho.file[1].segments[2].fsize == 4096 and
                macho.file[1].segments[2].maxprot == 7 and
                macho.file[1].segments[2].initprot == 3 and
                macho.file[1].segments[2].nsects == 2 and
                macho.file[1].segments[2].flags == 0 and
                (
                    macho.file[1].segments[2].sections[0].sectname == "__nl_symbol_ptr" and
                    macho.file[1].segments[2].sections[0].segname == "__DATA" and
                    macho.file[1].segments[2].sections[0].addr == 0x100001000 and
                    macho.file[1].segments[2].sections[0].size == 16 and
                    macho.file[1].segments[2].sections[0].offset == 4096 and
                    macho.file[1].segments[2].sections[0].align == 3 and
                    macho.file[1].segments[2].sections[0].reloff == 0 and
                    macho.file[1].segments[2].sections[0].nreloc == 0 and
                    macho.file[1].segments[2].sections[0].flags == 6 and
                    macho.file[1].segments[2].sections[0].reserved1 == 2 and
                    macho.file[1].segments[2].sections[0].reserved2 == 0 and
                    macho.file[1].segments[2].sections[0].reserved3 == 0
                ) and
                (
                    macho.file[1].segments[2].sections[1].sectname == "__la_symbol_ptr" and
                    macho.file[1].segments[2].sections[1].segname == "__DATA" and
                    macho.file[1].segments[2].sections[1].addr == 0x100001010 and
                    macho.file[1].segments[2].sections[1].size == 16 and
                    macho.file[1].segments[2].sections[1].offset == 4112 and
                    macho.file[1].segments[2].sections[1].align == 3 and
                    macho.file[1].segments[2].sections[1].reloff == 0 and
                    macho.file[1].segments[2].sections[1].nreloc == 0 and
                    macho.file[1].segments[2].sections[1].flags == 7 and
                    macho.file[1].segments[2].sections[1].reserved1 == 4 and
                    macho.file[1].segments[2].sections[1].reserved2 == 0 and
                    macho.file[1].segments[2].sections[1].reserved3 == 0
                ) and
                not defined macho.file[1].segments[2].sections[2].size
            ) and
            (
                macho.file[1].segments[3].segname == "__LINKEDIT" and
                macho.file[1].segments[3].vmaddr == 0x100002000 and
                macho.file[1].segments[3].vmsize == 4096 and
                macho.file[1].segments[3].fileoff == 8192 and
                macho.file[1].segments[3].fsize == 352 and
                macho.file[1].segments[3].maxprot == 7 and
                macho.file[1].segments[3].initprot == 1 and
                macho.file[1].segments[3].nsects == 0 and
                macho.file[1].segments[3].flags == 0 and
                not defined macho.file[1].segments[3].sections[0].size
            )
        )
}"#,
        "assets/libyara/data/tiny-universal",
        true,
    );
}
