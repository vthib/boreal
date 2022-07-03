use crate::{
    libyara_compat::util::{ELF32_FILE, ELF32_MIPS_FILE, ELF32_SHAREDOBJ},
    utils::check,
};

// These are mostly coverage tests, ensuring all the fields are correctly set and have the same
// values as in libyara

#[test]
fn test_coverage_elf32() {
    check(
        r#"import "elf"
rule test {
    condition:
        not defined elf.dynamic[0].type and
        not defined elf.dynamic_section_entries and
        not defined elf.dynsym[0].type and
        not defined elf.dynsym_entries and
        elf.entry_point == 96 and
        elf.machine == 3 and
        elf.number_of_sections == 4 and
        elf.number_of_segments == 1 and
        elf.ph_entry_size == 32 and
        elf.ph_offset == 52 and
        (
            elf.sections[0].address == 0 and
            elf.sections[0].flags == 0 and
            elf.sections[0].name == "" and
            elf.sections[0].offset == 0 and
            elf.sections[0].size == 0 and
            elf.sections[0].type == 0
        ) and
        (
            elf.sections[1].address == 0x8048060 and
            elf.sections[1].flags == 6 and
            elf.sections[1].name == ".text" and
            elf.sections[1].offset == 96 and
            elf.sections[1].size == 12 and
            elf.sections[1].type == 1
        ) and
        (
            elf.sections[2].address == 0 and
            elf.sections[2].flags == 0 and
            elf.sections[2].name == ".comment" and
            elf.sections[2].offset == 108 and
            elf.sections[2].size == 31 and
            elf.sections[2].type == 1
        ) and
        (
            elf.sections[3].address == 0 and
            elf.sections[3].flags == 0 and
            elf.sections[3].name == ".shstrtab" and
            elf.sections[3].offset == 139 and
            elf.sections[3].size == 26 and
            elf.sections[3].type == 3
        ) and
        (
            elf.segments[0].alignment == 0x1000 and
            elf.segments[0].file_size == 108 and
            elf.segments[0].flags == 5 and
            elf.segments[0].memory_size == 108 and
            elf.segments[0].offset == 0 and
            elf.segments[0].physical_address == 0x8048000 and
            elf.segments[0].type == 1 and
            elf.segments[0].virtual_address == 0x8048000
        ) and

        elf.sh_entry_size == 40 and
        elf.sh_offset == 168 and
        not defined elf.symtab[0].type and
        not defined elf.symtab_entries and
        elf.type == 2
}"#,
        ELF32_FILE,
        true,
    );
}

#[test]
fn test_coverage_elf32_mips() {
    check(
        r#"import "elf"
rule test {
    condition:
        (
            elf.dynamic[0].type == 1 and
            elf.dynamic[0].val == 151 and
            elf.dynamic[1].type == 12 and
            elf.dynamic[1].val == 0x40058c and
            elf.dynamic[2].type == 13 and
            elf.dynamic[2].val == 0x400910 and
            elf.dynamic[3].type == 4 and
            elf.dynamic[3].val == 0x400280 and
            elf.dynamic[4].type == 5 and
            elf.dynamic[4].val == 0x400484 and
            elf.dynamic[5].type == 6 and
            elf.dynamic[5].val == 0x400324 and
            elf.dynamic[6].type == 10 and
            elf.dynamic[6].val == 262 and
            elf.dynamic[7].type == 11 and
            elf.dynamic[7].val == 16 and
            elf.dynamic[8].type == 0x70000016 and
            elf.dynamic[8].val == 0x411000 and
            elf.dynamic[9].type == 21 and
            elf.dynamic[9].val == 0 and
            elf.dynamic[10].type == 3 and
            elf.dynamic[10].val == 0x411010 and
            elf.dynamic[11].type == 0x70000001 and
            elf.dynamic[11].val == 1 and
            elf.dynamic[12].type == 0x70000005 and
            elf.dynamic[12].val == 2 and
            elf.dynamic[13].type == 0x70000006 and
            elf.dynamic[13].val == 0x400000 and
            elf.dynamic[14].type == 0x7000000a and
            elf.dynamic[14].val == 8 and
            elf.dynamic[15].type == 0x70000011 and
            elf.dynamic[15].val == 22 and
            elf.dynamic[16].type == 0x70000012 and
            elf.dynamic[16].val == 32 and
            elf.dynamic[17].type == 0x70000013 and
            elf.dynamic[17].val == 16 and
            elf.dynamic[18].type == 0 and
            elf.dynamic[18].val == 0 and
            not defined elf.dynamic[19].type and
            not defined elf.dynamic[19].val
        ) and
        elf.dynamic_section_entries == 19 and
        (
            (
                elf.dynsym[0].bind == 0 and
                elf.dynsym[0].name == "" and
                elf.dynsym[0].shndx == 0 and
                elf.dynsym[0].size == 0 and
                elf.dynsym[0].type == 0 and
                elf.dynsym[0].value == 0
            ) and
            (
                elf.dynsym[1].bind == 1 and
                elf.dynsym[1].name == "_fdata" and
                elf.dynsym[1].shndx == 16 and
                elf.dynsym[1].size == 0 and
                elf.dynsym[1].type == 0 and
                elf.dynsym[1].value == 0x411000
            ) and
            (
                elf.dynsym[2].bind == 1 and
                elf.dynsym[2].name == "__gnu_local_gp" and
                elf.dynsym[2].shndx == 0 and
                elf.dynsym[2].size == 0 and
                elf.dynsym[2].type == 1 and
                elf.dynsym[2].value == 0
            ) and
            (
                elf.dynsym[3].bind == 1 and
                elf.dynsym[3].name == "_DYNAMIC_LINKING" and
                elf.dynsym[3].shndx == 65521 and
                elf.dynsym[3].size == 0 and
                elf.dynsym[3].type == 3 and
                elf.dynsym[3].value == 1
            ) and
            (
                elf.dynsym[4].bind == 1 and
                elf.dynsym[4].name == "_init" and
                elf.dynsym[4].shndx == 8 and
                elf.dynsym[4].size == 8 and
                elf.dynsym[4].type == 2 and
                elf.dynsym[4].value == 0x40058c
            ) and
            (
                elf.dynsym[5].bind == 1 and
                elf.dynsym[5].name == "__start" and
                elf.dynsym[5].shndx == 9 and
                elf.dynsym[5].size == 0 and
                elf.dynsym[5].type == 2 and
                elf.dynsym[5].value == 0x400610
            ) and
            (
                elf.dynsym[6].bind == 1 and
                elf.dynsym[6].name == "_ftext" and
                elf.dynsym[6].shndx == 9 and
                elf.dynsym[6].size == 0 and
                elf.dynsym[6].type == 0 and
                elf.dynsym[6].value == 0x400600
            ) and
            (
                elf.dynsym[7].bind == 1 and
                elf.dynsym[7].name == "_start" and
                elf.dynsym[7].shndx == 9 and
                elf.dynsym[7].size == 0 and
                elf.dynsym[7].type == 2 and
                elf.dynsym[7].value == 0x400610
            ) and
            (
                elf.dynsym[8].bind == 1 and
                elf.dynsym[8].name == "_start_c" and
                elf.dynsym[8].shndx == 9 and
                elf.dynsym[8].size == 56 and
                elf.dynsym[8].type == 2 and
                elf.dynsym[8].value == 0x400650
            ) and
            (
                elf.dynsym[9].bind == 1 and
                elf.dynsym[9].name == "__RLD_MAP" and
                elf.dynsym[9].shndx == 16 and
                elf.dynsym[9].size == 0 and
                elf.dynsym[9].type == 1 and
                elf.dynsym[9].value == 0x411000
            ) and
            (
                elf.dynsym[10].bind == 1 and
                elf.dynsym[10].name == "__bss_start" and
                elf.dynsym[10].shndx == 19 and
                elf.dynsym[10].size == 0 and
                elf.dynsym[10].type == 0 and
                elf.dynsym[10].value == 0x41104c
            ) and
            (
                elf.dynsym[11].bind == 1 and
                elf.dynsym[11].name == "main" and
                elf.dynsym[11].shndx == 9 and
                elf.dynsym[11].size == 8 and
                elf.dynsym[11].type == 2 and
                elf.dynsym[11].value == 0x400600
            ) and
            // ellipsis...
            (
                elf.dynsym[21].bind == 2 and
                elf.dynsym[21].name == "__deregister_frame_info" and
                elf.dynsym[21].shndx == 0 and
                elf.dynsym[21].size == 0 and
                elf.dynsym[21].type == 2 and
                elf.dynsym[21].value == 0
            ) and
            not defined elf.dynsym[22].bind
        ) and
        elf.dynsym_entries == 22 and
        elf.entry_point == 1552 and
        elf.machine == 8 and
        elf.number_of_sections == 35 and
        elf.number_of_segments == 10 and
        elf.ph_entry_size == 32 and
        elf.ph_offset == 52 and
        (
            (
                elf.sections[0].address == 0 and
                elf.sections[0].flags == 0 and
                elf.sections[0].name == "" and
                elf.sections[0].offset == 0 and
                elf.sections[0].size == 0 and
                elf.sections[0].type == 0
            ) and
            (
                elf.sections[10].address == 0x4008f0 and
                elf.sections[10].flags == 6 and
                elf.sections[10].name == ".MIPS.stubs" and
                elf.sections[10].offset == 2288 and
                elf.sections[10].size == 32 and
                elf.sections[10].type == 1
            ) and
            (
                elf.sections[20].address == 0 and
                elf.sections[20].flags == 48 and
                elf.sections[20].name == ".comment" and
                elf.sections[20].offset == 4172 and
                elf.sections[20].size == 17 and
                elf.sections[20].type == 1
            ) and
            (
                elf.sections[30].address == 0 and
                elf.sections[30].flags == 0 and
                elf.sections[30].name == ".gnu.attributes" and
                elf.sections[30].offset == 5736 and
                elf.sections[30].size == 16 and
                elf.sections[30].type == 0x6ffffff5
            ) and
            (
                elf.sections[34].address == 0 and
                elf.sections[34].flags == 0 and
                elf.sections[34].name == ".strtab" and
                elf.sections[34].offset == 7356 and
                elf.sections[34].size == 617 and
                elf.sections[34].type == 3
            ) and
            not defined elf.sections[35].type
        ) and
        (
            (
                elf.segments[0].alignment == 4 and
                elf.segments[0].file_size == 320 and
                elf.segments[0].flags == 5 and
                elf.segments[0].memory_size == 320 and
                elf.segments[0].offset == 52 and
                elf.segments[0].physical_address == 0x400034 and
                elf.segments[0].type == 6 and
                elf.segments[0].virtual_address == 0x400034
            ) and
            (
                elf.segments[1].alignment == 1 and
                elf.segments[1].file_size == 23 and
                elf.segments[1].flags == 4 and
                elf.segments[1].memory_size == 23 and
                elf.segments[1].offset == 372 and
                elf.segments[1].physical_address == 0x400174 and
                elf.segments[1].type == 3 and
                elf.segments[1].virtual_address == 0x400174
            ) and
            (
                elf.segments[2].alignment == 8 and
                elf.segments[2].file_size == 24 and
                elf.segments[2].flags == 4 and
                elf.segments[2].memory_size == 24 and
                elf.segments[2].offset == 400 and
                elf.segments[2].physical_address == 0x400190 and
                elf.segments[2].type == 0x70000003 and
                elf.segments[2].virtual_address == 0x400190
            ) and
            (
                elf.segments[3].alignment == 4 and
                elf.segments[3].file_size == 24 and
                elf.segments[3].flags == 4 and
                elf.segments[3].memory_size == 24 and
                elf.segments[3].offset == 424 and
                elf.segments[3].physical_address == 0x4001a8 and
                elf.segments[3].type == 0x70000000 and
                elf.segments[3].virtual_address == 0x4001a8
            ) and
            (
                elf.segments[4].alignment == 0x10000 and
                elf.segments[4].file_size == 2396 and
                elf.segments[4].flags == 5 and
                elf.segments[4].memory_size == 2396 and
                elf.segments[4].offset == 0 and
                elf.segments[4].physical_address == 0x400000 and
                elf.segments[4].type == 1 and
                elf.segments[4].virtual_address == 0x400000
            ) and
            (
                elf.segments[5].alignment == 0x10000 and
                elf.segments[5].file_size == 96 and
                elf.segments[5].flags == 6 and
                elf.segments[5].memory_size == 132 and
                elf.segments[5].offset == 4076 and
                elf.segments[5].physical_address == 0x410fec and
                elf.segments[5].type == 1 and
                elf.segments[5].virtual_address == 0x410fec
            ) and
            (
                elf.segments[6].alignment == 4 and
                elf.segments[6].file_size == 192 and
                elf.segments[6].flags == 4 and
                elf.segments[6].memory_size == 192 and
                elf.segments[6].offset == 448 and
                elf.segments[6].physical_address == 0x4001c0 and
                elf.segments[6].type == 2 and
                elf.segments[6].virtual_address == 0x4001c0
            ) and
            (
                elf.segments[7].alignment == 16 and
                elf.segments[7].file_size == 0 and
                elf.segments[7].flags == 7 and
                elf.segments[7].memory_size == 0 and
                elf.segments[7].offset == 0 and
                elf.segments[7].physical_address == 0 and
                elf.segments[7].type == 0x6474e551 and
                elf.segments[7].virtual_address == 0
            ) and
            (
                elf.segments[8].alignment == 1 and
                elf.segments[8].file_size == 20 and
                elf.segments[8].flags == 4 and
                elf.segments[8].memory_size == 20 and
                elf.segments[8].offset == 4076 and
                elf.segments[8].physical_address == 0x410fec and
                elf.segments[8].type == 0x6474e552 and
                elf.segments[8].virtual_address == 0x410fec
            ) and
            (
                elf.segments[9].alignment == 4 and
                elf.segments[9].file_size == 0 and
                elf.segments[9].flags == 0 and
                elf.segments[9].memory_size == 0 and
                elf.segments[9].offset == 0 and
                elf.segments[9].physical_address == 0 and
                elf.segments[9].type == 0 and
                elf.segments[9].virtual_address == 0
            ) and
            not defined elf.segments[10].type
        ) and
        elf.sh_entry_size == 40 and
        elf.sh_offset == 7976 and
        (
            (
                elf.symtab[0].bind == 0 and
                elf.symtab[0].name == "" and
                elf.symtab[0].shndx == 0 and
                elf.symtab[0].size == 0 and
                elf.symtab[0].type == 0 and
                elf.symtab[0].value == 0
            ) and
            (
                elf.symtab[32].bind == 0 and
                elf.symtab[32].name == "crt/crt1.c" and
                elf.symtab[32].shndx == 0xfff1 and
                elf.symtab[32].size == 0 and
                elf.symtab[32].type == 4 and
                elf.symtab[32].value == 0
            ) and
            (
                elf.symtab[59].bind == 1 and
                elf.symtab[59].name == "_fdata" and
                elf.symtab[59].shndx == 16 and
                elf.symtab[59].size == 0 and
                elf.symtab[59].type == 0 and
                elf.symtab[59].value == 0x411000
            ) and
            (
                elf.symtab[79].bind == 2 and
                elf.symtab[79].name == "__register_frame_info" and
                elf.symtab[79].shndx == 0 and
                elf.symtab[79].size == 0 and
                elf.symtab[79].type == 2 and
                elf.symtab[79].value == 0
            ) and
            not defined elf.symtab[80].type
        ) and
        elf.symtab_entries == 80 and
        elf.type == 2
}"#,
        ELF32_MIPS_FILE,
        true,
    );
}

#[test]
fn test_coverage_elf32_so() {
    check(
        r#"import "elf"
rule test {
    condition:
        (
            elf.dynamic[0].type == 0x6ffffef5 and
            elf.dynamic[0].val == 248 and
            elf.dynamic[1].type == 5 and
            elf.dynamic[1].val == 376 and
            elf.dynamic[2].type == 6 and
            elf.dynamic[2].val == 296 and
            elf.dynamic[3].type == 10 and
            elf.dynamic[3].val == 25 and
            elf.dynamic[4].type == 11 and
            elf.dynamic[4].val == 16 and
            elf.dynamic[5].type == 0 and
            elf.dynamic[5].val == 0 and
            not defined elf.dynamic[6].type and
            not defined elf.dynamic[6].val
        ) and
        elf.dynamic_section_entries == 6 and
        (
            (
                elf.dynsym[0].bind == 0 and
                elf.dynsym[0].name == "" and
                elf.dynsym[0].shndx == 0 and
                elf.dynsym[0].size == 0 and
                elf.dynsym[0].type == 0 and
                elf.dynsym[0].value == 0
            ) and
            (
                elf.dynsym[1].bind == 1 and
                elf.dynsym[1].name == "_edata" and
                elf.dynsym[1].shndx == 7 and
                elf.dynsym[1].size == 0 and
                elf.dynsym[1].type == 0 and
                elf.dynsym[1].value == 0x2000
            ) and
            (
                elf.dynsym[2].bind == 1 and
                elf.dynsym[2].name == "_end" and
                elf.dynsym[2].shndx == 7 and
                elf.dynsym[2].size == 0 and
                elf.dynsym[2].type == 0 and
                elf.dynsym[2].value == 0x2000
            ) and
            (
                elf.dynsym[3].bind == 1 and
                elf.dynsym[3].name == "_start" and
                elf.dynsym[3].shndx == 5 and
                elf.dynsym[3].size == 0 and
                elf.dynsym[3].type == 0 and
                elf.dynsym[3].value == 416
            ) and
            (
                elf.dynsym[4].bind == 1 and
                elf.dynsym[4].name == "__bss_start" and
                elf.dynsym[4].shndx == 7 and
                elf.dynsym[4].size == 0 and
                elf.dynsym[4].type == 0 and
                elf.dynsym[4].value == 0x2000
            ) and
            not defined elf.dynsym[5].bind
        ) and
        elf.dynsym_entries == 5 and
        elf.entry_point == 416 and
        elf.machine == 3 and
        elf.number_of_sections == 9 and
        elf.number_of_segments == 5 and
        elf.ph_entry_size == 32 and
        elf.ph_offset == 52 and
        (
            (
                elf.sections[0].address == 0 and
                elf.sections[0].flags == 0 and
                elf.sections[0].name == "" and
                elf.sections[0].offset == 0 and
                elf.sections[0].size == 0 and
                elf.sections[0].type == 0
            ) and
            (
                elf.sections[1].address == 212 and
                elf.sections[1].flags == 2 and
                elf.sections[1].name == ".note.gnu.build-id" and
                elf.sections[1].offset == 212 and
                elf.sections[1].size == 36 and
                elf.sections[1].type == 7
            ) and
            (
                elf.sections[7].address == 8104 and
                elf.sections[7].flags == 3 and
                elf.sections[7].name == ".dynamic" and
                elf.sections[7].offset == 4008 and
                elf.sections[7].size == 88 and
                elf.sections[7].type == 6
            ) and
            (
                elf.sections[8].address == 0 and
                elf.sections[8].flags == 0 and
                elf.sections[8].name == ".shstrtab" and
                elf.sections[8].offset == 4096 and
                elf.sections[8].size == 81 and
                elf.sections[8].type == 3
            ) and
            not defined elf.sections[9].type
        ) and
        elf.sh_entry_size == 40 and
        elf.sh_offset == 4180 and
        not defined elf.symtab[0].type and
        not defined elf.symtab_entries and
        elf.type == 3
}"#,
        ELF32_SHAREDOBJ,
        true,
    );
}
