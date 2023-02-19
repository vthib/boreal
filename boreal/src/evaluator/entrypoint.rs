//! Implementation of the entrypoint instruction in yara rules.
//!
//! This depends on the `object` feature.

use object::coff::SectionTable;
use object::elf::{FileHeader32, FileHeader64};
use object::pe::{
    ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
};
use object::read::elf::FileHeader;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
use object::{Endianness, FileKind, LittleEndian as LE};

use super::Value;
use crate::module::elf;

pub(super) fn get_pe_or_elf_entry_point(mem: &[u8]) -> Option<Value> {
    match FileKind::parse(mem).ok()? {
        FileKind::Pe32 => parse_pe::<ImageNtHeaders32>(mem),
        FileKind::Pe64 => parse_pe::<ImageNtHeaders64>(mem),
        FileKind::Elf32 => parse_elf(FileHeader32::parse(mem).ok()?, mem),
        FileKind::Elf64 => parse_elf(FileHeader64::parse(mem).ok()?, mem),
        _ => None,
    }
}

fn parse_pe<Pe: ImageNtHeaders>(mem: &[u8]) -> Option<Value> {
    let dos_header = ImageDosHeader::parse(mem).ok()?;
    let mut offset = dos_header.nt_headers_offset().into();
    let (nt_headers, _) = Pe::parse(mem, &mut offset).ok()?;
    let opt_hdr = nt_headers.optional_header();
    let sections = nt_headers.sections(mem, offset).ok()?;

    // For some reasons, those tests exists here, but not in pe module...
    let machine = nt_headers.file_header().machine.get(LE);
    if machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_AMD64 {
        return None;
    }

    let ep = opt_hdr.address_of_entry_point();

    Some(Value::Integer(
        pe_rva_to_file_offset(&sections, ep).unwrap_or(0),
    ))
}

// This reimplements the `yr_pe_rva_to_offset` function from libyara.
//
// This is not the same as the function implemented in the pe module and it has it own set
// of particularities...
fn pe_rva_to_file_offset(sections: &SectionTable, va: u32) -> Option<i64> {
    let mut nearest_section_va = 0;
    let mut nearest_section_offset = 0;
    for section in sections.iter().take(60) {
        let section_va = section.virtual_address.get(LE);
        if va >= section_va && nearest_section_va <= section_va {
            nearest_section_va = section_va;
            nearest_section_offset = section.pointer_to_raw_data.get(LE);
        }
    }

    i64::from(nearest_section_offset).checked_add(i64::from(va - nearest_section_va))
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(header: &Elf, mem: &[u8]) -> Option<Value> {
    let e = header.endian().ok()?;

    elf::entry_point(header, e, mem)
        .and_then(|ep| i64::try_from(ep).ok())
        .map(Value::Integer)
}
