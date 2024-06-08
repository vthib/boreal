use object::pe::{ImageDataDirectory, ImageSectionHeader};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
use object::read::ReadRef;
use object::LittleEndian as LE;

/// PE Section table.
///
/// This is a modified version of the equivalent struct from `object` to
/// properly handle file & section alignment when resolving the sections
/// file range.
pub struct SectionTable<'data> {
    pub sections: &'data [ImageSectionHeader],
    realign_section_raw_data: bool,
}

impl<'data> SectionTable<'data> {
    pub fn new<H: ImageNtHeaders>(nt_headers: &H, data: &'data [u8], offset: u64) -> Option<Self> {
        let opt_header = nt_headers.optional_header();
        let file_alignment = opt_header.file_alignment();

        let file_header = nt_headers.file_header();
        let sections = data
            .read_slice_at(offset, file_header.number_of_sections.get(LE) as usize)
            .ok()?;

        // XXX: see
        // https://github.com/erocarrera/pefile/blob/0d5ce5e0193c878cd57636b438b3746ffc3ae7e3/pefile.py#L7400=
        //
        // Basically:
        // - if alignment is smaller than 0x200, do not align
        // - if bigger, use 0x200 instead of the given alignment
        let realign_section_raw_data = file_alignment >= 0x200;

        Some(Self {
            sections,
            realign_section_raw_data,
        })
    }

    pub fn iter(&self) -> std::slice::Iter<'data, ImageSectionHeader> {
        self.sections.iter()
    }

    pub fn get_dir_data(&self, mem: &'data [u8], dir: ImageDataDirectory) -> Option<&'data [u8]> {
        let va = dir.virtual_address.get(LE);
        let offset = va_to_file_offset(mem, self, va)?;
        let end = offset.checked_add(dir.size.get(LE))?;

        match (usize::try_from(offset), usize::try_from(end)) {
            (Ok(offset), Ok(end)) => mem.get(offset..end),
            _ => None,
        }
    }

    pub fn max_section_file_offset(&self) -> u64 {
        let mut max = 0;
        for section in self.iter() {
            let end_of_section = u64::from(section.pointer_to_raw_data.get(LE))
                + u64::from(section.size_of_raw_data.get(LE));
            if end_of_section > max {
                max = end_of_section;
            }
        }
        max
    }

    pub fn get_section_containing(&self, data: &'data [u8], va: u32) -> Option<(&'data [u8], u32)> {
        self.iter().find_map(|section| {
            let section_va = section.virtual_address.get(LE);
            let offset = va.checked_sub(section_va)?;
            let (section_offset, section_size) =
                get_adjusted_section_file_range(section, self.realign_section_raw_data);
            // Address must be within section (and not at its end).
            if offset < section_size {
                let section_data = data
                    .read_bytes_at(section_offset.into(), section_size.into())
                    .ok()?;
                Some((section_data, section_va))
            } else {
                None
            }
        })
    }

    pub fn get_file_range_at(&self, va: u32) -> Option<(u32, u32)> {
        self.iter().find_map(|section| {
            let section_va = section.virtual_address.get(LE);
            let offset = va.checked_sub(section_va)?;
            let (section_offset, section_size) =
                get_adjusted_section_file_range(section, self.realign_section_raw_data);
            let vsize = std::cmp::max(section.virtual_size.get(LE), section_size);
            if offset >= vsize {
                return None;
            }
            // Address must be within section (and not at its end).
            if offset < section_size {
                Some((section_offset.checked_add(offset)?, section_size - offset))
            } else {
                None
            }
        })
    }
}

fn get_adjusted_section_file_range(
    section: &ImageSectionHeader,
    realign_section_raw_data: bool,
) -> (u32, u32) {
    // Pointer and size will be zero for uninitialized data; we don't need to validate this.
    let mut offset = section.pointer_to_raw_data.get(LE);
    if realign_section_raw_data {
        offset -= offset % 0x200;
    }
    (offset, section.size_of_raw_data.get(LE))
}

pub fn va_to_file_offset(mem: &[u8], sections: &SectionTable, va: u32) -> Option<u32> {
    va_to_file_offset_inner(sections, va).and_then(|v| {
        let len: u32 = mem.len().try_into().ok()?;
        if v < len {
            Some(v)
        } else {
            None
        }
    })
}

fn va_to_file_offset_inner(sections: &SectionTable, va: u32) -> Option<u32> {
    if let Some((offset, _)) = sections.get_file_range_at(va) {
        return Some(offset);
    }

    // Special behavior from libyara: if va is before the first section, it is returned as is.
    if let Some(first_section_va) = sections.iter().map(|s| s.virtual_address.get(LE)).min() {
        if va < first_section_va {
            return Some(va);
        }
    }

    None
}
