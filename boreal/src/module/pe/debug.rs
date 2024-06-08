use std::mem::size_of;

use object::read::pe::DataDirectories;
use object::read::{Bytes, ReadRef};
use object::{pe, LittleEndian as LE};

use super::{utils, Value};

pub fn pdb_path(
    data_dirs: &DataDirectories,
    mem: &[u8],
    sections: &utils::SectionTable,
) -> Option<Value> {
    let dir = data_dirs.get(pe::IMAGE_DIRECTORY_ENTRY_DEBUG)?;
    let mut debug_data = Bytes(sections.get_dir_data(mem, *dir)?);

    let nb_directories = debug_data.len() / size_of::<pe::ImageDebugDirectory>();
    for debug_dir in debug_data
        .read_slice::<pe::ImageDebugDirectory>(nb_directories)
        .ok()?
    {
        if debug_dir.typ.get(LE) != pe::IMAGE_DEBUG_TYPE_CODEVIEW {
            return None;
        }

        let mut offset = 0;

        // try first as an RVA, then as a raw offset. See logic from libyara for explanations.
        let raw_data_addr = debug_dir.address_of_raw_data.get(LE);
        let raw_data_ptr = debug_dir.pointer_to_raw_data.get(LE);
        if raw_data_addr != 0 {
            if let Some(v) = utils::va_to_file_offset(mem, sections, raw_data_addr) {
                offset = v;
            }
        }
        if offset == 0 && raw_data_ptr != 0 {
            offset = raw_data_ptr;
        }
        if offset == 0 {
            continue;
        }

        let info = mem
            .read_slice_at::<u8>(offset.into(), debug_dir.size_of_data.get(LE) as usize)
            .ok()?;

        let mut info = Bytes(info);
        let sig = match info.read_bytes(4) {
            Ok(v) => v.0,
            Err(()) => continue,
        };

        let pdb_path_offset = match sig {
            // PDB20
            b"NB10" => 12,
            // PDB70
            b"RSDS" => 20,
            // MTOC
            b"MTOC" => 16,
            _ => continue,
        };

        let path = info.read_string_at(pdb_path_offset).ok()?;

        return Some(path.to_vec().into());
    }

    None
}
