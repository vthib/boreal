use std::mem::size_of;

use object::{Bytes, LittleEndian as LE, U16};

use super::MAX_NB_VERSION_INFOS;

pub struct VersionInfo {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub fn read_version_info(mem: &[u8], mut offset: usize, infos: &mut Vec<VersionInfo>) {
    const VS_VERSION_INFO_KEY: &[u8] = b"V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0";

    let mut bytes = Bytes(mem);
    if bytes.skip(offset).is_err() {
        return;
    }
    let Some(header) = read_header(&mut bytes) else {
        return;
    };

    let version_info_length = usize::from(header.length);
    let end = offset + version_info_length;
    let Ok(key) = bytes.read_bytes(VS_VERSION_INFO_KEY.len()) else {
        return;
    };
    if key.0 != VS_VERSION_INFO_KEY {
        return;
    }

    // VS_FIXEDFILEINFO is 32-bits aligned after the key.
    // let offset = align32(offset + HEADER_SIZE + VS_VERSION_INFO_KEY.len());
    // Then add the length of the VS_FIXEDFILEINFO, and realign
    // let mut offset = align32(offset + usize::from(header.value_length));
    offset += align32(HEADER_SIZE + 86);

    // Skip VarFileInfo, if any
    while let Some(length) = read_var_file_info(mem, offset) {
        offset += align32(length);
    }

    // Then read StringFileInfo
    while offset < end {
        if infos.len() >= MAX_NB_VERSION_INFOS {
            break;
        }

        match read_string_file_info(mem, offset, infos) {
            Some(length) => offset += length,
            None => break,
        }
    }
}

// Read a VarFileInfo. If present, return the length of the entry
fn read_var_file_info(mem: &[u8], offset: usize) -> Option<usize> {
    const VAR_FILE_INFO_KEY: &[u8] = b"V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0";

    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;
    let key = bytes.read_bytes(VAR_FILE_INFO_KEY.len()).ok()?;
    if key.0 != VAR_FILE_INFO_KEY {
        return None;
    }

    Some(usize::from(header.length))
}

// Read a StringFileInfo. If present, return the length of the entry
fn read_string_file_info(
    mem: &[u8],
    mut offset: usize,
    out: &mut Vec<VersionInfo>,
) -> Option<usize> {
    const STRING_FILE_INFO_KEY: &[u8] = b"S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0";

    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;
    let key = bytes.read_bytes(STRING_FILE_INFO_KEY.len()).ok()?;
    if key.0 != STRING_FILE_INFO_KEY {
        return None;
    }

    let length = align32(usize::from(header.length));
    let end = offset + length;

    // StringTable is then aligned
    offset += align32(HEADER_SIZE + STRING_FILE_INFO_KEY.len());

    while offset < end {
        if out.len() >= MAX_NB_VERSION_INFOS {
            break;
        }

        match read_string_table(mem, offset, out) {
            Some(length) => offset += length,
            None => break,
        }
    }

    Some(length)
}

// Read a StringTable. If present, return the length of the entry
fn read_string_table(mem: &[u8], mut offset: usize, out: &mut Vec<VersionInfo>) -> Option<usize> {
    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;

    let length = align32(usize::from(header.length));
    let end = offset + length;

    let key_len = find_wide_nul(bytes.0);
    // move to children: header, 8 byte wide string and padding
    offset += align32(HEADER_SIZE + key_len + 2);

    while offset < end {
        if out.len() >= MAX_NB_VERSION_INFOS {
            break;
        }

        match read_string(mem, offset, out) {
            Some(length) => offset += length,
            None => break,
        }
    }

    Some(length)
}

// Read a String structure. If present, return the length of the entry
fn read_string(mem: &[u8], offset: usize, out: &mut Vec<VersionInfo>) -> Option<usize> {
    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;

    let length = align32(usize::from(header.length));
    let end = offset + length;
    let mem = mem.get(offset..end)?;

    // The shape of the struct is normally this:
    //
    // - length of struct
    // - value length
    // - type
    // - wide key
    // - padding to 32bits
    // - value
    //
    // The `value_length` is supposed to indicate the length of the value:
    //
    // - number of characters for the value if type == 1
    // - number of bytes for the value if type == 0
    //
    // This "type == 0" is weird, some files uses it but still put a wide string
    // in the value.
    //
    // To be as permissive as possible, we ignore value length and type: we simply
    // get the key, remove the padding, and get the value, as two wide strings.
    let key_start = HEADER_SIZE;
    if key_start > mem.len() {
        return None;
    }
    let key_end = key_start + find_wide_nul(mem.get(key_start..)?);
    let value_start = align32(key_end + 2);
    if value_start > end {
        return None;
    }
    let value_end = value_start + find_wide_nul(mem.get(value_start..)?);

    // Those are windows wide strings. We should technically:
    // - read it into a u16 slice
    // - convert it to an OsString
    // - convert it back to a String and thus a utf8 slice.
    // But yara simply strips the second byte of every pair (expecting it to always be 0). We could
    // differ here, but for the moment keep this broken behavior
    let key = unwide(&mem[key_start..key_end], 63);
    let value = unwide(&mem[value_start..value_end], 255);

    out.push(VersionInfo { key, value });

    Some(length)
}

fn find_wide_nul(mem: &[u8]) -> usize {
    let mut i = 0;
    while i + 1 < mem.len() {
        if mem[i] == b'\0' && mem[i + 1] == b'\0' {
            return i;
        }
        i += 2;
    }
    mem.len()
}

fn unwide(mem: &[u8], max_size: usize) -> Vec<u8> {
    let mut res = Vec::new();

    let mut i = 0;
    while i < mem.len() && res.len() < max_size {
        res.push(mem[i]);
        i += 2;
    }

    i = res.len();
    while i > 0 && res[i - 1] == 0 {
        i -= 1;
    }
    res.truncate(i);

    res
}

// Align offset on 32-bit boundary
const fn align32(offset: usize) -> usize {
    (offset + 3) & !3
}

#[repr(C)]
struct Header {
    length: u16,
    value_length: u16,
    typ: u16,
}

const HEADER_SIZE: usize = size_of::<Header>();

fn read_header(data: &mut Bytes) -> Option<Header> {
    Some(Header {
        length: data.read::<U16<LE>>().ok()?.get(LE),
        value_length: data.read::<U16<LE>>().ok()?.get(LE),
        typ: data.read::<U16<LE>>().ok()?.get(LE),
    })
}
