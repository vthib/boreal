use object::{Bytes, LittleEndian as LE, U16};

use super::MAX_NB_VERSION_INFOS;

pub struct VersionInfo {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub fn read_version_info(mem: &[u8], offset: usize) -> Option<Vec<VersionInfo>> {
    const VS_VERSION_INFO_KEY: &[u8] = b"V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0";

    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;
    let version_info_length = usize::from(header.length);
    let end = offset + version_info_length;
    let key = bytes.read_bytes(VS_VERSION_INFO_KEY.len()).ok()?;
    if key.0 != VS_VERSION_INFO_KEY {
        return None;
    }

    // VS_FIXEDFILEINFO is 32-bits aligned after the key.
    let offset = align32(offset + HEADER_SIZE + VS_VERSION_INFO_KEY.len());
    // Then add the length of the VS_FIXEDFILEINFO, and realign
    let mut offset = align32(offset + usize::from(header.value_length));

    // Skip VarFileInfo, if any
    while let Some(length) = read_var_file_info(mem, offset) {
        offset = align32(offset + length);
    }

    // Then read StringFileInfo
    let mut infos = Vec::new();
    while offset < end {
        if infos.len() >= MAX_NB_VERSION_INFOS {
            break;
        }

        match read_string_file_info(mem, offset, &mut infos) {
            Some(length) => offset = align32(offset + length),
            None => break,
        }
    }

    Some(infos)
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
fn read_string_file_info(mem: &[u8], offset: usize, out: &mut Vec<VersionInfo>) -> Option<usize> {
    const STRING_FILE_INFO_KEY: &[u8] = b"S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0";

    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;
    let key = bytes.read_bytes(STRING_FILE_INFO_KEY.len()).ok()?;
    if key.0 != STRING_FILE_INFO_KEY {
        return None;
    }

    let length = usize::from(header.length);
    let end = offset + length;

    // StringTable is then aligned
    let mut offset = align32(offset + HEADER_SIZE + STRING_FILE_INFO_KEY.len());

    while offset < end {
        if out.len() >= MAX_NB_VERSION_INFOS {
            break;
        }

        match read_string_table(mem, offset, out) {
            Some(length) => offset = align32(offset + length),
            None => break,
        }
    }

    Some(length)
}

// Read a StringTable. If present, return the length of the entry
fn read_string_table(mem: &[u8], offset: usize, out: &mut Vec<VersionInfo>) -> Option<usize> {
    let mut bytes = Bytes(mem);
    bytes.skip(offset).ok()?;
    let header = read_header(&mut bytes)?;

    let length = usize::from(header.length);
    let end = offset + length;

    // move to children: header, 8 byte wide string and padding
    let mut offset = align32(offset + HEADER_SIZE + 2 * 9);

    while offset < end {
        if out.len() >= MAX_NB_VERSION_INFOS {
            break;
        }

        match read_string(mem, offset, out) {
            Some(length) => offset = align32(offset + length),
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

    let length = usize::from(header.length);
    let end = offset + length;

    // We have the size for the value, hence easily getting the value.
    let value_length = usize::from(header.value_length);
    // This length is in characters, multiply by 2 to get byte length.
    let value_length = value_length * 2;
    if value_length + 6 > length {
        return None;
    }
    let value_start = end - value_length;

    // We can now get the key: its end is at the start of the value.
    // It is possibly padded, but the `unwide` helper will trim those.
    let key_start = offset + HEADER_SIZE;
    let key_end = value_start;
    if key_end <= key_start {
        return None;
    }

    // Those are windows wide strings. We should technically:
    // - read it into a u16 slice
    // - convert it to an OsString
    // - convert it back to a String and thus a utf8 slice.
    // But yara simply strips the second byte of every pair (expecting it to always be 0). We could
    // differ here, but for the moment keep this broken behavior
    let key = unwide(&mem[key_start..key_end]);
    let value = unwide(&mem[value_start..end]);

    out.push(VersionInfo { key, value });

    Some(length)
}

fn unwide(mem: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();

    let mut i = 0;
    while i < mem.len() {
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

#[derive(Copy, Clone)]
#[repr(C)]
struct Header {
    length: u16,
    value_length: u16,
    typ: u16,
}

const HEADER_SIZE: usize = std::mem::size_of::<Header>();

fn read_header(data: &mut Bytes) -> Option<Header> {
    Some(Header {
        length: data.read::<U16<LE>>().ok()?.get(LE),
        value_length: data.read::<U16<LE>>().ok()?.get(LE),
        typ: data.read::<U16<LE>>().ok()?.get(LE),
    })
}
