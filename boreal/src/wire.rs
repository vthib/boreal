use std::io;

use borsh::{BorshDeserialize as BD, BorshSerialize};

use crate::module::StaticValue;

const VERSION: u32 = 0;

pub(crate) struct DeserializeContext {
    pub(crate) modules_static_values: Vec<StaticValue>,
}

pub(crate) fn serialize_header<W: io::Write>(kind: [u8; 4], writer: &mut W) -> io::Result<()> {
    let magic: [u8; 12] = *b"boreal_wire_";
    magic.serialize(writer)?;
    kind.serialize(writer)?;
    VERSION.serialize(writer)?;
    Ok(())
}

pub(super) fn deserialize_header<R: io::Read>(
    expected_kind: [u8; 4],
    reader: &mut R,
) -> io::Result<()> {
    let magic: [u8; 12] = BD::deserialize_reader(reader)?;
    if &magic != b"boreal_wire_" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid magic: {:x?}", &magic),
        ));
    }
    let kind: [u8; 4] = BD::deserialize_reader(reader)?;
    if kind != expected_kind {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid kind: {:x?}", &kind),
        ));
    }
    let version: u32 = BD::deserialize_reader(reader)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown version {version}"),
        ));
    }
    Ok(())
}
