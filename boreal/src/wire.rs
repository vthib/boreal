use std::io;

pub use borsh::BorshDeserialize as Deserialize;
pub use borsh::BorshSerialize as Serialize;

use crate::module::StaticValue;

const VERSION: u32 = 0;

#[derive(Default)]
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
    let magic = <[u8; 12]>::deserialize_reader(reader)?;
    if &magic != b"boreal_wire_" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid magic: {:x?}", &magic),
        ));
    }
    let kind = <[u8; 4]>::deserialize_reader(reader)?;
    if kind != expected_kind {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid kind: {:x?}", &kind),
        ));
    }
    let version = u32::deserialize_reader(reader)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown version {version}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt::Debug;

    use super::*;

    // Test that a round trip through serialization yields the same object.
    //
    // The second parameter is a list of offsets at which if the serialized buffer
    // is truncated, the serialization will fail. This is useful to test proper error
    // propagation when failing to deserialize each field.
    #[track_caller]
    pub(crate) fn test_round_trip<T: Serialize + Deserialize + PartialEq + Debug>(
        v: &T,
        truncate_offset_errors: &[usize],
    ) {
        test_round_trip_custom_deser(
            v,
            |reader| T::deserialize_reader(reader),
            truncate_offset_errors,
        );
    }

    #[track_caller]
    pub(crate) fn test_round_trip_custom_deser<T, F>(
        v: &T,
        deser: F,
        truncate_offset_errors: &[usize],
    ) where
        T: Serialize + PartialEq + Debug,
        F: Fn(&mut io::Cursor<&[u8]>) -> io::Result<T>,
    {
        for offset in truncate_offset_errors {
            let mut buf = vec![0_u8; *offset];
            let mut s: &mut [u8] = &mut buf[..];
            assert!(v.serialize(&mut s).is_err());
        }

        let mut buf = Vec::new();
        v.serialize(&mut buf).unwrap();

        for offset in truncate_offset_errors {
            let mut cursor = io::Cursor::new(&buf[..*offset]);
            assert!((deser)(&mut cursor).is_err());
        }

        let mut cursor = io::Cursor::new(&*buf);
        let v2 = (deser)(&mut cursor).unwrap();
        assert_eq!(v, &v2);
    }

    pub(crate) fn test_invalid_deserialization<T: Deserialize>(mut buf: &[u8]) {
        assert!(T::deserialize(&mut buf).is_err());
    }

    #[test]
    fn test_wire_header() {
        let mut buf = [0; 16];
        assert!(serialize_header(*b"toto", &mut &mut buf[..0]).is_err());
        assert!(serialize_header(*b"toto", &mut &mut buf[..13]).is_err());
        assert!(serialize_header(*b"toto", &mut &mut buf[..16]).is_err());
        let mut buf = Vec::new();
        serialize_header(*b"toto", &mut buf).unwrap();
        assert!(buf.starts_with(b"boreal_wire_toto"));

        assert!(deserialize_header(*b"toto", &mut io::Cursor::new(&buf[..0])).is_err());
        assert!(deserialize_header(*b"toto", &mut io::Cursor::new(&buf[..13])).is_err());
        assert!(deserialize_header(*b"toto", &mut io::Cursor::new(&buf[..16])).is_err());
        deserialize_header(*b"toto", &mut io::Cursor::new(&buf)).unwrap();

        // invalid magic
        assert!(deserialize_header(
            *b"toto",
            &mut io::Cursor::new(b"wire_boreal_toto\x00\x00\x00\x00")
        )
        .is_err());
        // invalid kind
        assert!(deserialize_header(
            *b"toto",
            &mut io::Cursor::new(b"boreal_wire_nkgm\x00\x00\x00\x00")
        )
        .is_err());
        // unknown version
        assert!(deserialize_header(
            *b"toto",
            &mut io::Cursor::new(b"boreal_wire_toto\xCC\x00\x00\x00")
        )
        .is_err());
    }
}
