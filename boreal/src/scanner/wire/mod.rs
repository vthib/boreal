#![allow(clippy::cast_possible_truncation)]

const VERSION: u32 = 0;

mod ser;
pub use ser::serialize_scanner;

mod de;
pub use de::deserialize_scanner;
