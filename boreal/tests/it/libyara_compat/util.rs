use const_format::concatcp;

pub const TEXT_0063_BYTES: &str = "[ 987654321 987654321 987654321 987654321 987654321 987654321 ]";
pub const TEXT_0256_BYTES_001: &str = concatcp!(
    "001",
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    "\n"
);
pub const TEXT_0256_BYTES_002: &str = concatcp!(
    "002",
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    "\n"
);
pub const TEXT_0256_BYTES_003: &str = concatcp!(
    "003",
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    "\n"
);
pub const TEXT_0256_BYTES_004: &str = concatcp!(
    "004",
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    TEXT_0063_BYTES,
    "\n"
);
pub const TEXT_1024_BYTES: &str = concatcp!(
    TEXT_0256_BYTES_001,
    TEXT_0256_BYTES_002,
    TEXT_0256_BYTES_003,
    TEXT_0256_BYTES_004
);
