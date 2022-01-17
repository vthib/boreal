/// A token in an hex string.
#[derive(Debug, PartialEq)]
pub enum HexToken {
    /// A fully declared byte, eg `9C`
    Byte(u8),
    /// A masked byte, eg `?5`, `C?`, `??`
    MaskedByte(u8, Mask),
    /// A jump of unknown bytes, eg `[5-10]`, `[3-]`, ...
    Jump(Jump),
    /// Two possible list of tokens, eg `( 12 34 | 98 76 )`
    Alternatives(Vec<HexToken>, Vec<HexToken>),
}
pub type HexString = Vec<HexToken>;

/// Mask on a byte.
#[derive(Debug, PartialEq)]
pub enum Mask {
    /// The left part is masked, ie ?X
    Left,
    /// The right part is masked, ie X?
    Right,
    /// Both parts are masked, ie ??
    All,
}

/// A jump range, which can be expressed in multiple ways:
///
/// - `[a-b]` means between `a` and `b`, inclusive.
/// - `[-b]` is equivalent to `[0-b]`.
/// - `[a-]` means `a` or more.
/// - `[-]` is equivalent to `[0-]`.
/// - `[a]` is equivalent to `[a-a]`.
#[derive(Debug, PartialEq)]
pub struct Jump {
    /// Beginning of the range, included.
    pub from: u32,
    /// Optional end of the range, included.
    pub to: Option<u32>,
}
