//! Functions related to base64 encoding for yara strings
//!
//! Note that we cannot use existing crates for those encodings for two reasons:
//! - The dictionaries that can be used in yara rules do not have to be "valid" dictionaries, ie
//!   they do not have to be decodable. For example, using "A"*64 has a dictionary is possible,
//!   but every crate will refuse to use this dictionary.
//! - The cutting of leading/trailing bytes can be optimized in a better way with a custom function
//!   rather than using a dependency, then cutting the resulting string. Granted, this is not a
//!   huge deal.
//!
//! In addition, we only encode those strings once, when compiling the rule. Therefore, performance
//! of this encoding is negligible and doing it by hand with naive functions is good enough.
const DEFAULT_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode a given byte string in base64, ignoring padding.
///
/// Offset can be provided to offset the encoded string with a given amount of leading padding
/// characters.
///
/// How this work is that every byte from the resulting base64 string that is involved with
/// padding is removed from the returned value.
pub fn encode_base64(s: &[u8], alphabet: Option<&[u8; 64]>, offset: usize) -> Option<Vec<u8>> {
    let alphabet = alphabet.unwrap_or(DEFAULT_ALPHABET);

    let mut res = Vec::with_capacity(s.len() * 4 / 3);

    let chunks_offset = match offset % 3 {
        1 => {
            // We want to encode [0, s[0], s[1], ...].
            // This only gives 2 valid encoded bytes out of the 4.
            if s.len() < 2 {
                return None;
            }
            let v: u32 = (u32::from(s[0]) << 8) | u32::from(s[1]);
            res.push(alphabet[((v >> 6) & 0x3F) as usize]);
            res.push(alphabet[(v & 0x3F) as usize]);
            // Continue encoding the string normally, starting from s[2]
            2
        }
        2 => {
            // We want to encode [0, 0, s[0], ...].
            // This only gives 1 valid encoded byte out of the 4.
            if s.is_empty() {
                return None;
            }
            res.push(alphabet[(s[0] & 0x3F) as usize]);
            // Continue encoding the string normally, starting from s[1]
            1
        }
        _ => 0,
    };

    let mut iter = s[chunks_offset..].chunks_exact(3);
    for chunk in &mut iter {
        let v: u32 = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);

        res.push(alphabet[((v >> 18) & 0x3F) as usize]);
        res.push(alphabet[((v >> 12) & 0x3F) as usize]);
        res.push(alphabet[((v >> 6) & 0x3F) as usize]);
        res.push(alphabet[(v & 0x3F) as usize]);
    }

    match iter.remainder() {
        [a] => {
            // We have to encode [a, 0, 0]. This only gives 1 valid encoded byte out of the 4.
            res.push(alphabet[((*a >> 2) & 0x3F) as usize]);
        }
        [a, b] => {
            // We have to encode [a, b, 0]. This only gives 2 valid encoded byte out of the 4.
            let v: u32 = (u32::from(*a) << 8) | u32::from(*b);
            res.push(alphabet[((v >> 10) & 0x3F) as usize]);
            res.push(alphabet[((v >> 4) & 0x3F) as usize]);
        }
        _ => (),
    }
    Some(res)
}
