use bitflags::bitflags;

use crate::expression::Expression;
use crate::hex_string::HexString;
use crate::regex::Regex;

/// A Yara rule.
#[derive(Debug, PartialEq)]
pub struct Rule {
    /// Name of the rule.
    pub name: String,

    /// Tags associated with the rule
    pub tags: Vec<String>,

    /// Metadata associated with the rule.
    pub metadatas: Vec<Metadata>,

    /// Strings associated with the rule.
    pub strings: Vec<StringDeclaration>,

    /// Condition of the rule.
    pub condition: Expression,

    // Is the rule private.
    pub is_private: bool,
    // Is the rule global.
    pub is_global: bool,
}

/// Value associated with a metadata key.
#[derive(Debug, PartialEq)]
pub enum MetadataValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

/// A metadata key-value, associated with a rule.
#[derive(Debug, PartialEq)]
pub struct Metadata {
    /// Name of the metadata.
    pub name: String,
    /// Value of the metadata.
    pub value: MetadataValue,
}

bitflags! {
    pub struct StringFlags: u32 {
        const WIDE = 0b0000_0001;
        const ASCII = 0b000_0010;
        const NOCASE = 0b0000_0100;
        const FULLWORD = 0b0000_1000;
        const PRIVATE = 0b0001_0000;
        const XOR = 0b0010_0000;
        const BASE64 = 0b0100_0000;
        const BASE64WIDE = 0b1000_0000;
    }
}

/// Value for a string associated with a rule.
#[derive(Debug, PartialEq)]
pub enum StringDeclarationValue {
    /// A raw string.
    String(String),
    /// A regular expression.
    Regex(Regex),
    /// A hex string.
    HexString(HexString),
}

/// String declared in a rule.
#[derive(Debug, PartialEq)]
pub struct StringDeclaration {
    /// Name of the string.
    pub name: String,
    /// Value of the string.
    pub value: StringDeclarationValue,
    /// Modifiers for the string. This is a bitflags field.
    pub modifiers: StringFlags,
}
