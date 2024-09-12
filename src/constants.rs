pub(crate) const GAMMA: &str = "gamma";
pub(crate) const BETA: &str = "beta";
pub(crate) const ALPHA: &str = "alpha";
pub(crate) const ZETA: &str = "zeta";

pub const MASK: u8 = 0b11 << 6;
pub const COMPRESSED_POSTIVE: u8 = 0b10 << 6;
pub const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub const COMPRESSED_INFINITY: u8 = 0b01 << 6;

pub const SUBSTRATE_MASK: u8 = 0b11 << 6;
pub const SUBSTRATE_COMPRESSED_POSTIVE: u8 = 0b00 << 6;
pub const SUBSTRATE_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
pub const SUBSTRATE_COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(Debug, PartialEq, Eq)]
pub enum CompressedPointFlag {
    Positive = COMPRESSED_POSTIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

impl Into<u8> for CompressedPointFlag {
    fn into(self) -> u8 {
        self as u8
    }
}

impl From<u8> for CompressedPointFlag {
    fn from(value: u8) -> Self {
        match value {
            COMPRESSED_POSTIVE => CompressedPointFlag::Positive,
            COMPRESSED_NEGATIVE => CompressedPointFlag::Negative,
            COMPRESSED_INFINITY => CompressedPointFlag::Infinity,
            _ => panic!("Invalid compressed point flag"),
        }
    }
}

#[derive(Debug)]
pub enum SerializationError {
    InvalidData,
}

impl core::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SerializationError::InvalidData => write!(f, "Invalid data"),
        }
    }
}
