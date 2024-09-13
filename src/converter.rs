use crate::constants::{
    COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSTIVE, MASK,
    SUBSTRATE_COMPRESSED_INFINITY, SUBSTRATE_COMPRESSED_NEGATIVE, SUBSTRATE_COMPRESSED_POSTIVE,
    SUBSTRATE_MASK,
};
use crate::error::Error;

pub fn to_bn_flag(msb: u8) -> Result<u8, Error> {
    let flag = msb & MASK;

    let bn_flag = match flag {
        COMPRESSED_POSTIVE => SUBSTRATE_COMPRESSED_POSTIVE,
        COMPRESSED_NEGATIVE => SUBSTRATE_COMPRESSED_NEGATIVE,
        COMPRESSED_INFINITY => SUBSTRATE_COMPRESSED_INFINITY,
        _ => {
            return Err(Error::UnexpectedFlag);
        }
    };

    Ok(msb & !SUBSTRATE_MASK | bn_flag)
}

/// Convert big-endian compressed x bytes to litte-endian compressed x for g1 and g2 point
pub fn to_compressed_x(x: &[u8]) -> Result<Vec<u8>, Error> {
    if x.len() != 32 && x.len() != 64 {
        return Err(Error::InvalidXLength);
    }

    let mut x_copy = x.to_vec();
    let msb = to_bn_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

pub fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool, Error> {
    if first_byte != 0 {
        return Ok(false);
    }
    for &b in buf {
        if b != 0 {
            return Ok(false);
        }
    }

    Ok(true)
}
