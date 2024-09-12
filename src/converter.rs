use alloc::string::String;
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use core::fmt::Write;

use crate::constants::{
    COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSTIVE, MASK,
    SUBSTRATE_COMPRESSED_INFINITY, SUBSTRATE_COMPRESSED_NEGATIVE, SUBSTRATE_COMPRESSED_POSTIVE,
    SUBSTRATE_MASK,
};
use crate::error::Error;

pub fn to_bn_flag(msb: u8) -> Result<u8> {
    let flag = msb & MASK;

    let bn_flag = match flag {
        COMPRESSED_POSTIVE => SUBSTRATE_COMPRESSED_POSTIVE,
        COMPRESSED_NEGATIVE => SUBSTRATE_COMPRESSED_NEGATIVE,
        COMPRESSED_INFINITY => SUBSTRATE_COMPRESSED_INFINITY,
        _ => {
            let mut err_msg = String::new();
            write!(err_msg, "{}: {}", Error::UnexpectedFlag, flag).unwrap();
            return Err(anyhow!(err_msg));
        }
    };

    Ok(msb & !SUBSTRATE_MASK | bn_flag)
}

/// Convert big-endian compressed x bytes to litte-endian compressed x for g1 and g2 point
pub fn to_compressed_x(x: &[u8]) -> Result<Vec<u8>> {
    if x.len() != 32 && x.len() != 64 {
        let mut err_msg = String::new();
        write!(err_msg, "{}: {}", Error::InvalidXLength, x.len()).unwrap();
        return Err(anyhow!(err_msg));
    }
    let mut x_copy = x.to_vec();

    let msb = to_bn_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

pub fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool> {
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
