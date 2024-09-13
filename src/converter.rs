use crate::error::Error;

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
