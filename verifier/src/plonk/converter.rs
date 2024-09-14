use bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G2};
use core::cmp::Ordering;

use crate::{
    constants::{CompressedPointFlag, MASK},
    converter::is_zeroed,
    error::Error,
};

use super::{
    error::PlonkError,
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    verify::PlonkVerifyingKey,
    PlonkProof,
};

fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag), PlonkError> {
    if buf.len() != 32 {
        return Err(PlonkError::InvalidXLength);
    };

    let m_data = buf[0] & MASK;
    if m_data == CompressedPointFlag::Infinity.into() {
        if !is_zeroed(buf[0] & !MASK, &buf[1..32]).map_err(PlonkError::GeneralError)? {
            return Err(PlonkError::GeneralError(Error::InvalidPoint));
        }
        Ok((Fq::zero(), CompressedPointFlag::Infinity))
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes).expect("Failed to convert x bytes to Fq");

        Ok((x, CompressedPointFlag::from(m_data)))
    }
}

fn compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1, PlonkError> {
    let (x, m_data) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x)
        .ok_or(PlonkError::GeneralError(Error::InvalidPoint))?;

    let mut final_y = y;
    if y.cmp(&neg_y) == Ordering::Greater {
        if m_data == CompressedPointFlag::Positive {
            final_y = -y;
        }
    } else {
        if m_data == CompressedPointFlag::Negative {
            final_y = -y;
        }
    }

    Ok(AffineG1::new(x, final_y).map_err(|e| PlonkError::GeneralError(Error::GroupError(e)))?)
}

fn compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2, PlonkError> {
    if buf.len() != 64 {
        return Err(PlonkError::GeneralError(Error::InvalidXLength));
    };

    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64])
        .map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;
    let x = Fq2::new(x0, x1);

    if flag == CompressedPointFlag::Infinity {
        return Ok(AffineG2::one());
    }

    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x)
        .ok_or(PlonkError::GeneralError(Error::InvalidPoint))?;

    match flag {
        CompressedPointFlag::Positive => {
            Ok(AffineG2::new(x, y).map_err(|e| PlonkError::GeneralError(Error::GroupError(e)))?)
        }
        CompressedPointFlag::Negative => {
            Ok(AffineG2::new(x, neg_y)
                .map_err(|e| PlonkError::GeneralError(Error::GroupError(e)))?)
        }
        _ => Err(PlonkError::GeneralError(Error::InvalidPoint)),
    }
}

pub fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1, PlonkError> {
    if buf.len() != 64 {
        return Err(PlonkError::GeneralError(Error::InvalidXLength));
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;
    let y = Fq::from_slice(y_bytes).map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;
    let p = AffineG1::new(x, y).map_err(|e| PlonkError::GeneralError(Error::GroupError(e)))?;

    Ok(p)
}

pub(crate) fn load_plonk_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<PlonkVerifyingKey, PlonkError> {
    let size = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]) as usize;
    let size_inv = Fr::from_slice(&buffer[8..40])
        .map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;
    let generator = Fr::from_slice(&buffer[40..72])
        .map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;

    let nb_public_variables = u64::from_be_bytes([
        buffer[72], buffer[73], buffer[74], buffer[75], buffer[76], buffer[77], buffer[78],
        buffer[79],
    ]) as usize;

    let coset_shift = Fr::from_slice(&buffer[80..112])
        .map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;
    let s0 = compressed_x_to_g1_point(&buffer[112..144])?;
    let s1 = compressed_x_to_g1_point(&buffer[144..176])?;
    let s2 = compressed_x_to_g1_point(&buffer[176..208])?;
    let ql = compressed_x_to_g1_point(&buffer[208..240])?;
    let qr = compressed_x_to_g1_point(&buffer[240..272])?;
    let qm = compressed_x_to_g1_point(&buffer[272..304])?;
    let qo = compressed_x_to_g1_point(&buffer[304..336])?;
    let qk = compressed_x_to_g1_point(&buffer[336..368])?;
    let num_qcp = u32::from_be_bytes([buffer[368], buffer[369], buffer[370], buffer[371]]);
    let mut qcp = Vec::new();
    let mut offset = 372;

    for _ in 0..num_qcp {
        let point = compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        qcp.push(point);
        offset += 32;
    }

    let g1 = compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
    let g2_0 = compressed_x_to_g2_point(&buffer[offset + 32..offset + 96])?;
    let g2_1 = compressed_x_to_g2_point(&buffer[offset + 96..offset + 160])?;

    offset += 160 + 33788;

    let num_commitment_constraint_indexes = u64::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]) as usize;

    let mut commitment_constraint_indexes = Vec::new();
    offset += 8;
    for _ in 0..num_commitment_constraint_indexes {
        let index = u64::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]) as usize;
        commitment_constraint_indexes.push(index);
        offset += 8;
    }

    let result = PlonkVerifyingKey {
        size,
        size_inv,
        generator,
        nb_public_variables,
        kzg: kzg::KZGVerifyingKey {
            g2: [G2::from(g2_0), G2::from(g2_1)],
            g1: g1.into(),
            lines: [[[LineEvaluationAff {
                r0: E2 {
                    a0: Fr::zero(),
                    a1: Fr::zero(),
                },
                r1: E2 {
                    a0: Fr::zero(),
                    a1: Fr::zero(),
                },
            }; 66]; 2]; 2],
        },
        coset_shift,
        s: [s0, s1, s2],
        ql,
        qr,
        qm,
        qo,
        qk,
        qcp,
        commitment_constraint_indexes,
    };

    Ok(result)
}

pub(crate) fn load_plonk_proof_from_bytes(buffer: &[u8]) -> Result<PlonkProof, PlonkError> {
    let lro0 = uncompressed_bytes_to_g1_point(&buffer[..64])?;
    let lro1 = uncompressed_bytes_to_g1_point(&buffer[64..128])?;
    let lro2 = uncompressed_bytes_to_g1_point(&buffer[128..192])?;
    let z = uncompressed_bytes_to_g1_point(&buffer[192..256])?;
    let h0 = uncompressed_bytes_to_g1_point(&buffer[256..320])?;
    let h1 = uncompressed_bytes_to_g1_point(&buffer[320..384])?;
    let h2 = uncompressed_bytes_to_g1_point(&buffer[384..448])?;
    let batched_proof_h = uncompressed_bytes_to_g1_point(&buffer[448..512])?;

    let num_claimed_values =
        u32::from_be_bytes([buffer[512], buffer[513], buffer[514], buffer[515]]) as usize;

    let mut claimed_values = Vec::new();
    let mut offset = 516;
    for _ in 0..num_claimed_values {
        let value = Fr::from_slice(&buffer[offset..offset + 32])
            .map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;
        claimed_values.push(value);
        offset += 32;
    }

    let z_shifted_opening_h = uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
    let z_shifted_opening_value = Fr::from_slice(&buffer[offset + 64..offset + 96])
        .map_err(|e| PlonkError::GeneralError(Error::FieldError(e)))?;

    let num_bsb22_commitments = u32::from_be_bytes([
        buffer[offset + 96],
        buffer[offset + 97],
        buffer[offset + 98],
        buffer[offset + 99],
    ]) as usize;

    let mut bsb22_commitments = Vec::new();
    offset += 100;
    for _ in 0..num_bsb22_commitments {
        let commitment = uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
        bsb22_commitments.push(commitment);
        offset += 64;
    }

    let result = PlonkProof {
        lro: [lro0, lro1, lro2],
        z,
        h: [h0, h1, h2],
        bsb22_commitments,
        batched_proof: BatchOpeningProof {
            h: batched_proof_h,
            claimed_values,
        },
        z_shifted_opening: OpeningProof {
            h: z_shifted_opening_h,
            claimed_value: z_shifted_opening_value,
        },
    };

    Ok(result)
}

pub(crate) fn g1_to_bytes(g1: &AffineG1) -> Result<Vec<u8>, PlonkError> {
    let mut bytes: [u8; 64] = unsafe { core::mem::transmute(*g1) };
    bytes[..32].reverse();
    bytes[32..].reverse();
    Ok(bytes.to_vec())
}