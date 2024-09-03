use anyhow::{anyhow, Error, Result};
use ark_serialize::SerializationError;
use std::cmp::Ordering;
use std::ops::Neg;
use substrate_bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G2};

use crate::{
    constants::{
        GNARK_COMPRESSED_INFINITY, GNARK_COMPRESSED_NEGATIVE, GNARK_COMPRESSED_POSTIVE, GNARK_MASK,
    },
    converter::{gnark_commpressed_x_to_ark_commpressed_x, is_zeroed},
};

use super::{
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    verify::PlonkVerifyingKey,
    PlonkProof,
};

fn gnark_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    if buf.len() != 32 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let m_data = buf[0] & GNARK_MASK;
    if m_data == GNARK_COMPRESSED_INFINITY {
        if !is_zeroed(buf[0] & !GNARK_MASK, &buf[1..32])? {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok(AffineG1::one())
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !GNARK_MASK;

        let x = Fq::from_slice(&x_bytes.to_vec()).map_err(Error::msg)?;
        let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x)
            .ok_or(SerializationError::InvalidData)
            .map_err(Error::msg)?;

        let mut final_y = y;
        if y.cmp(&neg_y) == Ordering::Greater {
            if m_data == GNARK_COMPRESSED_POSTIVE {
                final_y = y.neg();
            }
        } else {
            if m_data == GNARK_COMPRESSED_NEGATIVE {
                final_y = y.neg();
            }
        }

        let p = AffineG1::new(x, final_y).map_err(Error::msg)?;

        Ok(p)
    }
}

fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2> {
    println!("Entering gnark_compressed_x_to_g2_point function");

    println!("Checking buffer length");
    if buf.len() != 64 {
        println!("Buffer length is not 64, returning error");
        return Err(anyhow!(SerializationError::InvalidData));
    };

    println!("Converting gnark compressed x to ark compressed x");
    let bytes = gnark_commpressed_x_to_ark_commpressed_x(&buf.to_vec())?;

    println!("Deserializing compressed bytes to AffineG2");
    let p = AffineG2::deserialize_compressed(&bytes).map_err(Error::msg)?;
    println!("AffineG2 point: {:?}", p);

    println!("Returning AffineG2 point");
    Ok(p)
}

pub fn gnark_uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(&x_bytes.to_vec()).map_err(Error::msg)?;
    let y = Fq::from_slice(&y_bytes.to_vec()).map_err(Error::msg)?;
    let p = AffineG1::new(x, y).map_err(Error::msg)?;

    Ok(p)
}

pub(crate) fn load_plonk_verifying_key_from_bytes(buffer: &[u8]) -> Result<PlonkVerifyingKey> {
    println!("Starting load_plonk_verifying_key_from_bytes");

    // Extracting size from the buffer
    let size = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]) as usize;
    println!("Extracted size: {}", size);

    // Extracting size inversion from the buffer
    let size_inv = Fr::from_slice(&buffer[8..40]).map_err(Error::msg)?;
    println!("Extracted size_inv: {:?}", size_inv);

    // Extracting generator from the buffer
    let generator = Fr::from_slice(&buffer[40..72]).map_err(|err| anyhow!("{err:?}"))?;
    println!("Extracted generator: {:?}", generator);

    // Extracting number of public variables from the buffer
    let nb_public_variables = u64::from_be_bytes([
        buffer[72], buffer[73], buffer[74], buffer[75], buffer[76], buffer[77], buffer[78],
        buffer[79],
    ]) as usize;
    println!("Extracted nb_public_variables: {}", nb_public_variables);

    // Extracting coset shift from the buffer
    let coset_shift = Fr::from_slice(&buffer[80..112]).map_err(|err| anyhow!("{err:?}"))?;
    println!("Extracted coset_shift: {:?}", coset_shift);

    // Extracting s0 from the buffer
    let s0 = gnark_compressed_x_to_g1_point(&buffer[112..144])?;
    println!("Extracted s0: {:?}", s0);

    // Extracting s1 from the buffer
    let s1 = gnark_compressed_x_to_g1_point(&buffer[144..176])?;
    println!("Extracted s1: {:?}", s1);

    // Extracting s2 from the buffer
    let s2 = gnark_compressed_x_to_g1_point(&buffer[176..208])?;
    println!("Extracted s2: {:?}", s2);

    // Extracting ql from the buffer
    let ql = gnark_compressed_x_to_g1_point(&buffer[208..240])?;
    println!("Extracted ql: {:?}", ql);

    // Extracting qr from the buffer
    let qr = gnark_compressed_x_to_g1_point(&buffer[240..272])?;
    println!("Extracted qr: {:?}", qr);

    // Extracting qm from the buffer
    let qm = gnark_compressed_x_to_g1_point(&buffer[272..304])?;
    println!("Extracted qm: {:?}", qm);

    // Extracting qo from the buffer
    let qo = gnark_compressed_x_to_g1_point(&buffer[304..336])?;
    println!("Extracted qo: {:?}", qo);

    // Extracting qk from the buffer
    let qk = gnark_compressed_x_to_g1_point(&buffer[336..368])?;
    println!("Extracted qk: {:?}", qk);

    // Extracting number of quadratic constraints from the buffer
    let num_qcp = u32::from_be_bytes([buffer[368], buffer[369], buffer[370], buffer[371]]);
    println!("Extracted num_qcp: {}", num_qcp);

    let mut qcp = Vec::new();
    let mut offset = 372;
    for i in 0..num_qcp {
        // Extracting quadratic constraint points from the buffer
        let point = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        println!("Extracted qcp[{}]: {:?}", i, point);
        qcp.push(point);
        offset += 32;
    }

    let g1 = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
    println!("Extracted g1: {:?}", g1);

    let g2_0 = gnark_compressed_x_to_g2_point(&buffer[offset + 32..offset + 96])?;
    println!("Extracted g2_0: {:?}", g2_0);

    let g2_1 = gnark_compressed_x_to_g2_point(&buffer[offset + 96..offset + 160])?;
    println!("Extracted g2_1: {:?}", g2_1);

    // Skip 33788 bytes
    offset += 160 + 33788;
    println!("Skipped 33788 bytes, new offset: {}", offset);

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
    println!(
        "Extracted num_commitment_constraint_indexes: {}",
        num_commitment_constraint_indexes
    );

    let mut commitment_constraint_indexes = Vec::new();
    offset += 8;
    for i in 0..num_commitment_constraint_indexes {
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
        println!("Extracted commitment_constraint_indexes[{}]: {}", i, index);
        commitment_constraint_indexes.push(index);
        offset += 8;
    }

    println!("Creating PlonkVerifyingKey");
    Ok(PlonkVerifyingKey {
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
    })
}

pub(crate) fn load_plonk_proof_from_bytes(buffer: &[u8]) -> Result<PlonkProof> {
    let lro0 = gnark_uncompressed_bytes_to_g1_point(&buffer[..64])?;
    let lro1 = gnark_uncompressed_bytes_to_g1_point(&buffer[64..128])?;
    let lro2 = gnark_uncompressed_bytes_to_g1_point(&buffer[128..192])?;

    let z = gnark_uncompressed_bytes_to_g1_point(&buffer[192..256])?;

    let h0 = gnark_uncompressed_bytes_to_g1_point(&buffer[256..320])?;
    let h1 = gnark_uncompressed_bytes_to_g1_point(&buffer[320..384])?;
    let h2 = gnark_uncompressed_bytes_to_g1_point(&buffer[384..448])?;

    let batched_proof_h = gnark_uncompressed_bytes_to_g1_point(&buffer[448..512])?;

    let num_claimed_values =
        u32::from_be_bytes([buffer[512], buffer[513], buffer[514], buffer[515]]) as usize;

    let mut claimed_values = Vec::new();
    let mut offset = 516;
    for _ in 0..num_claimed_values {
        let value = Fr::from_slice(&buffer[offset..offset + 32]).map_err(Error::msg)?;
        claimed_values.push(value);
        offset += 32;
    }

    let z_shifted_opening_h = gnark_uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
    let z_shifted_opening_value =
        Fr::from_slice(&buffer[offset + 64..offset + 96]).map_err(Error::msg)?;

    let num_bsb22_commitments = u32::from_be_bytes([
        buffer[offset + 96],
        buffer[offset + 97],
        buffer[offset + 98],
        buffer[offset + 99],
    ]) as usize;
    let mut bsb22_commitments = Vec::new();
    offset += 100;
    for _ in 0..num_bsb22_commitments {
        let commitment = gnark_uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
        bsb22_commitments.push(commitment);
        offset += 64;
    }

    Ok(PlonkProof {
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
    })
}

pub(crate) fn g1_to_bytes(g1: &AffineG1) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    g1.x()
        .to_big_endian(&mut bytes)
        .map_err(|err| anyhow!("{err:?}"))?;
    g1.y()
        .to_big_endian(&mut bytes)
        .map_err(|err| anyhow!("{err:?}"))?;
    Ok(bytes)
}
