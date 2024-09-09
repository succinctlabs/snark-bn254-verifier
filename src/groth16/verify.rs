use anyhow::Result;
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_serialize::CanonicalDeserialize;
use bn::{AffineG1, AffineG2, Fr};
use groth16_verifier::{Groth16Proof, Groth16VerifyingKey};

pub fn convert_g1_sub_to_ark(p: AffineG1) -> G1Affine {
    let p_bytes: [u8; 64] = unsafe { std::mem::transmute(p) };
    G1Affine::deserialize_uncompressed(&p_bytes[..]).unwrap()
}

pub fn convert_g1_ark_to_sub(p: G1Affine) -> AffineG1 {
    AffineG1::new(
        bn::Fq::from_str(&p.x.to_string()).unwrap(),
        bn::Fq::from_str(&p.y.to_string()).unwrap(),
    )
    .expect("Failed to create AffineG1")
}

pub fn convert_g2_sub_to_ark(p: AffineG2) -> G2Affine {
    let p_bytes: [u8; 128] = unsafe { std::mem::transmute(p) };
    G2Affine::deserialize_uncompressed(&p_bytes[..]).unwrap()
}

pub fn convert_g2_ark_to_sub(p: G2Affine) -> AffineG2 {
    let x0 = p.x().unwrap().c0.to_string();
    let x1 = p.x().unwrap().c1.to_string();
    let y0 = p.y().unwrap().c0.to_string();
    let y1 = p.y().unwrap().c1.to_string();
    AffineG2::new(
        bn::Fq2::new(
            bn::Fq::from_str(&x0).unwrap(),
            bn::Fq::from_str(&x1).unwrap(),
        ),
        bn::Fq2::new(
            bn::Fq::from_str(&y0).unwrap(),
            bn::Fq::from_str(&y1).unwrap(),
        ),
    )
    .expect("Failed to create AffineG2")
}

pub fn convert_fr_sub_to_ark(p: Fr) -> ark_bn254::Fr {
    let mut bytes = [0u8; 32];
    p.to_big_endian(&mut bytes).unwrap();
    bytes.reverse();
    unsafe { std::mem::transmute::<[u8; 32], ark_bn254::Fr>(bytes) }
}

pub fn verify_groth16(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool> {
    Ok(groth16_verifier::verify_groth16(vk, proof, public_inputs)?)
}
