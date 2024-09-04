use anyhow::Result;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{fields::PrimeField, BigInt, BigInteger};
use ark_groth16::{Groth16, Proof as ArkGroth16Proof, VerifyingKey as ArkGroth16VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use num_bigint::{BigUint, Sign};
use substrate_bn::{AffineG1, AffineG2, Fr};

use super::Groth16Proof;

#[allow(dead_code)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: AffineG1,
    pub(crate) beta: AffineG1,
    pub(crate) delta: AffineG1,
    pub(crate) k: Vec<AffineG1>,
}

#[derive(Debug)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: AffineG2,
    pub(crate) delta: AffineG2,
    pub(crate) gamma: AffineG2,
}

#[allow(dead_code)]
pub(crate) struct PedersenVerifyingKey {
    pub(crate) g: AffineG2,
    pub(crate) g_root_sigma_neg: AffineG2,
}

#[allow(dead_code)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
    pub(crate) commitment_key: PedersenVerifyingKey,
    pub(crate) public_and_commitment_committed: Vec<Vec<u32>>,
}

pub fn convert_g1_sub_to_ark(p: AffineG1) -> G1Affine {
    let p_bytes: [u8; 64] = unsafe { std::mem::transmute(p) };
    println!("p_bytes: {:?}", p_bytes);
    G1Affine::deserialize_uncompressed(&p_bytes[..]).unwrap()
}

pub fn convert_g1_ark_to_sub(p: G1Affine) -> AffineG1 {
    AffineG1::new(
        substrate_bn::Fq::from_str(&p.x.to_string()).unwrap(),
        substrate_bn::Fq::from_str(&p.y.to_string()).unwrap(),
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
        substrate_bn::Fq2::new(
            substrate_bn::Fq::from_str(&x0).unwrap(),
            substrate_bn::Fq::from_str(&x1).unwrap(),
        ),
        substrate_bn::Fq2::new(
            substrate_bn::Fq::from_str(&y0).unwrap(),
            substrate_bn::Fq::from_str(&y1).unwrap(),
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
    let proof: ArkGroth16Proof<Bn254> = ArkGroth16Proof {
        a: convert_g1_sub_to_ark(proof.ar),
        b: convert_g2_sub_to_ark(proof.bs),
        c: convert_g1_sub_to_ark(proof.krs),
    };
    let vk: ArkGroth16VerifyingKey<Bn254> = ArkGroth16VerifyingKey {
        alpha_g1: convert_g1_sub_to_ark(vk.g1.alpha),
        beta_g2: convert_g2_sub_to_ark(vk.g2.beta),
        gamma_g2: convert_g2_sub_to_ark(vk.g2.gamma),
        delta_g2: convert_g2_sub_to_ark(vk.g2.delta),
        gamma_abc_g1: vk.g1.k.iter().map(|p| convert_g1_sub_to_ark(*p)).collect(),
    };

    let pvk = Groth16::<Bn254>::process_vk(&vk)?;

    Ok(Groth16::<Bn254>::verify_with_processed_vk(
        &pvk,
        public_inputs
            .iter()
            .map(|p| convert_fr_sub_to_ark(*p))
            .collect::<Vec<ark_bn254::Fr>>()
            .as_slice(),
        &proof,
    )?)
}
