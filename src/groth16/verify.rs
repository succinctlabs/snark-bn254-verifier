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
    println!("cycle-tracker-start: convert_g1_ark_to_sub");
    let out = AffineG1::new(
        bn::Fq::from_str(&p.x.to_string()).unwrap(),
        bn::Fq::from_str(&p.y.to_string()).unwrap(),
    )
    .expect("Failed to create AffineG1");
    println!("cycle-tracker-end: convert_g1_ark_to_sub");
    out
}

pub fn convert_g2_sub_to_ark(p: AffineG2) -> G2Affine {
    println!("cycle-tracker-start: convert_g2_sub_to_ark");
    let p_bytes: [u8; 128] = unsafe { std::mem::transmute(p) };
    let out = G2Affine::deserialize_uncompressed(&p_bytes[..]).unwrap();
    println!("cycle-tracker-end: convert_g2_sub_to_ark");
    out
}

pub fn convert_g2_ark_to_sub(p: G2Affine) -> AffineG2 {
    println!("cycle-tracker-start: convert_g2_ark_to_sub");
    let x0 = p.x().unwrap().c0.to_string();
    let x1 = p.x().unwrap().c1.to_string();
    let y0 = p.y().unwrap().c0.to_string();
    let y1 = p.y().unwrap().c1.to_string();
    let out = AffineG2::new(
        bn::Fq2::new(
            bn::Fq::from_str(&x0).unwrap(),
            bn::Fq::from_str(&x1).unwrap(),
        ),
        bn::Fq2::new(
            bn::Fq::from_str(&y0).unwrap(),
            bn::Fq::from_str(&y1).unwrap(),
        ),
    )
    .expect("Failed to create AffineG2");
    println!("cycle-tracker-end: convert_g2_ark_to_sub");
    out
}

pub fn convert_fr_sub_to_ark(p: Fr) -> ark_bn254::Fr {
    println!("cycle-tracker-start: convert_fr_sub_to_ark");
    let mut bytes = [0u8; 32];
    p.to_big_endian(&mut bytes).unwrap();
    bytes.reverse();
    let out = unsafe { std::mem::transmute::<[u8; 32], ark_bn254::Fr>(bytes) };
    println!("cycle-tracker-end: convert_fr_sub_to_ark");
    out
}

pub fn verify_groth16(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool> {
    // println!("cycle-tracker-start: verify_groth16");
    // let proof: ArkGroth16Proof<Bn254> = ArkGroth16Proof {
    //     a: convert_g1_sub_to_ark(proof.ar),
    //     b: convert_g2_sub_to_ark(proof.bs),
    //     c: convert_g1_sub_to_ark(proof.krs),
    // };
    // let vk: ArkGroth16VerifyingKey<Bn254> = ArkGroth16VerifyingKey {
    //     alpha_g1: convert_g1_sub_to_ark(vk.g1.alpha),
    //     beta_g2: convert_g2_sub_to_ark(vk.g2.beta),
    //     gamma_g2: convert_g2_sub_to_ark(vk.g2.gamma),
    //     delta_g2: convert_g2_sub_to_ark(vk.g2.delta),
    //     gamma_abc_g1: vk.g1.k.iter().map(|p| convert_g1_sub_to_ark(*p)).collect(),
    // };

    // let pvk = Groth16::<Bn254>::process_vk(&vk)?;

    // let out = Ok(Groth16::<Bn254>::verify_with_processed_vk(
    //     &pvk,
    //     public_inputs
    //         .iter()
    //         .map(|p| convert_fr_sub_to_ark(*p))
    //         .collect::<Vec<ark_bn254::Fr>>()
    //         .as_slice(),
    //     &proof,
    // )?);
    // println!("cycle-tracker-end: verify_groth16");
    // out
    Ok(groth16_verifier::verify_groth16(vk, proof, public_inputs)?)
}
