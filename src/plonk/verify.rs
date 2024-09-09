use std::hash::Hasher;

use anyhow::{anyhow, Error, Result};
use ark_bn254::G1Projective;
use ark_ec::{CurveGroup, VariableBaseMSM};
use bn::{arith::U256, AffineG1, CurveError, Fr, G1};

use crate::{
    constants::{
        ALPHA, BETA, ERR_BSB22_COMMITMENT_MISMATCH, ERR_INVALID_WITNESS, ERR_INVERSE_NOT_FOUND,
        ERR_OPENING_POLY_MISMATCH, GAMMA, ZETA,
    },
    groth16::{convert_fr_sub_to_ark, convert_g1_ark_to_sub},
    transcript::Transcript,
};

use super::{converter::g1_to_bytes, element::PlonkFr, kzg, PlonkProof};
#[derive(Debug)]
pub(crate) struct PlonkVerifyingKey {
    pub(crate) size: usize,
    pub(crate) size_inv: Fr,
    pub(crate) generator: Fr,
    pub(crate) nb_public_variables: usize,

    pub(crate) kzg: kzg::KZGVerifyingKey,

    pub(crate) coset_shift: Fr,

    pub(crate) s: [kzg::Digest; 3],

    pub(crate) ql: kzg::Digest,
    pub(crate) qr: kzg::Digest,
    pub(crate) qm: kzg::Digest,
    pub(crate) qo: kzg::Digest,
    pub(crate) qk: kzg::Digest,
    pub(crate) qcp: Vec<kzg::Digest>,

    pub(crate) commitment_constraint_indexes: Vec<usize>,
}

pub fn verify_plonk(
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof,
    public_inputs: &[Fr],
) -> Result<bool> {
    println!("cycle-tracker-start: check_bsb22_commitments");
    if proof.bsb22_commitments.len() != vk.qcp.len() {
        return Err(anyhow::anyhow!(ERR_BSB22_COMMITMENT_MISMATCH));
    }
    println!("cycle-tracker-end: check_bsb22_commitments");

    println!("cycle-tracker-start: check_public_inputs");
    if public_inputs.len() != vk.nb_public_variables {
        return Err(anyhow::anyhow!(ERR_INVALID_WITNESS));
    }
    println!("cycle-tracker-end: check_public_inputs");

    println!("cycle-tracker-start: create_transcript");
    let mut fs = Transcript::new(Some(
        [
            GAMMA.to_string(),
            BETA.to_string(),
            ALPHA.to_string(),
            ZETA.to_string(),
        ]
        .to_vec(),
    ))?;
    println!("cycle-tracker-end: create_transcript");

    println!("cycle-tracker-start: bind_public_data");
    bind_public_data(&mut fs, GAMMA, vk, public_inputs)?;
    println!("cycle-tracker-end: bind_public_data");

    println!("cycle-tracker-start: derive_gamma");
    let gamma = derive_randomness(
        &mut fs,
        GAMMA,
        Some([proof.lro[0], proof.lro[1], proof.lro[2]].to_vec()),
    )?;
    println!("cycle-tracker-end: derive_gamma");

    println!("cycle-tracker-start: derive_beta");
    let beta = derive_randomness(&mut fs, BETA, None)?;
    println!("cycle-tracker-end: derive_beta");

    println!("cycle-tracker-start: prepare_alpha_deps");
    let mut alpha_deps: Vec<AffineG1> = proof.bsb22_commitments.iter().cloned().collect();
    alpha_deps.push(proof.z);
    println!("cycle-tracker-end: prepare_alpha_deps");

    println!("cycle-tracker-start: derive_alpha");
    let alpha = derive_randomness(&mut fs, ALPHA, Some(alpha_deps))?;
    println!("cycle-tracker-end: derive_alpha");

    println!("cycle-tracker-start: derive_zeta");
    let zeta = derive_randomness(
        &mut fs,
        ZETA,
        Some([proof.h[0], proof.h[1], proof.h[2]].to_vec()),
    )?;
    println!("cycle-tracker-end: derive_zeta");

    println!("cycle-tracker-start: initialize_variables");
    let one = Fr::one();
    let n = U256::from(vk.size as u64);
    let n = Fr::new(n).ok_or_else(|| anyhow!("Beyond the modulus"))?;
    let zeta_power_n = zeta.pow(n);
    let zh_zeta = zeta_power_n - one;
    let mut lagrange_one = (zeta - one).inverse().expect(ERR_INVERSE_NOT_FOUND);
    lagrange_one *= zh_zeta;
    lagrange_one *= vk.size_inv;
    println!("cycle-tracker-end: initialize_variables");

    println!("cycle-tracker-start: initialize_pi");
    let mut pi = Fr::zero();
    let mut accw = Fr::one();
    let mut dens = Vec::with_capacity(public_inputs.len());
    println!("cycle-tracker-end: initialize_pi");

    println!("cycle-tracker-start: prepare_dens");
    for _ in 0..public_inputs.len() {
        let mut temp = zeta;
        temp -= accw;
        dens.push(temp);
        accw *= vk.generator;
    }
    println!("cycle-tracker-end: prepare_dens");

    println!("cycle-tracker-start: batch_invert");
    let inv_dens = batch_invert(&dens)?;
    println!("cycle-tracker-end: batch_invert");

    println!("cycle-tracker-start: calculate_pi");
    accw = Fr::one();
    let mut xi_li;
    for (i, public_input) in public_inputs.iter().enumerate() {
        xi_li = zh_zeta;
        xi_li *= inv_dens[i];
        xi_li *= vk.size_inv;
        xi_li *= accw;
        xi_li *= *public_input;
        accw *= vk.generator;
        pi += xi_li;
    }
    println!("cycle-tracker-end: calculate_pi");

    println!("cycle-tracker-start: initialize_hash_to_field");
    let mut hash_to_field = crate::hash_to_field::WrappedHashToField::new(b"BSB22-Plonk")?;
    println!("cycle-tracker-end: initialize_hash_to_field");

    println!("cycle-tracker-start: process_commitments");
    for i in 0..vk.commitment_constraint_indexes.len() {
        hash_to_field.write(&g1_to_bytes(&proof.bsb22_commitments[i])?);
        let hash_bts = hash_to_field.sum()?;
        hash_to_field.reset();
        let hashed_cmt = Fr::from_bytes_be_mod_order(&hash_bts).map_err(Error::msg)?;

        let exponent =
            U256::from((vk.nb_public_variables + vk.commitment_constraint_indexes[i]) as u64);
        let exponent = Fr::new(exponent).ok_or_else(|| anyhow!("Beyond the modulus"))?;
        let w_pow_i = vk.generator.pow(exponent);
        let mut den = zeta;
        den -= w_pow_i;
        let mut lagrange = zh_zeta;
        lagrange *= w_pow_i;
        lagrange /= den;
        lagrange *= vk.size_inv;

        xi_li = lagrange;
        xi_li *= hashed_cmt;
        pi += xi_li;
    }
    println!("cycle-tracker-end: process_commitments");

    println!("cycle-tracker-start: extract_claimed_values");
    let l = proof.batched_proof.claimed_values[1];
    let r = proof.batched_proof.claimed_values[2];
    let o = proof.batched_proof.claimed_values[3];
    let s1 = proof.batched_proof.claimed_values[4];
    let s2 = proof.batched_proof.claimed_values[5];
    println!("cycle-tracker-end: extract_claimed_values");

    println!("cycle-tracker-start: extract_zu");
    let zu = proof.z_shifted_opening.claimed_value;
    println!("cycle-tracker-end: extract_zu");

    println!("cycle-tracker-start: calculate_alpha_square_lagrange_one");
    let alpha_square_lagrange_one = {
        let mut tmp = lagrange_one;
        tmp *= alpha;
        tmp *= alpha;
        tmp
    };
    println!("cycle-tracker-end: calculate_alpha_square_lagrange_one");

    println!("cycle-tracker-start: calculate_const_lin");
    let mut tmp = beta;
    tmp *= s1;
    tmp += gamma;
    tmp += l;
    let mut const_lin = tmp;

    tmp = beta;
    tmp *= s2;
    tmp += gamma;
    tmp += r;

    const_lin *= tmp;

    tmp = o;
    tmp += gamma;

    const_lin *= tmp;
    const_lin *= alpha;
    const_lin *= zu;

    const_lin -= alpha_square_lagrange_one;
    const_lin += pi;

    const_lin = -const_lin;
    println!("cycle-tracker-end: calculate_const_lin");

    println!("cycle-tracker-start: extract_opening_lin_pol");
    let opening_lin_pol = proof.batched_proof.claimed_values[0];
    println!("cycle-tracker-end: extract_opening_lin_pol");

    println!("cycle-tracker-start: check_opening_poly_match");
    if const_lin != opening_lin_pol {
        return Err(anyhow::anyhow!(ERR_OPENING_POLY_MISMATCH));
    }
    println!("cycle-tracker-end: check_opening_poly_match");

    println!("cycle-tracker-start: initialize_s1_s2");
    let _s1 = Fr::zero();
    let _s2 = Fr::zero();
    println!("cycle-tracker-end: initialize_s1_s2");

    println!("cycle-tracker-start: calculate_s1");
    let mut _s1 = beta * s1 + l + gamma;
    let tmp = beta * s2 + r + gamma;
    _s1 = _s1 * tmp * beta * alpha * zu;
    println!("cycle-tracker-end: calculate_s1");

    println!("cycle-tracker-start: calculate_s2");
    let mut _s2 = beta * zeta + gamma + l;
    let mut tmp = beta * vk.coset_shift * zeta + gamma + r;
    _s2 *= tmp;
    tmp = beta * vk.coset_shift * vk.coset_shift * zeta + gamma + o;
    _s2 *= tmp;
    _s2 *= alpha;
    _s2 = -_s2;
    println!("cycle-tracker-end: calculate_s2");

    println!("cycle-tracker-start: calculate_coeff_z");
    let coeff_z = alpha_square_lagrange_one + _s2;
    println!("cycle-tracker-end: calculate_coeff_z");

    println!("cycle-tracker-start: calculate_rl");
    let rl = l * r;
    println!("cycle-tracker-end: calculate_rl");

    println!("cycle-tracker-start: calculate_n_plus_two");
    let n_plus_two = U256::from(vk.size as u64 + 2);
    let n_plus_two = Fr::new(n_plus_two).ok_or_else(|| anyhow!("Beyond the modulus"))?;
    println!("cycle-tracker-end: calculate_n_plus_two");

    println!("cycle-tracker-start: calculate_zeta_powers");
    let mut zeta_n_plus_two_zh = zeta.pow(n_plus_two);
    let mut zeta_n_plus_two_square_zh = zeta_n_plus_two_zh * zeta_n_plus_two_zh;
    zeta_n_plus_two_zh *= zh_zeta;
    zeta_n_plus_two_zh = -zeta_n_plus_two_zh;
    zeta_n_plus_two_square_zh *= zh_zeta;
    zeta_n_plus_two_square_zh = -zeta_n_plus_two_square_zh;
    let zh = -zh_zeta;
    println!("cycle-tracker-end: calculate_zeta_powers");

    println!("cycle-tracker-start: prepare_points");
    let mut points = Vec::new();
    points.extend_from_slice(&proof.bsb22_commitments);
    points.push(vk.ql);
    points.push(vk.qr);
    points.push(vk.qm);
    points.push(vk.qo);
    points.push(vk.qk);
    points.push(vk.s[2]);
    points.push(proof.z);
    points.push(proof.h[0]);
    points.push(proof.h[1]);
    points.push(proof.h[2]);
    println!("cycle-tracker-end: prepare_points");

    println!("cycle-tracker-start: extract_qc");
    let qc = proof.batched_proof.claimed_values[6..].to_vec();
    println!("cycle-tracker-end: extract_qc");

    println!("cycle-tracker-start: prepare_scalars");
    let mut scalars = Vec::new();
    scalars.extend_from_slice(&qc);
    scalars.push(l);
    scalars.push(r);
    scalars.push(rl);
    scalars.push(o);
    scalars.push(one);
    scalars.push(_s1);
    scalars.push(coeff_z);
    scalars.push(zh);
    scalars.push(zeta_n_plus_two_zh);
    scalars.push(zeta_n_plus_two_square_zh);
    println!("cycle-tracker-end: prepare_scalars");

    println!("cycle-tracker-start: calculate_linearized_polynomial_digest");
    let linearized_polynomial_digest = G1::msm(
        &points.iter().map(|&p| p.into()).collect::<Vec<_>>(),
        &scalars,
    )
    .into();
    println!("cycle-tracker-end: calculate_linearized_polynomial_digest");

    println!("cycle-tracker-start: prepare_digests_to_fold");
    let mut digests_to_fold = vec![AffineG1::default(); vk.qcp.len() + 6];
    digests_to_fold[6..].copy_from_slice(&vk.qcp);
    digests_to_fold[0] = linearized_polynomial_digest;
    digests_to_fold[1] = proof.lro[0];
    digests_to_fold[2] = proof.lro[1];
    digests_to_fold[3] = proof.lro[2];
    digests_to_fold[4] = vk.s[0];
    digests_to_fold[5] = vk.s[1];
    println!("cycle-tracker-end: prepare_digests_to_fold");

    println!("cycle-tracker-start: fold_proof");
    let (folded_proof, folded_digest) = kzg::fold_proof(
        digests_to_fold,
        &proof.batched_proof,
        &zeta,
        Some(zu.into_u256().to_bytes_be().to_vec()),
    )?;
    println!("cycle-tracker-end: fold_proof");

    println!("cycle-tracker-start: calculate_shifted_zeta");
    let shifted_zeta = zeta * vk.generator;
    println!("cycle-tracker-end: calculate_shifted_zeta");

    println!("cycle-tracker-start: convert_folded_digest");
    let folded_digest: AffineG1 = folded_digest.into();
    println!("cycle-tracker-end: convert_folded_digest");

    println!("cycle-tracker-start: batch_verify_multi_points");
    kzg::batch_verify_multi_points(
        [folded_digest, proof.z].to_vec(),
        [folded_proof, proof.z_shifted_opening].to_vec(),
        [zeta, shifted_zeta].to_vec(),
        &vk.kzg,
    )?;
    println!("cycle-tracker-end: batch_verify_multi_points");

    Ok(true)
}

fn bind_public_data(
    transcript: &mut Transcript,
    challenge: &str,
    vk: &PlonkVerifyingKey,
    public_inputs: &[Fr],
) -> Result<()> {
    transcript.bind(challenge, &g1_to_bytes(&vk.s[0])?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.s[1])?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.s[2])?)?;

    transcript.bind(challenge, &g1_to_bytes(&vk.ql)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qr)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qm)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qo)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qk)?)?;

    for qcp in vk.qcp.iter() {
        transcript.bind(challenge, &g1_to_bytes(qcp)?)?;
    }

    for public_input in public_inputs.iter() {
        transcript.bind(challenge, &public_input.into_u256().to_bytes_be())?;
    }

    Ok(())
}

fn derive_randomness(
    transcript: &mut Transcript,
    challenge: &str,
    points: Option<Vec<AffineG1>>,
) -> Result<Fr> {
    if let Some(points) = points {
        for point in points {
            let buf = g1_to_bytes(&point)?;
            transcript.bind(challenge, &buf)?;
        }
    }

    let b = transcript.compute_challenge(challenge)?;
    let x = PlonkFr::set_bytes(&b.as_slice())?.into_fr()?;
    Ok(x)
}

fn batch_invert(elements: &[Fr]) -> Result<Vec<Fr>> {
    let mut elements = elements.to_vec();
    batch_inversion(&mut elements);
    Ok(elements)
}

fn batch_inversion(v: &mut [Fr]) {
    batch_inversion_and_mul(v, &Fr::one());
}

fn batch_inversion_and_mul(v: &mut [Fr], coeff: &Fr) {
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = Fr::one();
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp *= *f;
        prod.push(tmp);
    }

    tmp = tmp.inverse().unwrap();

    tmp *= *coeff;

    for (f, s) in v
        .iter_mut()
        .rev()
        .filter(|f| !f.is_zero())
        .zip(prod.into_iter().rev().skip(1).chain(Some(Fr::one())))
    {
        let new_tmp = tmp * *f;
        *f = tmp * s;
        tmp = new_tmp;
    }
}
