#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

//! This crate provides verifiers for Groth16 and Plonk zero-knowledge proofs.

use bn::Fr;
use groth16::{
    error::Groth16Error, load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes,
    verify_groth16,
};
use plonk::{
    error::PlonkError, load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes,
    verify_plonk,
};

mod constants;
mod converter;
mod error;
mod groth16;
mod hash_to_field;
mod plonk;
mod transcript;

/// A verifier for Groth16 zero-knowledge proofs.
#[derive(Debug)]
pub struct Groth16Verifier;

impl Groth16Verifier {
    /// Verifies a Groth16 proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof bytes.
    /// * `vk` - The verification key bytes.
    /// * `public_inputs` - The public inputs.
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating whether the proof is valid,
    /// or a `Groth16Error` if verification fails.
    pub fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, Groth16Error> {
        let proof = load_groth16_proof_from_bytes(proof).unwrap();
        let vk = load_groth16_verifying_key_from_bytes(vk).unwrap();

        verify_groth16(&vk, &proof, public_inputs)
    }
}

/// A verifier for Plonk zero-knowledge proofs.
#[derive(Debug)]
pub struct PlonkVerifier;

impl PlonkVerifier {
    /// Verifies a Plonk proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof bytes.
    /// * `vk` - The verification key bytes.
    /// * `public_inputs` - The public inputs.
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating whether the proof is valid,
    /// or a `PlonkError` if verification fails.
    pub fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, PlonkError> {
        let proof = load_plonk_proof_from_bytes(proof).unwrap();
        let vk = load_plonk_verifying_key_from_bytes(vk).unwrap();

        verify_plonk(&vk, &proof, public_inputs)
    }
}
