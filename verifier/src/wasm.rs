//! WASM bindings for the verifier.

use crate::{Groth16Verifier, PlonkVerifier};
use bn::Fr;
use wasm_bindgen::prelude::*;

fn load_public_inputs(public_inputs: &[u8]) -> Result<Vec<Fr>, JsValue> {
    public_inputs
        .chunks(32)
        .map(|chunk| Fr::from_slice(chunk).map_err(|e| JsValue::from_str(&e.to_string())))
        .collect()
}

/// Verifies a Groth16 proof using WebAssembly.
///
/// # Arguments
///
/// * `proof` - The proof bytes.
/// * `vk` - The verification key bytes.
/// * `public_inputs` - The public inputs bytes. This must be a concatenated array big-endian 32-byte segments representing scalar field elements
///
/// # Returns
///
/// A `Result` containing a boolean indicating whether the proof is valid,
/// or a `Groth16Error` if verification fails.
#[wasm_bindgen]
pub fn wasm_verify_groth16(proof: &[u8], vk: &[u8], public_inputs: &[u8]) -> Result<bool, JsValue> {
    let public_inputs = load_public_inputs(public_inputs)?;

    Groth16Verifier::verify(&proof, &vk, &public_inputs)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verifies a Plonk proof using WebAssembly.
///
/// # Arguments
///
/// * `proof` - The proof bytes.
/// * `vk` - The verification key bytes.
/// * `public_inputs` - The public inputs bytes. This must be a concatenated array of big-endian 32-byte segments representing scalar field elements
///
/// # Returns
///
/// A `Result` containing a boolean indicating whether the proof is valid,
/// or a `JsValue` containing an error message if verification fails.
#[wasm_bindgen]
pub fn wasm_verify_plonk(proof: &[u8], vk: &[u8], public_inputs: &[u8]) -> Result<bool, JsValue> {
    let public_inputs = load_public_inputs(public_inputs)?;

    PlonkVerifier::verify(&proof, &vk, &public_inputs)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
