#![no_main]
sp1_zkvm::entrypoint!(main);

use snark_bn254_verifier::PlonkVerifier;
use substrate_bn::Fr;

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct Input {
    proof_length: u64,
    proof: Vec<u8>,
    vk_length: u64,
    vk: Vec<u8>,
    vkey_hash_length: u64,
    vkey_hash: Vec<u8>,
    committed_values_digest_length: u64,
    committed_values_digest: Vec<u8>,
}

pub fn main() {
    let input = sp1_zkvm::io::read::<Input>();
    let vkey_hash = Fr::from_slice(&input.vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest = Fr::from_slice(&input.committed_values_digest)
        .expect("Unable to read committed_values_digest");

    println!("cycle-tracker-start: verify");
    let result = PlonkVerifier::verify(
        &input.proof,
        &input.vk,
        &[vkey_hash, committed_values_digest],
    );
    println!("cycle-tracker-end: verify");

    match result {
        Ok(true) => {
            println!("Proof is valid");
        }
        Ok(false) | Err(_) => {
            println!("Proof is invalid");
            panic!();
        }
    }
}
