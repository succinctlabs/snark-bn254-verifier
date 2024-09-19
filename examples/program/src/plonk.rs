#![no_main]
sp1_zkvm::entrypoint!(main);

use snark_bn254_verifier::PlonkVerifier;
use substrate_bn::Fr;

const PLONK_VK_BYTES: &[u8] = include_bytes!("../../../../.sp1/circuits/v2.0.0/plonk_vk.bin");

pub fn main() {
    let proof = sp1_zkvm::io::read_vec();
    let vkey_hash = sp1_zkvm::io::read_vec();
    let committed_values_digest = sp1_zkvm::io::read_vec();

    let vk = PLONK_VK_BYTES;
    let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest =
        Fr::from_slice(&committed_values_digest).expect("Unable to read committed_values_digest");

    println!("cycle-tracker-start: verify");
    let result = PlonkVerifier::verify(&proof, &vk, &[vkey_hash, committed_values_digest]);
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
