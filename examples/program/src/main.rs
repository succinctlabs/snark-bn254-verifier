#![no_main]
sp1_zkvm::entrypoint!(main);

use snark_bn254_verifier::Groth16Verifier;
use substrate_bn::Fr;

pub fn main() {
    let proof = sp1_zkvm::io::read_vec();
    let vk = sp1_zkvm::io::read_vec();
    let vkey_hash = sp1_zkvm::io::read_vec();
    let committed_values_digest = sp1_zkvm::io::read_vec();

    let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest =
        Fr::from_slice(&committed_values_digest).expect("Unable to read committed_values_digest");

    println!("cycle-tracker-start: verify");
    let result = Groth16Verifier::verify(&proof, &vk, &[vkey_hash, committed_values_digest]);
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
