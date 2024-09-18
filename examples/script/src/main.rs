//! A simple script to generate and verify the proof of a given program.
use num_bigint::BigUint;
use num_traits::Num;
use sp1_sdk::{
    install::try_install_circuit_artifacts, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin,
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../fibonacci-riscv32im-succinct-zkvm-elf");
pub const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging for the application
    utils::setup_logger();

    // Set the input value for the Fibonacci calculation
    let n = 20;

    // Prepare the input for the zkVM
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Initialize the prover client
    let client = ProverClient::new();
    let (pk, _) = client.setup(FIBONACCI_ELF);

    // Generate a proof for the Fibonacci program
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("Proving failed");

    // Save the generated proof to a binary file
    let proof_file = "proof.bin";
    proof.save(proof_file).unwrap();

    // Retrieve the verification key
    let vk_dir_entry = try_install_circuit_artifacts();
    let vk_bin_path = vk_dir_entry.join("groth16_vk.bin"); // For Groth16, use "groth16_vk.bin"

    // Read the verification key from file
    let vk = std::fs::read(vk_bin_path).unwrap();

    // Load the saved proof and convert it to a Groth16 proof
    let proof = SP1ProofWithPublicValues::load("proof.bin")
        .map(|sp1_proof_with_public_values| {
            sp1_proof_with_public_values
                .proof
                .try_as_groth_16()
                .unwrap() // Use `try_as_groth_16()` for Groth16
        })
        .expect("Failed to load proof");

    // Extract the raw proof and public inputs
    let raw_proof = hex::decode(proof.raw_proof).unwrap();
    let public_inputs = proof.public_inputs;

    // Convert public inputs to byte representations
    let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10)
        .unwrap()
        .to_bytes_be();
    let committed_values_digest = BigUint::from_str_radix(&public_inputs[1], 10)
        .unwrap()
        .to_bytes_be();

    // Prepare input for the verifier program
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&raw_proof);
    stdin.write_slice(&vk);
    stdin.write_slice(&vkey_hash);
    stdin.write_slice(&committed_values_digest);

    // Setup the verifier program
    let (pk, vk) = client.setup(ELF);
    // Generate a proof for the verifier program
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("Proving failed");

    // Verify the proof of the verifier program
    client.verify(&proof, &vk).expect("verification failed");

    println!("Successfully verified proof for the program!")
}

#[cfg(test)]
mod tests {

    use super::*;

    use snark_bn254_verifier::{Groth16Verifier, PlonkVerifier};
    use substrate_bn::Fr;

    #[test]
    fn test_fibonacci() {
        // Retrieve the verification key
        let vk_dir_entry = try_install_circuit_artifacts();

        // Groth16
        {
            let vk_bin_path = vk_dir_entry.join("groth16_vk.bin"); // For Groth16, use "groth16_vk.bin"

            // Read the verification key from file
            let vk = std::fs::read(vk_bin_path).unwrap();

            // Load the saved proof and convert it to a Groth16 proof
            let proof = SP1ProofWithPublicValues::load("groth16_proof.bin")
                .map(|sp1_proof_with_public_values| {
                    sp1_proof_with_public_values
                        .proof
                        .try_as_groth_16()
                        .unwrap() // Use `try_as_groth_16()` for Groth16
                })
                .expect("Failed to load proof");

            // Extract the raw proof and public inputs
            let raw_proof = hex::decode(proof.raw_proof).unwrap();
            let public_inputs = proof.public_inputs;

            // Convert public inputs to byte representations
            let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10)
                .unwrap()
                .to_bytes_be();
            let committed_values_digest = BigUint::from_str_radix(&public_inputs[1], 10)
                .unwrap()
                .to_bytes_be();

            let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
            let committed_values_digest = Fr::from_slice(&committed_values_digest)
                .expect("Unable to read committed_values_digest");

            let result =
                Groth16Verifier::verify(&raw_proof, &vk, &[vkey_hash, committed_values_digest]);

            match result {
                Ok(true) => {
                    println!("Groth16 Proof is valid");
                }
                Ok(false) | Err(_) => {
                    println!("Groth16 Proof is invalid");
                    panic!();
                }
            }
        }
        // Plonk
        {
            let vk_bin_path = vk_dir_entry.join("plonk_vk.bin"); // For Plonk, use "plonk_vk.bin"

            // Read the verification key from file
            let vk = std::fs::read(vk_bin_path).unwrap();

            // Load the saved proof and convert it to a Groth16 proof
            let proof = SP1ProofWithPublicValues::load("plonk_proof.bin")
                .map(|sp1_proof_with_public_values| {
                    sp1_proof_with_public_values.proof.try_as_plonk().unwrap() // Use `try_as_plonk()` for Plonk
                })
                .expect("Failed to load proof");

            // Extract the raw proof and public inputs
            let raw_proof = hex::decode(proof.raw_proof).unwrap();
            let public_inputs = proof.public_inputs;

            // Convert public inputs to byte representations
            let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10)
                .unwrap()
                .to_bytes_be();
            let committed_values_digest = BigUint::from_str_radix(&public_inputs[1], 10)
                .unwrap()
                .to_bytes_be();

            let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
            let committed_values_digest = Fr::from_slice(&committed_values_digest)
                .expect("Unable to read committed_values_digest");

            let result =
                PlonkVerifier::verify(&raw_proof, &vk, &[vkey_hash, committed_values_digest]);

            match result {
                Ok(true) => {
                    println!("Plonk Proof is valid");
                }
                Ok(false) | Err(_) => {
                    println!("Plonk Proof is invalid");
                    panic!();
                }
          }
        }
    }
}
