use clap::Parser;
use num_bigint::BigUint;
use num_traits::Num;
use sp1_sdk::{proto::network::ProofMode, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::str::FromStr;
use strum_macros::{Display, EnumIter, EnumString};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../elfs/fibonacci-riscv32im-succinct-zkvm-elf");
pub const ISPRIME_ELF: &[u8] = include_bytes!("../../elfs/isprime-riscv32im-succinct-zkvm-elf");
pub const SHA2_ELF: &[u8] = include_bytes!("../../elfs/sha2-riscv32im-succinct-zkvm-elf");
pub const TENDERMINT_ELF: &[u8] =
    include_bytes!("../../elfs/tendermint-riscv32im-succinct-zkvm-elf");

pub const PLONK_ELF: &[u8] = include_bytes!("../../program/elf/plonk");
pub const GROTH16_ELF: &[u8] = include_bytes!("../../program/elf/groth16");

#[derive(clap::Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(
        long,
        value_name = "ELF",
        default_value = "fibonacci",
        help = "Specifies the ELF file to use (e.g., fibonacci, is-prime)"
    )]
    elf: String,

    #[arg(
        long,
        value_name = "MODE",
        default_value = "plonk",
        help = "Specifies the proof mode to use (e.g., groth16, plonk)"
    )]
    mode: String,
}

#[derive(Debug, EnumString, EnumIter, Display)]
enum Elf {
    #[strum(serialize = "fibonacci")]
    Fibonacci,
    #[strum(serialize = "is-prime")]
    IsPrime,
    #[strum(serialize = "sha2")]
    Sha2,
    #[strum(serialize = "tendermint")]
    Tendermint,
}

impl Elf {
    fn get_elf(&self) -> &'static [u8] {
        match self {
            Elf::Fibonacci => FIBONACCI_ELF,
            Elf::IsPrime => ISPRIME_ELF,
            Elf::Sha2 => SHA2_ELF,
            Elf::Tendermint => TENDERMINT_ELF,
        }
    }
}

fn main() {
    // Setup logging for the application
    utils::setup_logger();

    // Parse command line arguments
    let args = Cli::parse();
    let mut stdin = SP1Stdin::new();

    let elf_enum = Elf::from_str(&args.elf)
        .expect("Invalid ELF name. Use 'fibonacci', 'is-prime', or other valid ELF names.");
    let elf = match elf_enum {
        Elf::Fibonacci => {
            let n = 20;
            stdin.write(&n);
            elf_enum.get_elf()
        }
        Elf::IsPrime => {
            let n = 11u64;
            stdin.write(&n);
            elf_enum.get_elf()
        }
        Elf::Sha2 | Elf::Tendermint => elf_enum.get_elf(),
    };

    let (mode, proof_elf) = match args.mode.as_str() {
        "groth16" => (ProofMode::Groth16, GROTH16_ELF),
        "plonk" => (ProofMode::Plonk, PLONK_ELF),
        _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
    };

    // Initialize the prover client
    let client = ProverClient::new();
    let (pk, _) = client.setup(elf);

    // Generate a proof for the specified program
    let proof = match mode {
        ProofMode::Groth16 => client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("Groth16 proof generation failed"),
        ProofMode::Plonk => client
            .prove(&pk, stdin)
            .plonk()
            .run()
            .expect("Plonk proof generation failed"),
        _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
    };

    // Save the generated proof to a binary file
    let proof_file = format!("../binaries/{}_{}_proof.bin", args.elf, args.mode);
    proof.save(&proof_file).unwrap();

    // Load the saved proof and convert it to a Groth16 proof
    let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(&proof_file)
        .map(|sp1_proof_with_public_values| match mode {
            ProofMode::Groth16 => {
                let proof = sp1_proof_with_public_values
                    .proof
                    .try_as_groth_16()
                    .unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            }
            ProofMode::Plonk => {
                let proof = sp1_proof_with_public_values.proof.try_as_plonk().unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            }
            _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
        })
        .expect("Failed to load proof");

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
    stdin.write_slice(&vkey_hash);
    stdin.write_slice(&committed_values_digest);

    // Setup the verifier program
    let (pk, vk) = client.setup(proof_elf);
    // Generate a proof for the verifier program
    let proof = match mode {
        ProofMode::Groth16 => client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("Groth16 proof generation failed"),
        ProofMode::Plonk => client
            .prove(&pk, stdin)
            .plonk()
            .run()
            .expect("Plonk proof generation failed"),
        _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
    };

    // Verify the proof of the verifier program
    client.verify(&proof, &vk).expect("verification failed");

    println!("Successfully verified proof for the program!")
}

#[cfg(test)]
mod tests {

    use super::*;

    use snark_bn254_verifier::{Fr, Groth16Verifier, PlonkVerifier};
    use strum::IntoEnumIterator;

    const PLONK_VK_BYTES: &[u8] = include_bytes!("../../../../.sp1/circuits/v2.0.0/plonk_vk.bin");
    const GROTH16_VK_BYTES: &[u8] =
        include_bytes!("../../../../.sp1/circuits/v2.0.0/groth16_vk.bin");

    #[test]
    fn test_programs() {
        fn verify_proof(proof_file: &str, vk: &[u8], proof_mode: ProofMode) {
            // Load the saved proof and convert it to the specified proof mode
            let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(proof_file)
                .map(|sp1_proof_with_public_values| match proof_mode {
                    ProofMode::Groth16 => {
                        let proof = sp1_proof_with_public_values
                            .proof
                            .try_as_groth_16()
                            .unwrap();
                        (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
                    }
                    ProofMode::Plonk => {
                        let proof = sp1_proof_with_public_values.proof.try_as_plonk().unwrap();
                        (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
                    }
                    _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
                })
                .expect("Failed to load proof");

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

            let is_valid = match proof_mode {
                ProofMode::Groth16 => {
                    Groth16Verifier::verify(&raw_proof, &vk, &[vkey_hash, committed_values_digest])
                        .expect("Groth16 proof is invalid")
                }
                ProofMode::Plonk => {
                    PlonkVerifier::verify(&raw_proof, &vk, &[vkey_hash, committed_values_digest])
                        .expect("Plonk proof is invalid")
                }
                _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
            };

            if !is_valid {
                panic!("{:?} proof is invalid", proof_mode);
            }
        }

        Elf::iter().for_each(|program| {
            // Verify Plonk proof
            let proof_file = format!("../binaries/{}_{}_proof.bin", program.to_string(), "plonk");
            verify_proof(&proof_file, PLONK_VK_BYTES, ProofMode::Plonk);

            // Verify Groth16 proof
            let proof_file = format!(
                "../binaries/{}_{}_proof.bin",
                program.to_string(),
                "groth16"
            );
            verify_proof(&proof_file, GROTH16_VK_BYTES, ProofMode::Groth16);
        });
    }
}
