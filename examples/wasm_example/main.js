import * as wasm from "../../verifier/pkg/snark_bn254_verifier.js"
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert'
import { homedir } from "node:os";


// Read the verification keys for Groth16 and Plonk from the file system
const GROTH16_VK_BYTES = new Uint8Array(fs.readFileSync(
    path.join(homedir(), '.sp1/circuits/v2.0.0/groth16_vk.bin')
));
const PLONK_VK_BYTES = new Uint8Array(fs.readFileSync(
    path.join(homedir(), '.sp1/circuits/v2.0.0/plonk_vk.bin')
));

// Pad a Uint8Array to 32 bytes
const pad32Bytes = (x) => {
    const padding = new Uint8Array(32 - x.length).fill(0);
    return new Uint8Array([...padding, ...x])
}

// Convert a hexadecimal string to a Uint8Array
export const fromHexString = (hexString) =>
    Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

// Convert a big number to a padded Uint8Array
export function fromBigNumber(number) {
    var array = [], bigint = BigInt(number)
    // Convert the number to bytes
    for (let i = 0; i < Math.ceil(Math.floor(Math.log2(new Number(number)) + 1) / 8); i++)
        array.unshift(new Number((bigint >> BigInt(8 * i)) & 255n))
    // Pad the resulting array to 32 bytes
    return pad32Bytes(new Uint8Array(array));
}


const files = fs.readdirSync("./data");

// Iterate through each file in the data directory
for (const file of files) {
    try {
        // Read and parse the JSON content of the file
        const fileContent = fs.readFileSync(path.join("./data", file), 'utf8');
        const { proof } = JSON.parse(fileContent);

        // Determine the ZKP type (Groth16 or Plonk) based on the filename
        const zkpType = file.toLowerCase().includes('groth16') ? 'Groth16' : 'Plonk';
        const { raw_proof, public_inputs } = proof[zkpType];

        // Select the appropriate verification function and verification key based on ZKP type
        const verifyFunction = zkpType === 'Groth16' ? wasm.wasm_verify_groth16 : wasm.wasm_verify_plonk;
        const vkBytes = zkpType === 'Groth16' ? GROTH16_VK_BYTES : PLONK_VK_BYTES;

        // The array is a flattened array of 32-byte segments
        const formattedPublicInputs = public_inputs.map(input => fromBigNumber(BigInt(input))).reduce((acc, val) => [...acc, ...val], []);

        assert(verifyFunction(fromHexString(raw_proof), vkBytes, formattedPublicInputs));
        console.log(`Proof in ${file} is valid.`);
    } catch (error) {
        console.error(`Error processing ${file}: ${error.message}`);
    }
}