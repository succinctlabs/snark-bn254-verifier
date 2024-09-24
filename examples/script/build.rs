use sp1_sdk::SP1ProofWithPublicValues;
use std::fs;
use std::path::Path;

fn main() {
    let binaries_dir = Path::new("../binaries");
    let output_dir = Path::new("../wasm_example/data");

    fs::read_dir(binaries_dir)
        .expect("Failed to read binaries directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|s| s.to_str()) == Some("bin"))
        .for_each(|entry| {
            let path = entry.path();
            let proof = SP1ProofWithPublicValues::load(&path).expect("Failed to load proof");
            let json_proof = serde_json::to_string(&proof).expect("Failed to serialize proof");
            let json_path = output_dir
                .join(path.file_stem().unwrap())
                .with_extension("json");
            fs::write(json_path, json_proof).expect("Failed to write JSON proof");
        });
}
