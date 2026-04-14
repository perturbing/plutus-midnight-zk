//! Generate Plutus test-vectors for all example circuits.
//!
//! Usage:
//!   cargo run --bin write-test-vectors [OUTPUT_DIR]
//!
//! OUTPUT_DIR defaults to "test-vectors". For each circuit, a subdirectory is
//! created containing five JSON files:
//!   {name}_plutus_vk.json       – extended Plutus VK (includes SRS g2 commitment)
//!   {name}_circuit_params.json  – 10 circuit-structure scalars
//!   {name}_rotation_sets.json   – rotation-set metadata for the Plutus verifier
//!   {name}_plutus_proof.json    – structured GWC proof
//!   {name}_plutus_instance.json – public inputs as array of 32-byte LE hex strings

use rust_midnight_zk::examples;

fn main() {
    let base_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test-vectors".to_string());

    println!("Writing test vectors to '{base_dir}/'");

    examples::poseidon::run(&base_dir);
    examples::sha_preimage::run(&base_dir);
    examples::ecc::run(&base_dir);
    examples::schnorr_sig::run(&base_dir);
    examples::native_gadgets::run(&base_dir);
    examples::membership::run(&base_dir);
    examples::rsa_sig::run(&base_dir);
    examples::bitcoin_sig::run(&base_dir);
    examples::ethereum_sig::run(&base_dir);
    examples::ecdsa_threshold::run(&base_dir);

    println!("\nDone. All test vectors written to '{base_dir}/'.");
}
