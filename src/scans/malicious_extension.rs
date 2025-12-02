use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network};
use hex;

/// Simulates a "Malicious Extension" Address Poisoning Attack (GPU Accelerated)
/// The attacker generates a "vanity" address that looks similar to the user's intended destination
/// (matching prefix/suffix) to trick them into copying the wrong address from history.
pub fn run() -> Result<()> {
    println!("Malicious Extension: Address Poisoning Attack (GPU Accelerated)");
    println!("Goal: Generate a 'poison' address that mimics a target address.");

    // Target Address (Legacy P2PKH for this demo)
    // "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" (Genesis Address)
    let target_str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    println!("Target Address: {}", target_str);

    // We want to match the first 6 chars "1A1zP1" and maybe last 2 "Na"
    // Matching 6 chars is trivial on GPU.
    let target_prefix = "1A1zP1";
    let target_suffix = "Na";

    println!(
        "Desired Poison Address: {}...{}",
        target_prefix, target_suffix
    );
    println!("Launching GPU search for matching private key...");

    // Initialize GPU
    let solver = GpuSolver::new()?;
    println!("[GPU] Solver initialized");

    // Search parameters
    let batch_size = 10_000_000; // 10M keys per batch
    let mut seed_base = 0u64;
    let mut found = false;

    let start_time = std::time::Instant::now();

    // Run a few batches
    for i in 0..100 {
        let results = solver.compute_address_poisoning(
            seed_base,
            batch_size,
            target_prefix,
            target_suffix,
        )?;

        if !results.is_empty() {
            for &seed in &results {
                // Verify match on CPU
                let priv_key_bytes = sha256::Hash::hash(&seed.to_le_bytes()).to_byte_array();
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&priv_key_bytes)?;
                let pubkey = secret_key.public_key(&secp);
                let address = Address::p2pkh(bitcoin::PublicKey::new(pubkey), Network::Bitcoin);
                let addr_str = address.to_string();

                if addr_str.starts_with(target_prefix) && addr_str.ends_with(target_suffix) {
                    println!("\n[GPU] 🎯 POISON ADDRESS FOUND!");
                    println!("  Seed: {}", seed);
                    println!("  Private Key: {}", hex::encode(priv_key_bytes));
                    println!("  Address:     {}", addr_str);
                    println!("  Target:      {}", target_str);
                    println!(
                        "  Match:       {}^^^^^...^^^^^",
                        " ".repeat(target_prefix.len())
                    );

                    found = true;
                    break;
                }
            }
        }

        if found {
            break;
        }

        seed_base += batch_size as u64;
        if i % 10 == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush()?;
        }
    }

    if !found {
        println!("\nNo match found in {} iterations.", seed_base);
    } else {
        println!("\nAttack successful! The user might mistake this address for the real one.");
    }

    println!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());

    Ok(())
}
