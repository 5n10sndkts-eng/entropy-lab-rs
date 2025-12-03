use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use bip39::Mnemonic;
use hex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;

/// Cake Wallet Targeted Scanner
/// Only generates addresses for the 8,717 officially confirmed vulnerable mnemonics
pub fn run_targeted() -> Result<()> {
    println!("Cake Wallet Targeted Vulnerability Scanner (GPU)");
    println!("Loading official vulnerable mnemonic hashes...");

    // Load vulnerable hashes
    let hashes_file = fs::read_to_string("cakewallet_vulnerable_hashes.txt")?;
    let vulnerable_hashes: HashSet<String> = hashes_file
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect();

    println!(
        "Loaded {} vulnerable mnemonic hashes",
        vulnerable_hashes.len()
    );
    println!("Scanning 1,048,576 possible seeds...");

    let solver = GpuSolver::new()?;

    let mut batch: Vec<[u8; 16]> = Vec::new();
    let mut vulnerable_seeds = Vec::new();
    let mut checked = 0;
    let mut found = 0;

    // Scan all 1M seeds
    for seed_index in 0..1_048_576 {
        // Generate entropy (20-bit index in high bits)
        let entropy_hi = (seed_index as u64) << 44;
        let entropy_lo = 0u64;

        // Pack to 16 bytes
        let mut entropy = [0u8; 16];
        entropy[0..8].copy_from_slice(&entropy_hi.to_be_bytes());
        entropy[8..16].copy_from_slice(&entropy_lo.to_be_bytes());

        // Generate mnemonic on CPU
        if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy[0..16]) {
            let mnemonic_str = mnemonic.to_string();

            // Hash mnemonic
            let mut hasher = Sha256::new();
            hasher.update(mnemonic_str.as_bytes());
            let hash = hasher.finalize();
            let hash_hex = hex::encode(hash);

            // Check if vulnerable
            if vulnerable_hashes.contains(&hash_hex) {
                found += 1;
                eprintln!(
                    "[VULNERABLE] Seed {}: {} -> Hash: {}",
                    seed_index,
                    &mnemonic_str[..50],
                    &hash_hex[..16]
                );

                // Add to GPU batch
                batch.push(entropy);
                vulnerable_seeds.push(seed_index);
            }
        }

        checked += 1;
        if checked % 100_000 == 0 {
            eprintln!(
                "Progress: {}/1048576 ({:.1}%) - Found: {}",
                checked,
                (checked as f64 / 1_048_576.0) * 100.0,
                found
            );
        }

        // Process GPU batch when full
        if batch.len() >= 1024 {
            let addresses = solver.compute_batch(&batch, 0)?; // purpose=0 for Cake Wallet
            for (i, addr) in addresses.iter().enumerate() {
                println!("ADDRESS: {}", hex::encode(addr));
                eprintln!("  -> Seed index: {}", vulnerable_seeds[i]);
            }
            batch.clear();
            vulnerable_seeds.clear();
        }
    }

    // Final batch
    if !batch.is_empty() {
        let addresses = solver.compute_batch(&batch, 0)?;
        for (i, addr) in addresses.iter().enumerate() {
            println!("ADDRESS: {}", hex::encode(addr));
            eprintln!("  -> Seed index: {}", vulnerable_seeds[i]);
        }
    }

    eprintln!("\nScan complete!");
    eprintln!("Total seeds checked: {}", checked);
    eprintln!("Vulnerable seeds found: {}", found);
    eprintln!("Expected: {} (from official list)", vulnerable_hashes.len());

    Ok(())
}
