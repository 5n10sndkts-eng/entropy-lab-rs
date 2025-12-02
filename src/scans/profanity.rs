use anyhow::{Result, Context};
use crate::scans::gpu_solver::GpuSolver;
use bitcoin::Address;
use std::str::FromStr;
use hex;

/// Profanity Vanity Address Vulnerability Scanner
/// Brute-forces 32-bit seeds used by Profanity's mt19937_64 RNG
pub fn run(target: Option<String>) -> Result<()> {
    println!("Profanity Vanity Address Vulnerability Scanner (GPU)");
    
    let target_addr_str = target.context("Target address required for Profanity scan")?;
    println!("Target Address: {}", target_addr_str);
    
    // Parse Ethereum address (remove 0x prefix if present)
    let clean_addr = target_addr_str.trim_start_matches("0x");
    let target_bytes = hex::decode(clean_addr).context("Invalid hex address")?;
    
    if target_bytes.len() != 20 {
        anyhow::bail!("Invalid Ethereum address length: {}", target_bytes.len());
    }
    
    println!("Initializing GPU Solver...");
    let solver = GpuSolver::new()?;
    println!("[GPU] Solver initialized.");
    
    // Search space: 0 to 2^32
    let total_seeds = 4_294_967_296u64;
    let batch_size = 10_000_000; // 10M per batch
    
    println!("Scanning {} seeds...", total_seeds);
    
    let start_time = std::time::Instant::now();
    
    // We can use a custom compute function in GpuSolver or just add one here.
    // For now, let's assume we add `compute_profanity` to GpuSolver.
    // Or we can implement it here if we expose the internal helper.
    // Better to add to GpuSolver to keep OpenCL logic encapsulated.
    
    let seeds = solver.compute_profanity(total_seeds, &target_bytes)?;
    
    if !seeds.is_empty() {
        println!("\n[GPU] 🔓 CRACKED SUCCESSFUL!");
        for seed in seeds {
            println!("Found Seed: {}", seed);
            println!("Private Key can be derived from this seed using MT19937-64.");
        }
    } else {
        println!("\nScan complete. No match found.");
    }
    
    println!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
    
    Ok(())
}
