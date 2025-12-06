//! Brainwallet Scanner
//! 
//! Covers Gap #8: SHA256(passphrase) → private key
//! 
//! Brainwallets use a passphrase directly hashed to create a private key.
//! This scanner supports:
//! - Direct SHA256 (1 iteration)
//! - SHA256 with multiple iterations
//! - SHA3-256 variant

use anyhow::Result;
use tracing::{info, warn};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network, CompressedPublicKey};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Hash type for brainwallet
#[derive(Debug, Clone, Copy)]
pub enum HashType {
    Sha256 { iterations: u32 },
    Sha3_256,
}

impl Default for HashType {
    fn default() -> Self {
        HashType::Sha256 { iterations: 1 }
    }
}

/// Run brainwallet scanner with a single passphrase
pub fn run_single(
    passphrase: &str,
    hash_type: HashType,
    target: Option<&str>,
) -> Result<()> {
    info!("Brainwallet Scanner");
    info!("Hash: {:?}", hash_type);
    info!("Passphrase: \"{}\"", passphrase);

    let privkey = derive_key(passphrase, hash_type);
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    
    if let Ok(secret) = SecretKey::from_slice(&privkey) {
        let pubkey_secp = secret.public_key(&secp);
        let compressed = CompressedPublicKey(pubkey_secp);
        
        // Generate various address types
        let addr_p2pkh = Address::p2pkh(compressed, network);
        let addr_p2wpkh = Address::p2wpkh(&compressed, network);
        
        info!("Private Key: {}", hex::encode(privkey));
        info!("P2PKH:  {}", addr_p2pkh);
        info!("P2WPKH: {}", addr_p2wpkh);
        
        if let Some(t) = target {
            if addr_p2pkh.to_string() == t || addr_p2wpkh.to_string() == t {
                warn!("🎯 MATCH FOUND!");
                return Ok(());
            }
        }
    } else {
        warn!("Invalid private key derived from passphrase");
    }
    
    Ok(())
}

/// Run brainwallet scanner with passphrase file
pub fn run_file(
    wordlist_path: &str,
    hash_type: HashType,
    target: &str,
) -> Result<()> {
    info!("Brainwallet Scanner - File Mode");
    info!("Hash: {:?}", hash_type);
    info!("Wordlist: {}", wordlist_path);
    info!("Target: {}", target);

    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    
    let mut checked = 0u64;
    let start_time = std::time::Instant::now();

    for line in reader.lines() {
        let passphrase = line?;
        if passphrase.is_empty() {
            continue;
        }
        
        let privkey = derive_key(&passphrase, hash_type);
        
        if let Ok(secret) = SecretKey::from_slice(&privkey) {
            let pubkey_secp = secret.public_key(&secp);
            let compressed = CompressedPublicKey(pubkey_secp);
            
            let addr_p2pkh = Address::p2pkh(compressed, network);
            let addr_p2wpkh = Address::p2wpkh(&compressed, network);
            
            if addr_p2pkh.to_string() == target || addr_p2wpkh.to_string() == target {
                warn!("\n🎯 FOUND MATCH!");
                warn!("Passphrase: \"{}\"", passphrase);
                warn!("Private Key: {}", hex::encode(privkey));
                warn!("Address: {}", addr_p2pkh);
                return Ok(());
            }
        }
        
        checked += 1;
        if checked.is_multiple_of(100_000) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = checked as f64 / elapsed;
            info!("Checked {} passphrases | {:.0}/s", checked, speed);
        }
    }

    info!("Scan complete (checked {} passphrases). No match found.", checked);
    Ok(())
}

/// Derive private key from passphrase
fn derive_key(passphrase: &str, hash_type: HashType) -> [u8; 32] {
    match hash_type {
        HashType::Sha256 { iterations } => {
            let mut hash = Sha256::digest(passphrase.as_bytes());
            for _ in 1..iterations {
                hash = Sha256::digest(hash);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&hash);
            key
        }
        HashType::Sha3_256 => {
            use sha3::{Sha3_256, Digest as Sha3Digest};
            let hash = Sha3_256::digest(passphrase.as_bytes());
            let mut key = [0u8; 32];
            key.copy_from_slice(&hash);
            key
        }
    }
}

/// Generate common brainwallet passphrases
pub fn generate_common_passphrases() -> Vec<String> {
    let common = vec![
        "password", "123456", "bitcoin", "secret", "passphrase",
        "satoshi", "nakamoto", "blockchain", "wallet", "money",
        "test", "hello", "world", "abc123", "qwerty",
        "letmein", "admin", "login", "welcome", "master",
        "correct horse battery staple",  // Famous XKCD passphrase
    ];
    common.into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_password() {
        // SHA256("password") verified with: echo -n "password" | shasum -a 256
        let key = derive_key("password", HashType::Sha256 { iterations: 1 });
        let hex = hex::encode(&key);
        assert_eq!(hex, "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
    }

    #[test]
    fn test_sha256_two_iterations() {
        let key1 = derive_key("test", HashType::Sha256 { iterations: 1 });
        let key2 = derive_key("test", HashType::Sha256 { iterations: 2 });
        assert_ne!(key1, key2);
    }
}
