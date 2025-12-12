//! Brainwallet Scanner
//!
//! Covers Gap #8: SHA256(passphrase) → private key
//!
//! Brainwallets use a passphrase directly hashed to create a private key.
//! This scanner supports:
//! - Direct SHA256 (1 iteration)
//! - SHA256 with multiple iterations
//! - SHA3-256 variant
//!
//! Address types supported:
//! - P2PKH (uncompressed) - "1..." prefix - uses 65-byte uncompressed public key
//! - P2PKH (compressed) - "1..." prefix - uses 33-byte compressed public key
//! - P2SH-P2WPKH - "3..." prefix - SegWit-compatible (BIP49)
//! - P2WPKH - "bc1q..." prefix - Native SegWit (BIP84)
//!
//! Example brainwallet test vectors:
//! - Passphrase: "hashcat"
//! - Private key (SHA256): 127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
//! - Run tests to see computed addresses for this passphrase

use anyhow::Result;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{info, warn};

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

/// Hash160 helper function: RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_result = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_result);
    ripemd.finalize().into()
}

/// Generate P2PKH address from hash160 with version byte
fn p2pkh_from_hash160(hash160: &[u8; 20], version: u8) -> String {
    let mut addr_bytes = vec![version];
    addr_bytes.extend_from_slice(hash160);
    bs58::encode(&addr_bytes).with_check().into_string()
}

/// Run brainwallet scanner with a single passphrase
pub fn run_single(passphrase: &str, hash_type: HashType, target: Option<&str>) -> Result<()> {
    info!("Brainwallet Scanner");
    info!("Hash: {:?}", hash_type);
    info!("Passphrase: \"{}\"", passphrase);

    let privkey = derive_key(passphrase, hash_type);
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    if let Ok(secret) = SecretKey::from_slice(&privkey) {
        let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
        let compressed = CompressedPublicKey(pubkey_secp);

        // Get both compressed and uncompressed public keys
        let compressed_bytes = pubkey_secp.serialize();
        let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

        // P2PKH (uncompressed) - uses uncompressed public key
        let uncompressed_hash160 = hash160(&uncompressed_bytes);
        let addr_p2pkh_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);

        // P2PKH (compressed) - uses compressed public key
        let addr_p2pkh_compressed = Address::p2pkh(compressed, network);

        // P2SH-P2WPKH (BIP49) - "3" prefix
        let addr_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);

        // P2WPKH (BIP84) - "bc1q" prefix
        let addr_p2wpkh = Address::p2wpkh(&compressed, network);

        info!("Private Key: {}", hex::encode(privkey));
        info!("Compressed pubkey: {}", hex::encode(compressed_bytes));
        info!("Uncompressed pubkey: {}...", hex::encode(&uncompressed_bytes[..33]));
        info!("P2PKH (uncompressed): {}", addr_p2pkh_uncompressed);
        info!("P2PKH (compressed):   {}", addr_p2pkh_compressed);
        info!("P2SH-P2WPKH:          {}", addr_p2sh_p2wpkh);
        info!("P2WPKH:               {}", addr_p2wpkh);

        if let Some(t) = target {
            if addr_p2pkh_uncompressed == t
                || addr_p2pkh_compressed.to_string() == t
                || addr_p2sh_p2wpkh.to_string() == t
                || addr_p2wpkh.to_string() == t
            {
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
pub fn run_file(wordlist_path: &str, hash_type: HashType, target: &str) -> Result<()> {
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
            let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
            let compressed = CompressedPublicKey(pubkey_secp);

            // Get both compressed and uncompressed public keys
            let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

            // Generate all address types
            let uncompressed_hash160 = hash160(&uncompressed_bytes);
            let addr_p2pkh_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);
            let addr_p2pkh_compressed = Address::p2pkh(compressed, network);
            let addr_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);
            let addr_p2wpkh = Address::p2wpkh(&compressed, network);

            if addr_p2pkh_uncompressed == target
                || addr_p2pkh_compressed.to_string() == target
                || addr_p2sh_p2wpkh.to_string() == target
                || addr_p2wpkh.to_string() == target
            {
                warn!("\n🎯 FOUND MATCH!");
                warn!("Passphrase: \"{}\"", passphrase);
                warn!("Private Key: {}", hex::encode(privkey));
                warn!("P2PKH (uncompressed): {}", addr_p2pkh_uncompressed);
                warn!("P2PKH (compressed):   {}", addr_p2pkh_compressed);
                warn!("P2SH-P2WPKH:          {}", addr_p2sh_p2wpkh);
                warn!("P2WPKH:               {}", addr_p2wpkh);
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

    info!(
        "Scan complete (checked {} passphrases). No match found.",
        checked
    );
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
            use sha3::{Digest as Sha3Digest, Sha3_256};
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
        "password",
        "123456",
        "bitcoin",
        "secret",
        "passphrase",
        "satoshi",
        "nakamoto",
        "blockchain",
        "wallet",
        "money",
        "test",
        "hello",
        "world",
        "abc123",
        "qwerty",
        "letmein",
        "admin",
        "login",
        "welcome",
        "master",
        "correct horse battery staple", // Famous XKCD passphrase
    ];
    common.into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::PublicKey;

    #[test]
    fn test_sha256_password() {
        // SHA256("password") verified with: echo -n "password" | shasum -a 256
        let key = derive_key("password", HashType::Sha256 { iterations: 1 });
        let hex = hex::encode(key);
        assert_eq!(
            hex,
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn test_sha256_two_iterations() {
        let key1 = derive_key("test", HashType::Sha256 { iterations: 1 });
        let key2 = derive_key("test", HashType::Sha256 { iterations: 2 });
        assert_ne!(key1, key2);
    }

    /// Test "hashcat" passphrase produces all address types correctly
    /// SHA256("hashcat") = 127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
    #[test]
    fn test_hashcat_passphrase_all_address_types() {
        let passphrase = "hashcat";
        let privkey = derive_key(passphrase, HashType::Sha256 { iterations: 1 });

        // Verify private key matches SHA256("hashcat")
        assert_eq!(
            hex::encode(privkey),
            "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
        );

        let secp = Secp256k1::new();
        let network = Network::Bitcoin;
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
        let compressed = CompressedPublicKey(pubkey_secp);

        // Get public keys
        let compressed_bytes = pubkey_secp.serialize();
        let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

        // Print all values for cross-project verification
        println!("=== Brainwallet Test Vector: 'hashcat' ===");
        println!("Private key: {}", hex::encode(privkey));
        println!("Compressed pubkey: {}", hex::encode(compressed_bytes));

        // P2PKH (uncompressed) - uses 65-byte uncompressed public key
        let uncompressed_hash160 = hash160(&uncompressed_bytes);
        let addr_p2pkh_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);
        println!("P2PKH (uncompressed): {}", addr_p2pkh_uncompressed);
        assert!(addr_p2pkh_uncompressed.starts_with('1'), "P2PKH uncompressed should start with '1'");

        // P2PKH (compressed) - uses 33-byte compressed public key
        let addr_p2pkh_compressed = Address::p2pkh(compressed, network);
        println!("P2PKH (compressed):   {}", addr_p2pkh_compressed);
        assert!(addr_p2pkh_compressed.to_string().starts_with('1'), "P2PKH compressed should start with '1'");

        // P2WPKH (BIP84) - "bc1q" prefix
        let addr_p2wpkh = Address::p2wpkh(&compressed, network);
        println!("P2WPKH:               {}", addr_p2wpkh);
        assert!(addr_p2wpkh.to_string().starts_with("bc1q"), "P2WPKH should start with 'bc1q'");

        // P2SH-P2WPKH (BIP49) - "3" prefix
        let addr_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);
        println!("P2SH-P2WPKH:          {}", addr_p2sh_p2wpkh);
        assert!(addr_p2sh_p2wpkh.to_string().starts_with('3'), "P2SH-P2WPKH should start with '3'");

        // Verify uncompressed and compressed P2PKH are different
        assert_ne!(
            addr_p2pkh_uncompressed,
            addr_p2pkh_compressed.to_string(),
            "Uncompressed and compressed P2PKH should produce different addresses"
        );
    }

    /// Test additional known brainwallet passphrases
    #[test]
    fn test_common_brainwallet_passphrases() {
        let test_cases = vec![
            ("password", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"),
            ("satoshi nakamoto", "aa2d3c4a4ae6559e9f13f093cc6e32459c5249da723de810651b4b54373385e2"),
            ("correct horse battery staple", "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"),
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ];

        for (passphrase, expected_privkey) in test_cases {
            let privkey = derive_key(passphrase, HashType::Sha256 { iterations: 1 });
            assert_eq!(
                hex::encode(privkey),
                expected_privkey,
                "Private key mismatch for passphrase: '{}'",
                passphrase
            );
        }
    }
}
