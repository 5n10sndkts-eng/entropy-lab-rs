use anyhow::{Result, Context};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
use bitcoin::{Transaction, Address};
use std::collections::HashMap;
use std::io::Write;
use bitcoin::hashes::Hash;


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
            for (input_idx, input) in tx.input.iter().enumerate() {
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
                                        
                                        // TODO: Implement private key recovery from duplicate R values
                                        // This requires:
                                        // 1. Extract both signatures (r, s1) and (r, s2)
                                        // 2. Extract message hashes m1 and m2
                                        // 3. Calculate k = (m1 - m2) / (s1 - s2) mod n
                                        // 4. Calculate private key = (s1 * k - m1) / r mod n
                                        
                                        // Write to file
                                        std::fs::write(
                                            "android_securerandom_hits.txt",
                                            format!("Duplicate R value found!\nR: {}\nTx1: {}\nTx2: {}\nBlock: {}\n\n",
                                                hex::encode(&r_value), entry[0].0, txid, block_height)
                                        )?;
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
        println!("\nNote: Private key recovery not yet implemented.");
        println!("To recover private keys, you need to:");
        println!("1. Extract both signatures and message hashes");
        println!("2. Calculate k = (m1 - m2) / (s1 - s2) mod n");
        println!("3. Calculate private key = (s1 * k - m1) / r mod n");
    }

    Ok(())
}
